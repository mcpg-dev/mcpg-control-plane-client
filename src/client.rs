//! `AgentClient` — thin wrapper around the tonic-generated
//! `AgentControlClient` + transparent JWT injection.

use std::sync::Arc;
use std::time::Duration;

use mcpg_control_plane_core::proto::agent_control_client::AgentControlClient;
use mcpg_control_plane_core::proto::{
    HeartbeatRequest, HeartbeatResponse, RegisterRequest, RegisterResponse,
};
use tokio::sync::RwLock;
use tonic::Status;
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

/// Optional mTLS material the agent presents on every call once it
/// has been issued by the CP at Register time.
#[derive(Clone, Debug, Default)]
pub struct ClientTlsMaterial {
    pub ca_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    /// Hostname to use for SNI / cert verification; defaults to
    /// the host part of the endpoint URL.
    pub server_name: Option<String>,
}

#[derive(Clone)]
pub struct AgentClient {
    endpoint: String,
    /// Lazy-built channel; kept warm via gRPC keepalive.
    channel: Arc<RwLock<Option<Channel>>>,
    /// Current instance JWT used in `mcpg-instance-token`
    /// metadata. Replaced after rotation.
    jwt: Arc<RwLock<Option<String>>>,
    /// Optional mTLS material applied on connect when the
    /// endpoint scheme is `https`. Populated by `set_tls`.
    tls: Arc<RwLock<Option<ClientTlsMaterial>>>,
}

impl AgentClient {
    pub fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            channel: Arc::new(RwLock::new(None)),
            jwt: Arc::new(RwLock::new(None)),
            tls: Arc::new(RwLock::new(None)),
        }
    }

    /// Configure mTLS material. Takes effect on the next reconnect
    /// (call `reset()` if you need to apply it immediately).
    pub async fn set_tls(&self, material: Option<ClientTlsMaterial>) {
        *self.tls.write().await = material;
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Replace the active instance JWT (e.g. after a credential
    /// rotation).
    pub async fn set_jwt(&self, token: String) {
        *self.jwt.write().await = Some(token);
    }

    /// Lazy-connect; reused thereafter.
    pub async fn connect(&self) -> anyhow::Result<()> {
        let mut g = self.channel.write().await;
        if g.is_some() {
            return Ok(());
        }
        let mut endpoint = Endpoint::from_shared(self.endpoint.clone())?
            .timeout(Duration::from_secs(10))
            .keep_alive_while_idle(true)
            .keep_alive_timeout(Duration::from_secs(20))
            .http2_keep_alive_interval(Duration::from_secs(20));

        // If we have mTLS material configured AND the endpoint is
        // https, install a `ClientTlsConfig` that pins the CP CA
        // and presents the client cert.
        let tls = self.tls.read().await.clone();
        if self.endpoint.starts_with("https://") {
            let tls_cfg = if let Some(m) = tls.as_ref() {
                let mut c = ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(m.ca_pem.as_bytes()));
                if !m.client_cert_pem.is_empty() && !m.client_key_pem.is_empty() {
                    c = c.identity(Identity::from_pem(
                        m.client_cert_pem.as_bytes(),
                        m.client_key_pem.as_bytes(),
                    ));
                }
                if let Some(name) = m.server_name.as_deref() {
                    c = c.domain_name(name);
                }
                c
            } else {
                ClientTlsConfig::new()
            };
            endpoint = endpoint.tls_config(tls_cfg)?;
        }
        *g = Some(endpoint.connect().await?);
        Ok(())
    }

    /// Force a reconnect (e.g. after a stream-level error).
    pub async fn reset(&self) {
        let mut g = self.channel.write().await;
        *g = None;
    }

    /// Public RPC — Register doesn't require auth metadata.
    pub async fn register(&self, req: RegisterRequest) -> anyhow::Result<RegisterResponse> {
        self.connect().await?;
        let ch = self.channel.read().await.clone().expect("connected");
        let mut client = AgentControlClient::new(ch);
        let resp = client.register(req).await?;
        Ok(resp.into_inner())
    }

    /// Authenticated RPC — Heartbeat needs the instance JWT.
    /// Returns the full `HeartbeatResponse` so callers can read
    /// `quota_status` and `expected_config_hash` alongside `ok`.
    pub async fn heartbeat(&self, req: HeartbeatRequest) -> anyhow::Result<HeartbeatResponse> {
        let mut client = self.authed_client().await?;
        let resp = client.heartbeat(req).await?;
        Ok(resp.into_inner())
    }

    /// Build an authenticated client wrapping the channel with a
    /// JWT-injecting interceptor. Returned client cheap-clones
    /// the underlying channel.
    pub async fn authed_client(
        &self,
    ) -> anyhow::Result<AgentControlClient<InterceptedService<Channel, JwtInterceptor>>> {
        self.connect().await?;
        let ch = self.channel.read().await.clone().expect("connected");
        let jwt = self
            .jwt
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no instance JWT cached; call register() first"))?;

        Ok(AgentControlClient::with_interceptor(
            ch,
            JwtInterceptor { jwt },
        ))
    }
}

#[derive(Clone)]
pub struct JwtInterceptor {
    jwt: String,
}

impl tonic::service::Interceptor for JwtInterceptor {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
        let val = MetadataValue::try_from(self.jwt.as_str())
            .map_err(|_| Status::internal("invalid jwt encoding"))?;
        req.metadata_mut().insert("mcpg-instance-token", val);
        Ok(req)
    }
}
