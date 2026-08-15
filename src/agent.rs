//! `AgentRunner` — full gateway-side lifecycle: register, open
//! Channel, heartbeat, apply ConfigUpdate, reconnect with
//! backoff.
//!
//! Used by:
//! - The MCPG plugin host (when this crate is loaded as a plugin
//!   into a running gateway).
//! - `mcpg --enroll <URL>` (CP-attached gateway for the Tier 0
//!   wedge UX + integration tests).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use futures::StreamExt;
use mcpg_control_plane_core::proto::agent_message::Kind as AgentKind;
use mcpg_control_plane_core::proto::server_message::Kind as ServerKind;
use mcpg_control_plane_core::proto::{
    AgentMessage, ConfigAck, ConfigBundle, Heartbeat, HostInfo, QuotaStatus, RegisterRequest,
    ServerMessage,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

use crate::backoff::Backoff;
use crate::client::{AgentClient, ClientTlsMaterial};
use crate::lkg::LkgCache;
use crate::logs::{DEFAULT_LOG_FLUSH_INTERVAL, LogBuffer, flush_loop as logs_flush_loop};
use crate::metrics::{DEFAULT_FLUSH_INTERVAL, MetricsBuffer, flush_loop as metrics_flush_loop};
use crate::payload_dek::DekHandle;

#[derive(Clone, Debug)]
pub struct AgentRunnerConfig {
    pub cp_endpoint: String,
    pub enrollment_url: String,
    pub instance_uid: String,
    pub version: String,
    /// Where to persist creds (`<dir>/agent-creds.json`).
    pub state_dir: PathBuf,
    pub heartbeat_interval: Duration,
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
    /// PEM-encoded CA bundle to trust on the very first connect
    /// (Register), before the agent has its own creds. Once
    /// Register completes, the CP-issued cert/key/ca_chain trio
    /// supplants this. Optional; only required when the CP gRPC
    /// listener is TLS and the caller hasn't pre-populated a
    /// previous run's `agent-creds.json`.
    pub bootstrap_ca_pem: Option<String>,
}

impl Default for AgentRunnerConfig {
    fn default() -> Self {
        Self {
            cp_endpoint: "http://127.0.0.1:7844".into(),
            enrollment_url: String::new(),
            instance_uid: format!("mcpg-{}", uuid::Uuid::now_v7()),
            version: env!("CARGO_PKG_VERSION").into(),
            state_dir: PathBuf::from("./agent-state"),
            heartbeat_interval: Duration::from_secs(30),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            bootstrap_ca_pem: None,
        }
    }
}

/// External-facing event stream so callers (CLI, tests, plugin
/// host) can react to lifecycle changes.
#[derive(Clone, Debug)]
pub enum AgentEvent {
    Registered { instance_id: String },
    ChannelConnected,
    ChannelDisconnected { reason: String },
    HeartbeatSent { seq: u64 },
    ConfigReceived { hash: String },
    Error(String),
}

/// Host hook to APPLY a pushed config bundle to the running process — e.g. the
/// gateway hot-reloads it without a restart. Wired via
/// [`AgentRunner::with_config_applier`]. When absent, the agent caches the
/// bundle (LKG) and acks without applying — the legacy behaviour for
/// non-gateway agents. The returned `Result` drives the `ConfigAck` the CP
/// sees: `Ok` → applied; `Err(reason)` → the host kept its prior config and the
/// CP is told why (truthful ack).
#[async_trait::async_trait]
pub trait ConfigApplier: Send + Sync {
    async fn apply(&self, bundle: &ConfigBundle) -> Result<(), String>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredCreds {
    instance_id: String,
    instance_jwt: String,
    cp_endpoint: String,
    /// When the JWT was issued (for half-life rotation logic).
    issued_at: chrono::DateTime<chrono::Utc>,
    /// PEM-encoded mTLS client cert + key issued by the CP CA at
    /// Register time and rotated alongside the JWT. May be empty
    /// for creds files written before mTLS support existed.
    #[serde(default)]
    client_cert_pem: String,
    #[serde(default)]
    client_key_pem: String,
    /// PEM-encoded CA chain so the agent can verify the CP's
    /// server cert on reconnect. Empty when TLS is disabled.
    #[serde(default)]
    ca_chain_pem: String,
    /// Per-tenant DEK for source-side payload encryption.
    /// Base64-encoded so the on-disk creds file remains JSON.
    /// Empty for legacy creds files / a CP that doesn't mint DEKs.
    #[serde(default)]
    payload_dek_b64: String,
    /// Version stamped on every encrypted payload blob shipped to
    /// the CP. Zero when no DEK was issued. (Operator-triggered
    /// rotation increments this; deferred to a follow-up.)
    #[serde(default)]
    payload_dek_version: u32,
}

/// How many batches a shutdown flush will ship before giving up. The buffers
/// are capped, so this covers a full one; the bound exists so shutdown cannot
/// be held open by a producer that keeps writing.
const MAX_SHUTDOWN_FLUSH_BATCHES: usize = 16;

/// Asks a running [`AgentRunner`] to stop gracefully.
#[derive(Clone)]
pub struct AgentShutdown {
    notify: Arc<tokio::sync::Notify>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
    done: Arc<tokio::sync::Notify>,
    finished: Arc<std::sync::atomic::AtomicBool>,
}

impl AgentShutdown {
    /// Signal the agent to finish its current session and stop. Idempotent.
    pub fn trigger(&self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    /// Resolves once the agent has shipped what it had buffered and stopped.
    /// Returns immediately if that already happened.
    pub async fn finished(&self) {
        if self.finished.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        // Register before re-checking: the agent may finish between the load
        // above and the await, and `notified()` only sees later notifications.
        let waiter = self.done.notified();
        if self.finished.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        waiter.await;
    }
}

pub struct AgentRunner {
    cfg: AgentRunnerConfig,
    client: AgentClient,
    events: broadcast::Sender<AgentEvent>,
    /// Per-call tool metrics buffer. Cheap to clone (internal Arc).
    /// Plugin hosts call `runner.metrics().record(sample)` from
    /// every tool dispatch; the agent's flush task drains every
    /// `metrics_flush_interval` and ships the batch over the open
    /// Channel as a `MetricsReport`.
    metrics: MetricsBuffer,
    /// Set once to ask the run loop to stop after a final flush.
    shutdown: Arc<tokio::sync::Notify>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
    /// Raised once that flush has happened and the loop has stopped.
    shutdown_done: Arc<tokio::sync::Notify>,
    shutdown_finished: Arc<std::sync::atomic::AtomicBool>,
    /// Recent gateway log lines. The cp-attach log sink calls
    /// `runner.logs().record(line)`; the agent's log-flush task drains every
    /// `DEFAULT_LOG_FLUSH_INTERVAL` and ships a `LogBatch`. Mirrors `metrics`.
    logs: LogBuffer,
    /// Lock-free hot-path handle to the latest quota state pushed
    /// by the CP. Updated from `ServerMessage::QuotaStatus` (sent
    /// after every streaming heartbeat ingest) and consulted by
    /// the gateway dispatch path before invoking a tool. `None`
    /// means "unmetered tier or not yet known" — fall through.
    quota_status: Arc<ArcSwap<Option<QuotaStatus>>>,
    /// Lock-free hot-path handle to the per-tenant payload DEK
    /// issued by the CP at Register and refreshed on every
    /// `CredentialRotation`. `None` means "no source-side
    /// encryption" — the gateway falls through to plaintext
    /// capture and the CP wraps at ingest.
    payload_dek: Arc<ArcSwap<Option<DekHandle>>>,
    /// Host hook to apply a pushed config bundle (gateway hot-reload). `None`
    /// → cache-only (legacy). See [`ConfigApplier`].
    config_applier: Option<Arc<dyn ConfigApplier>>,
}

impl AgentRunner {
    pub fn new(cfg: AgentRunnerConfig) -> Self {
        let client = AgentClient::new(cfg.cp_endpoint.clone());
        let (events, _) = broadcast::channel(64);
        Self {
            cfg,
            client,
            events,
            metrics: MetricsBuffer::new(),
            shutdown: Arc::new(tokio::sync::Notify::new()),
            stopping: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            shutdown_done: Arc::new(tokio::sync::Notify::new()),
            shutdown_finished: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            logs: LogBuffer::new(),
            quota_status: Arc::new(ArcSwap::from_pointee(None)),
            payload_dek: Arc::new(ArcSwap::from_pointee(None)),
            config_applier: None,
        }
    }

    /// Wire a host hook that applies pushed config bundles (e.g. the gateway's
    /// in-process hot-reload). Without it, pushed bundles are cached but not
    /// applied (legacy behaviour).
    pub fn with_config_applier(mut self, applier: Arc<dyn ConfigApplier>) -> Self {
        self.config_applier = Some(applier);
        self
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AgentEvent> {
        self.events.subscribe()
    }

    /// Cheap-to-clone handle to the latest quota status the CP has
    /// pushed to this agent. Read by the gateway's dispatch
    /// hot-path; `None` means unmetered or not-yet-known.
    pub fn quota_status_handle(&self) -> Arc<ArcSwap<Option<QuotaStatus>>> {
        self.quota_status.clone()
    }

    /// Cheap-to-clone handle to the per-tenant payload DEK. Read
    /// by the gateway's dispatch hot-path before pushing a sample
    /// into the metrics buffer; `None` means the gateway should
    /// fall through to plaintext capture (legacy CP-encrypts-at-
    /// ingest path).
    pub fn payload_dek_handle(&self) -> Arc<ArcSwap<Option<DekHandle>>> {
        self.payload_dek.clone()
    }

    /// Cheap-to-clone handle to the metrics buffer. Plugin hosts
    /// call `record(sample)` from each tool dispatch site;
    /// samples are batched and shipped to the CP every
    /// `metrics_flush_interval` (default 30s) over the open
    /// Channel.
    ///
    /// ```ignore
    /// // At dispatch time:
    /// runner.metrics().record(ToolCallSample {
    ///     plugin_id: "github".into(),
    ///     tool_name: "list_repos".into(),
    ///     binding_id: None,
    ///     started_at: chrono::Utc::now(),
    ///     duration: elapsed,
    ///     outcome: SampleOutcome::Ok,
    ///     error_code: None,
    ///     error_hash: None,
    ///     request_id: Some(req_id),
    ///     caller_subject: Some(caller),
    /// });
    /// ```
    /// A handle that asks the agent to stop after shipping whatever metrics
    /// and logs are still buffered. Aborting the task instead discards them,
    /// and buffered tool calls are billable — a deploy would silently cost a
    /// flush interval of revenue.
    pub fn shutdown_handle(&self) -> AgentShutdown {
        AgentShutdown {
            notify: self.shutdown.clone(),
            stopping: self.stopping.clone(),
            done: self.shutdown_done.clone(),
            finished: self.shutdown_finished.clone(),
        }
    }

    pub fn metrics(&self) -> MetricsBuffer {
        self.metrics.clone()
    }

    /// Cheap-to-clone handle to the recent-log ring. The cp-attach log sink
    /// records captured gateway lines here; the agent's log-flush task ships
    /// them as `LogBatch` (powers `mcpg cloud logs`).
    pub fn logs(&self) -> LogBuffer {
        self.logs.clone()
    }

    /// One-shot: register if needed, then run the heartbeat +
    /// channel loop until cancelled or a fatal error occurs.
    pub async fn run(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.cfg.state_dir)?;
        // For an initial Register over TLS we need *some* CA to
        // verify the CP server cert; the bootstrap_ca_pem field
        // covers that. Once Register completes, the CP-returned
        // ca_chain_pem replaces this.
        if let Some(ca) = self.cfg.bootstrap_ca_pem.as_ref() {
            self.client
                .set_tls(Some(ClientTlsMaterial {
                    ca_pem: ca.clone(),
                    client_cert_pem: String::new(),
                    client_key_pem: String::new(),
                    server_name: None,
                }))
                .await;
        }
        let creds = self.ensure_registered().await?;
        self.client.set_jwt(creds.instance_jwt.clone()).await;
        // Hydrate the payload DEK handle from creds — either
        // freshly issued at Register or restored from disk on
        // restart. Empty fields → `None`, gateway falls through
        // to plaintext capture (legacy CP-side encrypt at ingest).
        self.install_payload_dek_from_creds(&creds);
        // Apply any stored mTLS material so the next connect uses
        // it. No-op when the endpoint scheme is plain http. We
        // also reset the cached channel so subsequent calls
        // negotiate a fresh TLS handshake with the new client
        // cert (Register may have run TLS-only or plaintext).
        if !creds.client_cert_pem.is_empty() && !creds.ca_chain_pem.is_empty() {
            self.client
                .set_tls(Some(ClientTlsMaterial {
                    ca_pem: creds.ca_chain_pem.clone(),
                    client_cert_pem: creds.client_cert_pem.clone(),
                    client_key_pem: creds.client_key_pem.clone(),
                    server_name: None,
                }))
                .await;
            self.client.reset().await;
        }

        // Best-effort: preload the last-known-good config so the
        // gateway can serve traffic immediately on restart.
        let lkg = LkgCache::in_state_dir(&self.cfg.state_dir);
        if let Ok(Some((hash, _))) = lkg.load_bundle() {
            info!(%hash, "agent: preloaded LKG config");
            let _ = self.events.send(AgentEvent::ConfigReceived { hash });
        }

        self.run_loop(Arc::new(creds)).await
    }

    /// Run the heartbeat + channel loop. Reconnects with backoff
    /// on failure. Returns only when the underlying error is
    /// non-recoverable.
    async fn run_loop(&self, creds: Arc<StoredCreds>) -> anyhow::Result<()> {
        let mut backoff = Backoff::new(self.cfg.backoff_initial, self.cfg.backoff_max, true);

        loop {
            if self.stopping.load(std::sync::atomic::Ordering::SeqCst) {
                info!("agent: shutdown requested; run loop stopping");
                self.shutdown_finished
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                self.shutdown_done.notify_waiters();
                return Ok(());
            }
            match self.run_session(creds.clone()).await {
                Ok(()) => {
                    backoff.reset();
                    info!("agent: session ended cleanly");
                }
                Err(e) => {
                    let delay = backoff.next_delay();
                    warn!(error = ?e, ?delay, "agent: session error, reconnecting");
                    let _ = self.events.send(AgentEvent::ChannelDisconnected {
                        reason: e.to_string(),
                    });
                    self.client.reset().await;
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// One Channel session: connect → spawn heartbeat ticker →
    /// receive ServerMessages → exit on stream error.
    async fn run_session(&self, _creds: Arc<StoredCreds>) -> anyhow::Result<()> {
        // Open the bidirectional Channel.
        let (out_tx, out_rx) = mpsc::channel::<AgentMessage>(64);
        let outbound = tokio_stream::wrappers::ReceiverStream::new(out_rx);

        let mut client = self.client.authed_client().await?;
        let resp = client.channel(outbound).await?;
        let mut server_stream = resp.into_inner();

        info!("agent: Channel established");
        let _ = self.events.send(AgentEvent::ChannelConnected);

        // Heartbeat ticker.
        let heartbeat_tx = out_tx.clone();
        let interval = self.cfg.heartbeat_interval;
        let events_for_hb = self.events.clone();
        let hb_handle = tokio::spawn(async move {
            let mut seq: u64 = 0;
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // immediate
            loop {
                seq = seq.saturating_add(1);
                let msg = AgentMessage {
                    kind: Some(AgentKind::Heartbeat(Heartbeat {
                        at: Some(prost_types::Timestamp {
                            seconds: chrono::Utc::now().timestamp(),
                            nanos: 0,
                        }),
                        seq,
                        health: "ok".into(),
                        active_connections: 0,
                        cpu_load_avg: 0.0,
                        memory_rss_bytes: 0,
                    })),
                };
                if heartbeat_tx.send(msg).await.is_err() {
                    debug!("heartbeat: outbound channel closed; stopping ticker");
                    break;
                }
                let _ = events_for_hb.send(AgentEvent::HeartbeatSent { seq });
                ticker.tick().await;
            }
        });

        // Tool-metrics flush ticker. Runs alongside the heartbeat
        // ticker; each tick drains up to `DEFAULT_BATCH_CAP`
        // samples + the dropped-overflow counter and ships them
        // as a `MetricsReport`. Stops when the outbound channel
        // closes (Channel reconnect / shutdown).
        let metrics_buf = self.metrics.clone();
        let metrics_tx = out_tx.clone();
        let metrics_handle = tokio::spawn(async move {
            metrics_flush_loop(metrics_buf, metrics_tx, DEFAULT_FLUSH_INTERVAL).await;
        });

        // Log-batch flush ticker — same shape as metrics, on a staggered
        // interval so the three timers don't all wake on the same tick.
        let logs_buf = self.logs.clone();
        let logs_tx = out_tx.clone();
        let logs_handle = tokio::spawn(async move {
            logs_flush_loop(logs_buf, logs_tx, DEFAULT_LOG_FLUSH_INTERVAL).await;
        });

        // Read inbound ServerMessages until the stream ends or shutdown is
        // asked for.
        let inbound_result = tokio::select! {
            r = self.read_inbound(&mut server_stream, out_tx.clone()) => r,
            _ = self.shutdown.notified() => Ok(()),
        };

        hb_handle.abort();
        metrics_handle.abort();
        logs_handle.abort();
        // The abort above returns any in-flight batch to its buffer, so this
        // ships everything still owed — including whatever accumulated since
        // the last tick. Only on a requested shutdown: a session that died is
        // about to be retried, and its buffers carry over to the next one.
        if self.stopping.load(std::sync::atomic::Ordering::SeqCst) {
            self.flush_remaining(&out_tx).await;
        }
        inbound_result
    }

    /// Drain the metrics and log buffers into the outbound channel before the
    /// session closes. Buffered tool calls are billable, so dropping them at
    /// shutdown is lost revenue on every deploy.
    async fn flush_remaining(&self, out_tx: &mpsc::Sender<AgentMessage>) {
        // Each drain is capped at one batch, so loop — bounded, because a
        // shutdown must not block on a buffer something else is still filling.
        for _ in 0..MAX_SHUTDOWN_FLUSH_BATCHES {
            let (samples, dropped, seq) = self.metrics.drain();
            let empty = samples.is_empty() && dropped == 0;
            if let Some(msg) = crate::metrics::batch_to_message(&samples, dropped, seq)
                && out_tx.send(msg).await.is_err()
            {
                warn!(
                    samples = samples.len(),
                    "agent: outbound closed during shutdown flush; metrics not shipped"
                );
                return;
            }
            if empty {
                break;
            }
        }
        for _ in 0..MAX_SHUTDOWN_FLUSH_BATCHES {
            let (entries, dropped, seq) = self.logs.drain();
            let empty = entries.is_empty() && dropped == 0;
            if let Some(msg) = crate::logs::batch_to_message(entries, dropped, seq)
                && out_tx.send(msg).await.is_err()
            {
                return;
            }
            if empty {
                break;
            }
        }
        info!("agent: shutdown flush complete");
    }

    async fn read_inbound(
        &self,
        stream: &mut tonic::Streaming<ServerMessage>,
        out_tx: mpsc::Sender<AgentMessage>,
    ) -> anyhow::Result<()> {
        while let Some(msg) = stream.next().await {
            let msg = msg?;
            match msg.kind {
                Some(ServerKind::ConfigUpdate(update)) => {
                    let hash = update.config_hash.clone();
                    info!(%hash, "agent: ConfigUpdate received");

                    // Persist LKG before applying so a crash mid-cycle still has
                    // the new config on disk.
                    if let Some(bundle) = update.bundle.as_ref() {
                        let lkg = LkgCache::in_state_dir(&self.cfg.state_dir);
                        match lkg.save(&hash, bundle) {
                            Ok(()) => debug!(%hash, "agent: LKG saved"),
                            Err(e) => warn!(error = ?e, "agent: LKG save failed"),
                        }
                    }

                    // Apply via the host hook if one is wired; the ack reflects
                    // the real outcome. No applier (non-gateway agents) →
                    // cache-only, ack active (legacy behaviour).
                    let (applied_state, error) = match (
                        update.bundle.as_ref(),
                        self.config_applier.as_ref(),
                    ) {
                        (Some(bundle), Some(applier)) => match applier.apply(bundle).await {
                            Ok(()) => ("active".to_string(), String::new()),
                            Err(e) => {
                                warn!(%hash, error = %e, "agent: config apply failed; keeping prior config");
                                ("error".to_string(), e)
                            }
                        },
                        _ => ("active".to_string(), String::new()),
                    };

                    let _ = self
                        .events
                        .send(AgentEvent::ConfigReceived { hash: hash.clone() });
                    let ack = AgentMessage {
                        kind: Some(AgentKind::ConfigAck(ConfigAck {
                            config_hash: hash,
                            applied_at: Some(prost_types::Timestamp {
                                seconds: chrono::Utc::now().timestamp(),
                                nanos: 0,
                            }),
                            applied_state,
                            error,
                        })),
                    };
                    let _ = out_tx.send(ack).await;
                }
                Some(ServerKind::Command(c)) => {
                    debug!(command_id = %c.command_id, "agent: Command received (stub)");
                }
                Some(ServerKind::CredentialRotation(cr)) => {
                    info!("agent: CredentialRotation received");
                    if !cr.instance_jwt.is_empty() {
                        self.client.set_jwt(cr.instance_jwt.clone()).await;
                        // Persist the rotated JWT (and cert if any)
                        // so a restart before the next rotation
                        // still authenticates without re-running
                        // Register.
                        if let Err(e) = persist_rotated_creds(
                            &self.cfg.state_dir,
                            &cr.instance_jwt,
                            &cr.client_cert_pem,
                            &cr.client_key_pem,
                            &cr.payload_dek,
                            cr.payload_dek_version,
                        ) {
                            warn!(error = ?e, "agent: persist rotated creds failed");
                        }
                        // Refresh in-memory TLS material so the
                        // next reconnect picks up the new cert.
                        // The CA didn't change, so we re-read from
                        // disk to keep the ca_pem field consistent.
                        if !cr.client_cert_pem.is_empty()
                            && let Ok(stored) = read_stored_creds(&self.cfg.state_dir)
                        {
                            self.client
                                .set_tls(Some(ClientTlsMaterial {
                                    ca_pem: stored.ca_chain_pem,
                                    client_cert_pem: cr.client_cert_pem.clone(),
                                    client_key_pem: cr.client_key_pem.clone(),
                                    server_name: None,
                                }))
                                .await;
                        }
                        // Refresh the lock-free payload DEK handle
                        // so the next captured sample uses the new
                        // key. Empty bytes → leave the existing
                        // handle in place (best-effort fallback;
                        // CP-side mint failure shouldn't drop the
                        // gateway's existing capability).
                        if !cr.payload_dek.is_empty() {
                            match DekHandle::from_proto(&cr.payload_dek, cr.payload_dek_version) {
                                Ok(Some(h)) => {
                                    self.payload_dek.store(Arc::new(Some(h)));
                                    debug!(
                                        version = cr.payload_dek_version,
                                        "agent: payload DEK rotated"
                                    );
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    warn!(
                                        error = ?e,
                                        "agent: rotated payload DEK rejected; keeping previous"
                                    );
                                }
                            }
                        }
                    }
                }
                Some(ServerKind::Quarantine(q)) => {
                    warn!(reason = %q.reason, "agent: Quarantine notice");
                    return Err(anyhow::anyhow!("quarantined: {}", q.reason));
                }
                Some(ServerKind::DiagnosticRequest(_)) => {
                    debug!("agent: DiagnosticRequest (stub)");
                }
                Some(ServerKind::LogRequest(_)) => {
                    debug!("agent: LogRequest (stub)");
                }
                Some(ServerKind::QuotaStatus(qs)) => {
                    debug!(
                        exhausted = qs.exhausted,
                        remaining = ?qs.remaining,
                        limit = ?qs.limit,
                        "agent: QuotaStatus push received"
                    );
                    self.quota_status.store(Arc::new(Some(qs)));
                }
                None => {}
            }
        }
        Ok(())
    }

    /// Read cached creds if present; else perform a fresh
    /// Register exchange.
    async fn ensure_registered(&self) -> anyhow::Result<StoredCreds> {
        let creds_path = self.cfg.state_dir.join("agent-creds.json");
        if let Ok(bytes) = std::fs::read(&creds_path)
            && let Ok(creds) = serde_json::from_slice::<StoredCreds>(&bytes)
        {
            // exp is not validated here; the server rejects an expired JWT.
            info!(instance_id = %creds.instance_id, "agent: using cached creds");
            return Ok(creds);
        }

        let token = extract_token(&self.cfg.enrollment_url)?;
        let req = RegisterRequest {
            bootstrap_token: token,
            instance_uid: self.cfg.instance_uid.clone(),
            version: self.cfg.version.clone(),
            labels: Default::default(),
            capabilities: vec!["control_plane_client".into()],
            addressable_endpoints: vec![],
            host: Some(HostInfo {
                os: std::env::consts::OS.into(),
                arch: std::env::consts::ARCH.into(),
                hostname: hostname().unwrap_or_default(),
                kernel_version: String::new(),
            }),
        };

        // Retry the INITIAL Register with backoff. A transient CP outage at pod
        // boot (the CP rolling, a network blip, the gRPC advertise endpoint not
        // yet routable) must not permanently wedge enrollment — the old one-shot
        // `?` returned the first error and the agent task exited, so the gateway
        // served its file config forever but never received CP config / quota /
        // credential rotation. Runs in the agent's own task, so the gateway's
        // HTTP server keeps serving while this retries in the background.
        let client = self.client.clone();
        let resp = retry_with_backoff(self.cfg.backoff_initial, self.cfg.backoff_max, move || {
            let client = client.clone();
            let req = req.clone();
            async move { client.register(req).await }
        })
        .await;
        info!(instance_id = %resp.instance_id, "agent: registered");
        let _ = self.events.send(AgentEvent::Registered {
            instance_id: resp.instance_id.clone(),
        });

        let payload_dek_b64 = if resp.payload_dek.is_empty() {
            String::new()
        } else {
            B64.encode(&resp.payload_dek)
        };
        let creds = StoredCreds {
            instance_id: resp.instance_id,
            instance_jwt: resp.instance_jwt,
            cp_endpoint: resp.cp_endpoint,
            issued_at: chrono::Utc::now(),
            client_cert_pem: resp.client_cert_pem,
            client_key_pem: resp.client_key_pem,
            ca_chain_pem: resp.ca_chain_pem,
            payload_dek_b64,
            payload_dek_version: resp.payload_dek_version,
        };
        let _ = std::fs::write(&creds_path, serde_json::to_vec_pretty(&creds)?);
        // chmod 600 best-effort on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&creds_path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(creds)
    }
}

impl AgentRunner {
    /// Decode the persisted DEK + version into a `DekHandle` and
    /// publish it to the lock-free `payload_dek` slot. Empty/
    /// malformed inputs leave the slot at `None` so the gateway
    /// falls through to plaintext capture instead of erroring.
    fn install_payload_dek_from_creds(&self, creds: &StoredCreds) {
        if creds.payload_dek_b64.is_empty() {
            return;
        }
        let raw = match B64.decode(creds.payload_dek_b64.as_bytes()) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = ?e, "agent: stored payload_dek_b64 decode failed");
                return;
            }
        };
        match DekHandle::from_proto(&raw, creds.payload_dek_version) {
            Ok(Some(h)) => {
                self.payload_dek.store(Arc::new(Some(h)));
                debug!(
                    version = creds.payload_dek_version,
                    "agent: payload DEK installed"
                );
            }
            Ok(None) => {}
            Err(e) => {
                warn!(error = ?e, "agent: stored payload DEK rejected");
            }
        }
    }
}

fn read_stored_creds(state_dir: &std::path::Path) -> anyhow::Result<StoredCreds> {
    let bytes = std::fs::read(state_dir.join("agent-creds.json"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Replace the `instance_jwt` field of the persisted creds file
/// (plus the optional client cert/key + payload DEK) in place,
/// leaving other fields untouched. Used after a
/// `CredentialRotation` push.
fn persist_rotated_creds(
    state_dir: &std::path::Path,
    new_jwt: &str,
    new_cert: &str,
    new_key: &str,
    new_payload_dek: &[u8],
    new_payload_dek_version: u32,
) -> anyhow::Result<()> {
    let creds_path = state_dir.join("agent-creds.json");
    let bytes = std::fs::read(&creds_path)?;
    let mut creds: StoredCreds = serde_json::from_slice(&bytes)?;
    creds.instance_jwt = new_jwt.to_owned();
    creds.issued_at = chrono::Utc::now();
    if !new_cert.is_empty() {
        creds.client_cert_pem = new_cert.to_owned();
    }
    if !new_key.is_empty() {
        creds.client_key_pem = new_key.to_owned();
    }
    if !new_payload_dek.is_empty() && new_payload_dek_version != 0 {
        creds.payload_dek_b64 = B64.encode(new_payload_dek);
        creds.payload_dek_version = new_payload_dek_version;
    }
    let new_bytes = serde_json::to_vec_pretty(&creds)?;
    let tmp = creds_path.with_extension("json.tmp");
    std::fs::write(&tmp, new_bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, &creds_path)?;
    Ok(())
}

/// Retry `op` with exponential backoff until it succeeds, returning its value.
///
/// Used for the INITIAL Register so a transient CP outage at pod boot doesn't
/// permanently wedge enrollment. There is no max-attempts cap on purpose: a
/// gateway that can't reach its CP has nothing better to do than keep trying,
/// and the caller's task is aborted on shutdown — which cancels the `sleep`
/// await — so this never needs an explicit cancellation token. A genuinely
/// permanent failure (e.g. a bad bootstrap token) retries too, but that is no
/// worse than the old one-shot behaviour (which also never enrolled) and
/// self-heals if the cause clears.
async fn retry_with_backoff<T, F, Fut>(initial: Duration, max: Duration, mut op: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let mut backoff = Backoff::new(initial, max, true);
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match op().await {
            Ok(v) => {
                if attempt > 1 {
                    info!(attempt, "agent: initial Register succeeded after retries");
                }
                return v;
            }
            Err(e) => {
                let delay = backoff.next_delay();
                warn!(error = ?e, attempt, ?delay, "agent: initial Register failed; retrying after backoff");
                tokio::time::sleep(delay).await;
            }
        }
    }
}

fn extract_token(url: &str) -> anyhow::Result<String> {
    // Enrollment URL: `<base>/enroll/v1#token=ENROL-<nonce>`.
    let frag = url
        .split_once('#')
        .map(|(_, f)| f)
        .ok_or_else(|| anyhow::anyhow!("enrollment URL missing fragment"))?;
    let token = frag
        .split('&')
        .find_map(|kv| kv.strip_prefix("token="))
        .ok_or_else(|| anyhow::anyhow!("enrollment URL missing token=..."))?;
    Ok(token.to_string())
}

fn hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A gateway restart used to take whatever the agent had buffered with it.
    /// Those samples are billable tool calls, so every deploy quietly cost a
    /// flush interval of revenue.
    #[tokio::test]
    async fn a_shutdown_flush_ships_what_is_still_buffered() {
        let runner = AgentRunner::new(AgentRunnerConfig::default());
        let metrics = runner.metrics();
        for i in 0..3 {
            metrics.record(crate::metrics::ToolCallSample {
                plugin_id: "github".into(),
                tool_name: format!("t{i}"),
                binding_id: None,
                started_at: chrono::Utc::now(),
                duration: Duration::from_millis(1),
                outcome: crate::metrics::SampleOutcome::Ok,
                error_code: None,
                error_hash: None,
                request_id: None,
                caller_subject: None,
                request_payload: None,
                response_payload: None,
                payload_encrypted: false,
                dek_version: 0,
            });
        }

        let (tx, mut rx) = mpsc::channel(8);
        runner.flush_remaining(&tx).await;

        let msg = rx.try_recv().expect("the buffered batch must be shipped");
        let Some(AgentKind::MetricsReport(report)) = msg.kind else {
            panic!("expected a MetricsReport");
        };
        assert_eq!(report.invocations.len(), 3);
        assert!(
            metrics.drain().0.is_empty(),
            "the buffer is emptied, not copied"
        );
    }

    /// `finished()` must resolve even when the agent stopped first — a shutdown
    /// that races the agent would otherwise wait out its whole timeout.
    #[tokio::test]
    async fn finished_resolves_when_the_agent_already_stopped() {
        let runner = AgentRunner::new(AgentRunnerConfig::default());
        let handle = runner.shutdown_handle();
        runner
            .shutdown_finished
            .store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::time::timeout(Duration::from_millis(200), handle.finished())
            .await
            .expect("finished() must not block once the agent has stopped");
    }

    struct FakeApplier {
        ok: bool,
    }

    #[async_trait::async_trait]
    impl ConfigApplier for FakeApplier {
        async fn apply(&self, _bundle: &ConfigBundle) -> Result<(), String> {
            if self.ok {
                Ok(())
            } else {
                Err("apply rejected".into())
            }
        }
    }

    /// The initial-Register retry survives transient failures and returns the
    /// first success — a CP that's briefly unreachable at pod boot no longer
    /// permanently wedges enrollment.
    #[tokio::test]
    async fn retry_with_backoff_recovers_after_transient_failures() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let calls = Arc::new(AtomicU32::new(0));
        let c = calls.clone();
        let out = retry_with_backoff(
            Duration::from_millis(1),
            Duration::from_millis(2),
            move || {
                let c = c.clone();
                async move {
                    // Fail the first two attempts, succeed on the third.
                    let n = c.fetch_add(1, Ordering::SeqCst);
                    if n < 2 {
                        anyhow::bail!("transient outage {n}")
                    } else {
                        Ok::<_, anyhow::Error>(format!("registered-{n}"))
                    }
                }
            },
        )
        .await;
        assert_eq!(out, "registered-2");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "failed twice then succeeded on the third attempt"
        );
    }

    // The trait is object-safe + async-usable so the gateway can implement it
    // and the agent can hold it behind `dyn`. The ConfigUpdate handler maps
    // Ok→"active" and Err(e)→("error", e) on the ack.
    #[tokio::test]
    async fn config_applier_trait_contract() {
        let ok: Arc<dyn ConfigApplier> = Arc::new(FakeApplier { ok: true });
        assert!(ok.apply(&ConfigBundle::default()).await.is_ok());

        let err: Arc<dyn ConfigApplier> = Arc::new(FakeApplier { ok: false });
        assert_eq!(
            err.apply(&ConfigBundle::default()).await.unwrap_err(),
            "apply rejected"
        );
    }
}
