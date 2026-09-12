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
use tracing::{debug, error, info, warn};

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
    /// Host hook that snapshots the process for the periodic
    /// `StatusReport`. `None` → no reports (legacy behaviour for
    /// non-gateway agents). See [`crate::status::StatusSource`].
    status_source: Option<Arc<dyn crate::status::StatusSource>>,
    /// Hash of the last config bundle this process runs — the LKG
    /// preload at boot, then every successfully-applied ConfigUpdate.
    /// Stamped as `config_hash` on each `StatusReport` so the CP sees
    /// what is actually in effect, not what it last pushed.
    applied_config_hash: Arc<ArcSwap<Option<String>>>,
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
            status_source: None,
            applied_config_hash: Arc::new(ArcSwap::from_pointee(None)),
        }
    }

    /// Wire a host hook that applies pushed config bundles (e.g. the gateway's
    /// in-process hot-reload). Without it, pushed bundles are cached but not
    /// applied (legacy behaviour).
    pub fn with_config_applier(mut self, applier: Arc<dyn ConfigApplier>) -> Self {
        self.config_applier = Some(applier);
        self
    }

    /// Wire a host hook that snapshots the process for the periodic
    /// `StatusReport` (plugin table, warnings, clustering health on the
    /// console's gateway pages). Without it the agent sends none.
    pub fn with_status_source(mut self, source: Arc<dyn crate::status::StatusSource>) -> Self {
        self.status_source = Some(source);
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
        match self.cached_creds() {
            Some(creds) => {
                info!(instance_id = %creds.instance_id, "agent: using cached creds");
                self.install_creds(&creds).await;
            }
            None => {
                self.register_fresh().await?;
            }
        }

        // Best-effort: preload the last-known-good config so the
        // gateway can serve traffic immediately on restart.
        let lkg = LkgCache::in_state_dir(&self.cfg.state_dir);
        if let Ok(Some((hash, _))) = lkg.load_bundle() {
            info!(%hash, "agent: preloaded LKG config");
            self.applied_config_hash.store(Arc::new(Some(hash.clone())));
            let _ = self.events.send(AgentEvent::ConfigReceived { hash });
        }

        self.run_loop().await
    }

    /// Run the heartbeat + channel loop. Reconnects with backoff
    /// on failure. Returns only when the underlying error is
    /// non-recoverable.
    async fn run_loop(&self) -> anyhow::Result<()> {
        let mut backoff = Backoff::new(self.cfg.backoff_initial, self.cfg.backoff_max, true);
        let refresh_window = token_refresh_window(self.cfg.heartbeat_interval);

        loop {
            if self.stopping.load(std::sync::atomic::Ordering::SeqCst) {
                info!("agent: shutdown requested; run loop stopping");
                self.shutdown_finished
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                self.shutdown_done.notify_waiters();
                return Ok(());
            }
            // A token the CP would refuse (or is about to) is replaced before
            // the connect, so an agent that missed its rotation pushes never
            // presents it. The normal case stays the CredentialRotation push.
            let now = chrono::Utc::now().timestamp();
            let exp = match self.client.current_jwt().await {
                Some(jwt) => jwt_exp(&jwt),
                None => None,
            };
            if expires_within(exp, now, refresh_window) {
                match extract_token(&self.cfg.enrollment_url) {
                    Ok(_) => {
                        info!(
                            ?exp,
                            "agent: instance token expired or about to; re-enrolling before connecting"
                        );
                        self.register_fresh().await?;
                    }
                    Err(e) => warn!(
                        error = %e,
                        "agent: instance token expired or about to, but no enrollment_url to re-enrol with"
                    ),
                }
            }
            match self.run_session().await {
                Ok(()) => {
                    backoff.reset();
                    info!("agent: session ended cleanly");
                }
                Err(e) if is_credential_rejection(&e) => {
                    let delay = backoff.next_delay();
                    warn!(
                        error = %e,
                        ?delay,
                        "agent: CP rejected the instance credentials; re-enrolling"
                    );
                    let _ = self.events.send(AgentEvent::ChannelDisconnected {
                        reason: e.to_string(),
                    });
                    self.client.reset().await;
                    // The rejected creds are discarded only once something can
                    // replace them; without an enrollment token they stay on
                    // disk and the loop keeps retrying them at backoff cadence.
                    if let Err(e) = extract_token(&self.cfg.enrollment_url) {
                        error!(
                            error = %e,
                            "agent: cannot re-enrol after credential rejection; set control_plane.enrollment_url"
                        );
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    discard_stored_creds(&self.cfg.state_dir);
                    tokio::time::sleep(delay).await;
                    self.register_fresh().await?;
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
    async fn run_session(&self) -> anyhow::Result<()> {
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

        // Status ticker — snapshots the host on every tick (first one
        // immediate, so the console's status card fills right after
        // attach) and ships a `StatusReport`. Only when the host wired
        // a source.
        let status_handle = self.status_source.as_ref().map(|source| {
            let source = source.clone();
            let hash = self.applied_config_hash.clone();
            let status_tx = out_tx.clone();
            tokio::spawn(async move {
                crate::status::status_loop(
                    source,
                    hash,
                    status_tx,
                    crate::status::DEFAULT_STATUS_INTERVAL,
                )
                .await;
            })
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
        if let Some(h) = status_handle {
            h.abort();
        }
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
                    if applied_state == "active" && !hash.is_empty() {
                        self.applied_config_hash.store(Arc::new(Some(hash.clone())));
                    }

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

    /// The creds persisted by an earlier Register or rotation, if readable.
    /// The token's `exp` is checked by the run loop before every connect.
    fn cached_creds(&self) -> Option<StoredCreds> {
        read_stored_creds(&self.cfg.state_dir).ok()
    }

    /// Make `creds` the ones the client presents: JWT, payload DEK, and the
    /// mTLS material (with a channel reset so the next connect handshakes
    /// with the new client cert).
    async fn install_creds(&self, creds: &StoredCreds) {
        self.client.set_jwt(creds.instance_jwt.clone()).await;
        // Empty DEK fields → `None`, gateway falls through to plaintext
        // capture (legacy CP-side encrypt at ingest).
        self.install_payload_dek_from_creds(creds);
        // No-op when the endpoint scheme is plain http.
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
    }

    /// Perform the Register exchange with the enrollment token, persist the
    /// issued creds, and install them on the client. Retries the RPC with
    /// backoff until the CP answers; fails only when there is no enrollment
    /// token to present.
    async fn register_fresh(&self) -> anyhow::Result<StoredCreds> {
        let creds_path = self.cfg.state_dir.join("agent-creds.json");
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

        // A transient CP outage (the CP rolling, a network blip, the gRPC
        // advertise endpoint not yet routable) must not wedge enrollment. This
        // runs in the agent's own task, so the gateway's HTTP server keeps
        // serving while it retries in the background.
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
        self.install_creds(&creds).await;
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

/// Remove the persisted creds so a restart re-enrols instead of presenting a
/// token the CP has already refused. Best-effort.
fn discard_stored_creds(state_dir: &std::path::Path) {
    if let Err(e) = std::fs::remove_file(state_dir.join("agent-creds.json"))
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(error = ?e, "agent: could not remove rejected creds file");
    }
}

/// Floor on how much validity a token must have left before a connect.
const MIN_TOKEN_REFRESH_WINDOW: Duration = Duration::from_secs(5 * 60);

/// A token due to expire within this window is replaced before it is
/// presented: enough heartbeats to notice a rotation push that never came.
fn token_refresh_window(heartbeat_interval: Duration) -> Duration {
    MIN_TOKEN_REFRESH_WINDOW.max(heartbeat_interval.saturating_mul(3))
}

/// The `exp` claim of a JWT, read from the payload without checking the
/// signature — the CP verifies; this only decides whether to bother it.
fn jwt_exp(jwt: &str) -> Option<i64> {
    let payload = jwt.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let exp = claims.get("exp")?;
    exp.as_i64().or_else(|| exp.as_f64().map(|f| f as i64))
}

/// Whether a token with this `exp` must be replaced before use. An
/// unreadable `exp` counts as expired: a token this client cannot read is
/// not one to build a session on.
fn expires_within(exp: Option<i64>, now: i64, window: Duration) -> bool {
    match exp {
        Some(exp) => exp.saturating_sub(now) <= window.as_secs() as i64,
        None => true,
    }
}

/// Whether a session error is the CP refusing the presented instance
/// credentials, as opposed to a transport blip or a stream that ended. That
/// is a `tonic::Status` anywhere in the chain with code `Unauthenticated`
/// (the auth interceptor's verdict on the `mcpg-instance-token` header), or
/// `PermissionDenied` whose message names the instance token.
fn is_credential_rejection(err: &anyhow::Error) -> bool {
    let Some(status) = err
        .chain()
        .find_map(|cause| cause.downcast_ref::<tonic::Status>())
    else {
        return false;
    };
    match status.code() {
        tonic::Code::Unauthenticated => true,
        tonic::Code::PermissionDenied => {
            let message = status.message().to_ascii_lowercase();
            message.contains("instance-token") || message.contains("instance token")
        }
        _ => false,
    }
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
/// Used for the Register exchange (first enrolment and re-enrolment) so a
/// transient CP outage doesn't wedge the agent. There is no max-attempts cap
/// on purpose: a gateway that can't reach its CP has nothing better to do than
/// keep trying, and the caller's task is aborted on shutdown — which cancels
/// the `sleep` await — so this never needs an explicit cancellation token. A
/// genuinely permanent failure (e.g. a bad bootstrap token) retries too, which
/// enrols no worse than giving up would and self-heals if the cause clears.
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
                    info!(attempt, "agent: Register succeeded after retries");
                }
                return v;
            }
            Err(e) => {
                let delay = backoff.next_delay();
                warn!(error = ?e, attempt, ?delay, "agent: Register failed; retrying after backoff");
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

    /// An unsigned JWT-shaped string with the given payload JSON.
    fn jwt_with_payload(payload: &str) -> String {
        let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes());
        format!(
            "{}.{}.sig",
            b64(r#"{"alg":"EdDSA","typ":"JWT"}"#),
            b64(payload)
        )
    }

    #[test]
    fn jwt_exp_reads_the_payload_claim() {
        assert_eq!(
            jwt_exp(&jwt_with_payload(
                r#"{"sub":"instance:x","exp":1700000000}"#
            )),
            Some(1_700_000_000)
        );
        // Padded base64url (some encoders keep the `=`) decodes too.
        let padded = format!(
            "{}==",
            jwt_with_payload(r#"{"exp":42}"#)
                .rsplit_once('.')
                .unwrap()
                .0
        );
        assert_eq!(jwt_exp(&format!("{padded}.sig")), Some(42));
        // A float `exp` is still a deadline.
        assert_eq!(jwt_exp(&jwt_with_payload(r#"{"exp":42.0}"#)), Some(42));
    }

    #[test]
    fn jwt_exp_is_none_for_malformed_or_missing() {
        assert_eq!(jwt_exp(""), None, "empty");
        assert_eq!(jwt_exp("not-a-jwt"), None, "no dots");
        assert_eq!(jwt_exp("a.!!!.c"), None, "payload is not base64url");
        assert_eq!(jwt_exp("a.bm90IGpzb24.c"), None, "payload is not JSON");
        assert_eq!(
            jwt_exp(&jwt_with_payload(r#"{"sub":"instance:x"}"#)),
            None,
            "no exp claim"
        );
        assert_eq!(
            jwt_exp(&jwt_with_payload(r#"{"exp":"soon"}"#)),
            None,
            "exp is not a number"
        );
    }

    /// Whatever cannot be read is treated as "refresh now" — the loop never
    /// builds a session on a token it cannot vouch for.
    #[test]
    fn expires_within_treats_unreadable_as_expired() {
        let window = Duration::from_secs(300);
        assert!(expires_within(None, 1_000, window));
        assert!(expires_within(Some(900), 1_000, window), "already past");
        assert!(expires_within(Some(1_000), 1_000, window), "expiring now");
        assert!(
            expires_within(Some(1_300), 1_000, window),
            "at the window edge"
        );
        assert!(
            !expires_within(Some(1_301), 1_000, window),
            "outside the window"
        );
    }

    #[test]
    fn token_refresh_window_is_five_minutes_or_three_heartbeats() {
        assert_eq!(
            token_refresh_window(Duration::from_secs(30)),
            Duration::from_secs(300)
        );
        assert_eq!(
            token_refresh_window(Duration::from_secs(120)),
            Duration::from_secs(360)
        );
    }

    #[test]
    fn credential_rejection_is_unauthenticated_or_a_named_permission_denied() {
        let rejected = |s: tonic::Status| is_credential_rejection(&anyhow::Error::from(s));

        // The CP auth interceptor's verdict on a stale token.
        assert!(rejected(tonic::Status::unauthenticated(
            "instance-token: ExpiredSignature"
        )));
        assert!(rejected(tonic::Status::unauthenticated(
            "missing instance-token"
        )));
        // PermissionDenied counts only when it names the instance token.
        assert!(rejected(tonic::Status::permission_denied(
            "Instance-Token revoked for this instance"
        )));
        assert!(rejected(tonic::Status::permission_denied(
            "instance token no longer accepted"
        )));
        assert!(!rejected(tonic::Status::permission_denied(
            "peer cert SPIFFE URI spiffe://a does not match JWT identity spiffe://b"
        )));
        // Transport and server trouble is retried with the same creds.
        assert!(!rejected(tonic::Status::unavailable("connection reset")));
        assert!(!rejected(tonic::Status::internal("db down")));
        assert!(!rejected(tonic::Status::cancelled("stream closed")));

        // A Status wrapped in context is still found; a plain error is not.
        let wrapped = anyhow::Error::from(tonic::Status::unauthenticated("instance-token: x"))
            .context("opening Channel");
        assert!(is_credential_rejection(&wrapped));
        assert!(!is_credential_rejection(&anyhow::anyhow!(
            "no instance JWT cached; call register() first"
        )));
    }

    /// A stand-in CP: Register hands out a fresh token; Channel accepts only
    /// that token and refuses every other one the way the real auth
    /// interceptor does. Records which tokens Channel was tried with.
    mod fake_cp {
        use std::pin::Pin;
        use std::sync::{Arc, Mutex};

        use mcpg_control_plane_core::proto::agent_control_server::{
            AgentControl, AgentControlServer,
        };
        use mcpg_control_plane_core::proto::{
            AgentMessage, DeregisterRequest, DeregisterResponse, HeartbeatRequest,
            HeartbeatResponse, PullConfigRequest, PullConfigResponse, RegisterRequest,
            RegisterResponse, ServerMessage,
        };
        use tonic::{Request, Response, Status, Streaming};

        #[derive(Default)]
        struct Inner {
            channel_tokens: Mutex<Vec<String>>,
            registers: Mutex<u32>,
            /// Keeps every accepted Channel's outbound stream open.
            senders: Mutex<Vec<tokio::sync::mpsc::Sender<Result<ServerMessage, Status>>>>,
        }

        /// Cheap to clone: the server owns one handle, the test keeps another.
        #[derive(Clone)]
        pub struct FakeCp {
            /// The token Register issues — JWT-shaped with a far-off `exp`,
            /// so the client's own expiry check accepts it.
            fresh_jwt: String,
            inner: Arc<Inner>,
        }

        impl FakeCp {
            pub fn new() -> Self {
                let exp = chrono::Utc::now().timestamp() + 3600;
                Self {
                    fresh_jwt: super::jwt_with_payload(&format!(r#"{{"exp":{exp}}}"#)),
                    inner: Arc::default(),
                }
            }

            pub fn fresh_jwt(&self) -> &str {
                &self.fresh_jwt
            }

            /// Every token a Channel open presented, in order.
            pub fn channel_tokens(&self) -> Vec<String> {
                self.inner.channel_tokens.lock().unwrap().clone()
            }

            pub fn registers(&self) -> u32 {
                *self.inner.registers.lock().unwrap()
            }
        }

        #[tonic::async_trait]
        impl AgentControl for FakeCp {
            async fn register(
                &self,
                _request: Request<RegisterRequest>,
            ) -> Result<Response<RegisterResponse>, Status> {
                *self.inner.registers.lock().unwrap() += 1;
                Ok(Response::new(RegisterResponse {
                    instance_jwt: self.fresh_jwt.clone(),
                    instance_id: "11111111-1111-7111-8111-111111111111".into(),
                    cp_endpoint: "http://fake".into(),
                    ..Default::default()
                }))
            }

            type ChannelStream =
                Pin<Box<dyn futures::Stream<Item = Result<ServerMessage, Status>> + Send>>;

            async fn channel(
                &self,
                request: Request<Streaming<AgentMessage>>,
            ) -> Result<Response<Self::ChannelStream>, Status> {
                let token = request
                    .metadata()
                    .get("mcpg-instance-token")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                self.inner
                    .channel_tokens
                    .lock()
                    .unwrap()
                    .push(token.clone());
                if token != self.fresh_jwt {
                    return Err(Status::unauthenticated("instance-token: ExpiredSignature"));
                }
                let (tx, rx) = tokio::sync::mpsc::channel(4);
                self.inner.senders.lock().unwrap().push(tx);
                Ok(Response::new(Box::pin(
                    tokio_stream::wrappers::ReceiverStream::new(rx),
                )))
            }

            async fn pull_config(
                &self,
                _request: Request<PullConfigRequest>,
            ) -> Result<Response<PullConfigResponse>, Status> {
                Err(Status::unimplemented("fake"))
            }

            async fn heartbeat(
                &self,
                _request: Request<HeartbeatRequest>,
            ) -> Result<Response<HeartbeatResponse>, Status> {
                Err(Status::unimplemented("fake"))
            }

            async fn deregister(
                &self,
                _request: Request<DeregisterRequest>,
            ) -> Result<Response<DeregisterResponse>, Status> {
                Err(Status::unimplemented("fake"))
            }
        }

        /// Serve the fake on a loopback port; returns the endpoint URL.
        pub async fn serve(cp: FakeCp) -> String {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .unwrap();
            let port = listener.local_addr().unwrap().port();
            let incoming =
                tonic::transport::server::TcpIncoming::from_listener(listener, true, None).unwrap();
            tokio::spawn(
                tonic::transport::Server::builder()
                    .add_service(AgentControlServer::new(cp))
                    .serve_with_incoming(incoming),
            );
            format!("http://127.0.0.1:{port}")
        }
    }

    /// Cached creds for `state_dir` carrying `jwt`, as a previous run would
    /// have left them.
    fn write_cached_creds(state_dir: &std::path::Path, jwt: &str) {
        std::fs::create_dir_all(state_dir).unwrap();
        let creds = StoredCreds {
            instance_id: "cached-instance".into(),
            instance_jwt: jwt.into(),
            cp_endpoint: String::new(),
            issued_at: chrono::Utc::now(),
            client_cert_pem: String::new(),
            client_key_pem: String::new(),
            ca_chain_pem: String::new(),
            payload_dek_b64: String::new(),
            payload_dek_version: 0,
        };
        std::fs::write(
            state_dir.join("agent-creds.json"),
            serde_json::to_vec(&creds).unwrap(),
        )
        .unwrap();
    }

    fn runner_against(endpoint: String, state_dir: &std::path::Path) -> AgentRunner {
        AgentRunner::new(AgentRunnerConfig {
            cp_endpoint: endpoint,
            enrollment_url: "http://fake/enroll/v1#token=ENROL-abc".into(),
            instance_uid: "reenrol-test".into(),
            state_dir: state_dir.to_path_buf(),
            heartbeat_interval: Duration::from_millis(100),
            backoff_initial: Duration::from_millis(5),
            backoff_max: Duration::from_millis(20),
            ..AgentRunnerConfig::default()
        })
    }

    /// Collect events until `until` matches one, or the deadline passes.
    async fn events_until(
        rx: &mut broadcast::Receiver<AgentEvent>,
        until: impl Fn(&AgentEvent) -> bool,
    ) -> Vec<AgentEvent> {
        let mut seen = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while let Ok(Ok(ev)) = tokio::time::timeout_at(deadline, rx.recv()).await {
            let done = until(&ev);
            seen.push(ev);
            if done {
                break;
            }
        }
        seen
    }

    /// A cached token the CP refuses is replaced through Register, not
    /// retried forever: the runner re-enrols and the next Channel connects.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejected_token_is_replaced_by_a_fresh_register() {
        let cp = fake_cp::FakeCp::new();
        let endpoint = fake_cp::serve(cp.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        // Well within its lifetime as far as the client can tell, so only the
        // CP's verdict can trigger the re-enrol.
        let far_future = chrono::Utc::now().timestamp() + 3600;
        let stale = jwt_with_payload(&format!(r#"{{"sub":"stale","exp":{far_future}}}"#));
        write_cached_creds(dir.path(), &stale);

        let runner = runner_against(endpoint, dir.path());
        let mut events = runner.subscribe();
        let task = tokio::spawn(async move { runner.run().await });

        let seen = events_until(&mut events, |e| matches!(e, AgentEvent::ChannelConnected)).await;
        task.abort();

        assert!(
            seen.iter().any(|e| matches!(e, AgentEvent::ChannelDisconnected { reason } if reason.contains("Unauthenticated"))),
            "the rejection is surfaced as a disconnect: {seen:?}"
        );
        let registered = seen
            .iter()
            .position(|e| matches!(e, AgentEvent::Registered { .. }))
            .expect("re-enrolled after the rejection");
        let connected = seen
            .iter()
            .position(|e| matches!(e, AgentEvent::ChannelConnected))
            .expect("connected after re-enrolling");
        assert!(registered < connected, "Register precedes the connect");

        let tokens = cp.channel_tokens();
        assert_eq!(tokens.first().map(String::as_str), Some(stale.as_str()));
        assert_eq!(tokens.last().map(String::as_str), Some(cp.fresh_jwt()));
        assert_eq!(cp.registers(), 1);
        let on_disk = read_stored_creds(dir.path()).expect("creds rewritten");
        assert_eq!(on_disk.instance_jwt, cp.fresh_jwt());
    }

    /// A cached token already past `exp` is never presented: the runner
    /// re-enrols before its first connect.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expired_cached_token_is_replaced_before_connecting() {
        let cp = fake_cp::FakeCp::new();
        let endpoint = fake_cp::serve(cp.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let past = chrono::Utc::now().timestamp() - 60;
        write_cached_creds(
            dir.path(),
            &jwt_with_payload(&format!(r#"{{"exp":{past}}}"#)),
        );

        let runner = runner_against(endpoint, dir.path());
        let mut events = runner.subscribe();
        let task = tokio::spawn(async move { runner.run().await });

        let seen = events_until(&mut events, |e| matches!(e, AgentEvent::ChannelConnected)).await;
        task.abort();

        assert!(
            seen.iter()
                .any(|e| matches!(e, AgentEvent::ChannelConnected)),
            "connected: {seen:?}"
        );
        assert!(
            !seen
                .iter()
                .any(|e| matches!(e, AgentEvent::ChannelDisconnected { .. })),
            "no session was attempted with the expired token: {seen:?}"
        );
        assert_eq!(
            cp.channel_tokens(),
            [cp.fresh_jwt().to_owned()],
            "only the fresh token ever reached Channel"
        );
    }
}
