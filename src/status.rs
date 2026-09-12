//! Periodic `StatusReport` — a host-supplied process snapshot shipped
//! to the CP via Channel, powering the console's per-instance status
//! card (plugin table, warnings, clustering health).
//!
//! Unlike the metrics / log lanes there is no buffer: a report is a
//! point-in-time snapshot, so the loop asks the host's
//! [`StatusSource`] for a fresh one on every tick and ships it
//! directly. A missed report costs nothing — the next tick supersedes
//! it.

use std::time::Duration;

use mcpg_control_plane_core::proto::agent_message::Kind as AgentKind;
use mcpg_control_plane_core::proto::{AgentMessage, ClusterStatus, PluginStatus, StatusReport};
use tokio::sync::mpsc;
use tracing::debug;

/// Distinct from heartbeat/metrics (30s) and logs (45s) so status
/// wakes stagger against the co-ticking timers. Plugin state and
/// cluster health move slowly; a minute of staleness is fine.
pub const DEFAULT_STATUS_INTERVAL: Duration = Duration::from_secs(60);

/// One plugin's state as the host reports it.
#[derive(Clone, Debug)]
pub struct PluginStatusSample {
    pub id: String,
    pub version: String,
    /// "loaded" | "failed" | "unloading" (free-form; the host's own
    /// state vocabulary).
    pub state: String,
    pub error: String,
    pub invocations: u64,
}

/// Coordinator health as this replica sees it. `kind:
/// "single_node"` carries both options unset — there is no backend
/// to probe and no peer set to enumerate.
#[derive(Clone, Debug)]
pub struct ClusterStatusSample {
    pub kind: String,
    /// `None` until the coordinator health probe has run (and always
    /// for single_node / KV-less coordinators, which are never probed).
    pub backend_up: Option<bool>,
    /// Cluster members visible to this replica, itself included.
    /// `None` when the coordinator cannot enumerate peers.
    pub peers: Option<u32>,
}

/// Host snapshot for one report. `config_hash` is stamped by the
/// agent (it tracks the last-applied bundle hash), not the host.
#[derive(Clone, Debug, Default)]
pub struct StatusSnapshot {
    pub plugins: Vec<PluginStatusSample>,
    pub warnings: Vec<String>,
    pub cluster: Option<ClusterStatusSample>,
    /// Digest of the `${secret.*}` values the running config resolved with
    /// (sha256 over sorted `NAME=VALUE\n`, hex); empty when none.
    pub secrets_digest: String,
}

/// Host hook that snapshots the running process for the periodic
/// `StatusReport`. Wired via `AgentRunner::with_status_source`;
/// without it the agent sends no reports (legacy behaviour for
/// non-gateway agents).
#[async_trait::async_trait]
pub trait StatusSource: Send + Sync {
    async fn snapshot(&self) -> StatusSnapshot;
}

/// Build the wire message for one snapshot.
pub(crate) fn snapshot_to_message(snap: StatusSnapshot, config_hash: String) -> AgentMessage {
    AgentMessage {
        kind: Some(AgentKind::StatusReport(StatusReport {
            at: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
            config_hash,
            plugins: snap
                .plugins
                .into_iter()
                .map(|p| PluginStatus {
                    id: p.id,
                    version: p.version,
                    state: p.state,
                    error: p.error,
                    invocations: p.invocations,
                })
                .collect(),
            resources: None,
            warnings: snap.warnings,
            cluster: snap.cluster.map(|c| ClusterStatus {
                kind: c.kind,
                backend_up: c.backend_up,
                peers: c.peers,
            }),
            secrets_digest: snap.secrets_digest,
        })),
    }
}

/// Snapshot + ship on every tick (first tick immediate, so the
/// console lights up right after attach). Stops when the outbound
/// channel closes (Channel reconnect / shutdown).
pub(crate) async fn status_loop(
    source: std::sync::Arc<dyn StatusSource>,
    config_hash: std::sync::Arc<arc_swap::ArcSwap<Option<String>>>,
    out_tx: mpsc::Sender<AgentMessage>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let snap = source.snapshot().await;
        let hash = config_hash.load().as_ref().clone().unwrap_or_default();
        if out_tx.send(snapshot_to_message(snap, hash)).await.is_err() {
            debug!("status: outbound channel closed; stopping");
            break;
        }
        debug!("status: shipped StatusReport");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_maps_cluster_section_onto_the_wire() {
        let snap = StatusSnapshot {
            plugins: vec![PluginStatusSample {
                id: "dev.mcpg.cluster.nats".into(),
                version: "1.0.0".into(),
                state: "loaded".into(),
                error: String::new(),
                invocations: 0,
            }],
            warnings: vec![],
            cluster: Some(ClusterStatusSample {
                kind: "nats".into(),
                backend_up: Some(true),
                peers: Some(3),
            }),
            secrets_digest: String::new(),
        };
        let msg = snapshot_to_message(snap, "hash-1".into());
        let Some(AgentKind::StatusReport(r)) = msg.kind else {
            panic!("expected StatusReport");
        };
        assert_eq!(r.config_hash, "hash-1");
        assert_eq!(r.plugins.len(), 1);
        let c = r.cluster.expect("cluster section on the wire");
        assert_eq!(c.kind, "nats");
        assert_eq!(c.backend_up, Some(true));
        assert_eq!(c.peers, Some(3));
    }

    #[test]
    fn single_node_snapshot_keeps_options_unset() {
        let snap = StatusSnapshot {
            plugins: vec![],
            warnings: vec![],
            cluster: Some(ClusterStatusSample {
                kind: "single_node".into(),
                backend_up: None,
                peers: None,
            }),
            secrets_digest: String::new(),
        };
        let msg = snapshot_to_message(snap, String::new());
        let Some(AgentKind::StatusReport(r)) = msg.kind else {
            panic!("expected StatusReport");
        };
        let c = r.cluster.expect("cluster section on the wire");
        assert_eq!(c.kind, "single_node");
        assert_eq!(c.backend_up, None);
        assert_eq!(c.peers, None);
    }
}
