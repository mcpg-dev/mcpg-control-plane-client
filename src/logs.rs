//! Gateway log lines — gateway-side capture + batched ship to the CP via
//! Channel `LogBatch`. The logs lane mirrors `metrics.rs` exactly: a bounded
//! ring (`Mutex<VecDeque>`), synchronous drop-oldest-on-overflow `record`, a
//! `drain` that resets the dropped counter, and a `flush_loop` shipping on its
//! own staggered cadence.
//!
//! PRIVACY: unlike the metrics lane (names + hashes only), a log line carries
//! the rendered message verbatim — the tenant's OWN gateway logs surfaced back
//! to them (the same data `kubectl logs` shows). v1 ships the message string +
//! level + target only (no structured fields).

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mcpg_control_plane_core::proto::agent_message::Kind as AgentKind;
use mcpg_control_plane_core::proto::{AgentMessage, LogBatch, LogLevel as ProtoLevel, LogLine};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Recent-N-lines ring; non-durable by design.
pub const DEFAULT_LOG_BUFFER_CAP: usize = 5_000;
/// Cap on lines-per-LogBatch (bounds wire size + CP-side insert cost).
pub const DEFAULT_LOG_BATCH_CAP: usize = 500;
/// Distinct from heartbeat (30s) + metrics (30s) so log flushes stagger
/// against the co-ticking pair rather than piling a third wake on the same tick.
pub const DEFAULT_LOG_FLUSH_INTERVAL: Duration = Duration::from_secs(45);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    fn to_proto(self) -> ProtoLevel {
        match self {
            Self::Trace => ProtoLevel::Trace,
            Self::Debug => ProtoLevel::Debug,
            Self::Info => ProtoLevel::Info,
            Self::Warn => ProtoLevel::Warn,
            Self::Error => ProtoLevel::Error,
        }
    }
}

/// One captured log line. Flat projection (no structured-field map) so the
/// capture path stays cheap.
#[derive(Clone, Debug)]
pub struct LogLineSample {
    pub at: chrono::DateTime<chrono::Utc>,
    pub level: LogLevel,
    pub target: String,
    pub message: String,
    pub plugin_id: Option<String>,
}

/// Cheap-to-clone handle (internal `Arc`); clones share the same ring.
#[derive(Clone)]
pub struct LogBuffer {
    inner: Arc<Inner>,
}

struct Inner {
    buf: Mutex<VecDeque<LogLineSample>>,
    cap: usize,
    batch_cap: usize,
    dropped_overflow: AtomicU64,
    seq: AtomicU64,
}

impl LogBuffer {
    pub fn new() -> Self {
        Self::with_caps(DEFAULT_LOG_BUFFER_CAP, DEFAULT_LOG_BATCH_CAP)
    }

    pub fn with_caps(cap: usize, batch_cap: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                buf: Mutex::new(VecDeque::with_capacity(cap)),
                cap,
                batch_cap,
                dropped_overflow: AtomicU64::new(0),
                seq: AtomicU64::new(0),
            }),
        }
    }

    /// Record one line. Drops the oldest when full (incrementing
    /// `dropped_overflow`). Synchronous + fast — never blocks the emitter.
    pub fn record(&self, line: LogLineSample) {
        let mut buf = self.inner.buf.lock();
        if buf.len() >= self.inner.cap {
            buf.pop_front();
            self.inner.dropped_overflow.fetch_add(1, Ordering::Relaxed);
        }
        buf.push_back(line);
    }

    /// Drain up to `batch_cap` oldest lines + the dropped count since the last
    /// drain (resets it) + the next monotonic seq.
    pub fn drain(&self) -> (Vec<LogLineSample>, u64, u64) {
        let mut buf = self.inner.buf.lock();
        let n = buf.len().min(self.inner.batch_cap);
        let drained: Vec<_> = buf.drain(..n).collect();
        let dropped = self.inner.dropped_overflow.swap(0, Ordering::Relaxed);
        let seq = self.inner.seq.fetch_add(1, Ordering::Relaxed) + 1;
        (drained, dropped, seq)
    }
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a wire `AgentMessage{LogBatch}` from a drained batch. `None` when the
/// batch is empty AND nothing was dropped (don't spam empty batches — but DO
/// send when only `dropped > 0` so the operator sees the overflow).
pub fn batch_to_message(lines: Vec<LogLineSample>, dropped: u64, seq: u64) -> Option<AgentMessage> {
    if lines.is_empty() && dropped == 0 {
        return None;
    }
    let lines: Vec<LogLine> = lines
        .into_iter()
        .map(|l| LogLine {
            at: Some(prost_types::Timestamp {
                seconds: l.at.timestamp(),
                nanos: l.at.timestamp_subsec_nanos() as i32,
            }),
            level: l.level.to_proto() as i32,
            target: l.target,
            message: l.message,
            plugin_id: l.plugin_id.unwrap_or_default(),
        })
        .collect();
    Some(AgentMessage {
        kind: Some(AgentKind::LogBatch(LogBatch {
            at: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
            seq,
            lines,
            dropped_overflow: dropped,
        })),
    })
}

/// Background loop: every `interval`, drain + ship over `out_tx`. Stops when
/// `out_tx` closes (Channel reconnecting).
pub async fn flush_loop(buffer: LogBuffer, out_tx: mpsc::Sender<AgentMessage>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // immediate
    loop {
        let (drained, dropped, seq) = buffer.drain();
        let count = drained.len();
        if let Some(msg) = batch_to_message(drained, dropped, seq) {
            if out_tx.send(msg).await.is_err() {
                debug!("log flush: outbound channel closed; stopping");
                break;
            }
            debug!(count, dropped, seq, "log flush: shipped batch");
        }
        ticker.tick().await;
    }
    let buffered = buffer.inner.buf.lock().len();
    if buffered > 0 {
        warn!(buffered, "log flush: shutdown with lines still in buffer");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(msg: &str, level: LogLevel) -> LogLineSample {
        LogLineSample {
            at: chrono::Utc::now(),
            level,
            target: "mcpg::test".into(),
            message: msg.into(),
            plugin_id: None,
        }
    }

    #[test]
    fn record_and_drain_round_trip() {
        let b = LogBuffer::new();
        for i in 0..3 {
            b.record(line(&format!("m{i}"), LogLevel::Info));
        }
        let (drained, dropped, seq) = b.drain();
        assert_eq!(drained.len(), 3);
        assert_eq!(dropped, 0);
        assert_eq!(seq, 1);
        assert_eq!(drained[0].message, "m0"); // FIFO
        assert_eq!(drained[2].message, "m2");
    }

    #[test]
    fn overflow_drops_oldest_and_counts() {
        let b = LogBuffer::with_caps(3, 10);
        for i in 0..5 {
            b.record(line(&format!("m{i}"), LogLevel::Warn));
        }
        let (drained, dropped, _) = b.drain();
        assert_eq!(drained.len(), 3);
        assert_eq!(dropped, 2);
        assert_eq!(drained[0].message, "m2"); // oldest two dropped
    }

    #[test]
    fn batch_cap_respected() {
        let b = LogBuffer::with_caps(100, 5);
        for i in 0..20 {
            b.record(line(&format!("m{i}"), LogLevel::Debug));
        }
        let (drained, _, _) = b.drain();
        assert_eq!(drained.len(), 5);
        assert_eq!(drained[0].message, "m0");
    }

    #[test]
    fn dropped_resets_on_drain() {
        let b = LogBuffer::with_caps(2, 10);
        for i in 0..5 {
            b.record(line(&format!("m{i}"), LogLevel::Error));
        }
        assert_eq!(b.drain().1, 3);
        assert_eq!(b.drain().1, 0);
    }

    #[test]
    fn skips_empty_no_drops() {
        assert!(batch_to_message(vec![], 0, 1).is_none());
    }

    #[test]
    fn emits_when_only_drops() {
        let msg = batch_to_message(vec![], 7, 1).unwrap();
        match msg.kind {
            Some(AgentKind::LogBatch(b)) => {
                assert!(b.lines.is_empty());
                assert_eq!(b.dropped_overflow, 7);
                assert_eq!(b.seq, 1);
            }
            _ => panic!("expected LogBatch"),
        }
    }

    #[test]
    fn batch_carries_level_target_message() {
        let mut l = line("boom", LogLevel::Error);
        l.target = "mcpg::dispatch".into();
        l.plugin_id = Some("github".into());
        let msg = batch_to_message(vec![l], 0, 3).unwrap();
        match msg.kind {
            Some(AgentKind::LogBatch(b)) => {
                assert_eq!(b.lines.len(), 1);
                assert_eq!(b.lines[0].level, ProtoLevel::Error as i32);
                assert_eq!(b.lines[0].target, "mcpg::dispatch");
                assert_eq!(b.lines[0].message, "boom");
                assert_eq!(b.lines[0].plugin_id, "github");
            }
            _ => panic!("expected LogBatch"),
        }
    }
}
