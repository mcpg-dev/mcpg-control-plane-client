//! Per-call tool invocation metrics — gateway-side capture +
//! batched ship to the CP via Channel `MetricsReport`.
//!
//! Design:
//! - `MetricsBuffer` is a bounded ring buffer protected by a
//!   `Mutex<VecDeque>` (writes are short — pushing one sample —
//!   so contention is minimal even under heavy load).
//! - The plugin host calls `record(sample)` synchronously on
//!   every tool dispatch. If the buffer is full, the oldest
//!   sample is dropped and the `dropped_overflow` counter is
//!   incremented; this is surfaced in the next MetricsReport so
//!   the operator knows we lost data.
//!
//!   DELIBERATE TRADEOFF: drop-with-counter, NOT back-pressure. The
//!   recorder sits on the gateway's dispatch hot path — blocking it to
//!   preserve a metrics sample would trade tenant-visible latency for
//!   billing precision. The exact drop COUNT always survives (the
//!   counter rides every report), so the CP knows precisely how many
//!   billable samples were lost; folding that count into usage as a
//!   billing adjustment is the usage-export job's concern
//!   (BILLING.md P4). Overflow needs >~166 sustained calls/sec for the
//!   full 30s flush window at the default 5k cap before any drop.
//! - `flush_loop` is the async task spawned alongside the agent's
//!   Channel session. It wakes every `MetricsBuffer.flush_interval`,
//!   drains the buffer, builds a `MetricsReport`, and sends it
//!   via the agent's outbound mpsc.
//!
//! Privacy invariant: tool *names* + aggregate stats only. Tool
//! arguments and responses are NEVER captured here.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mcpg_control_plane_core::proto::agent_message::Kind as AgentKind;
use mcpg_control_plane_core::proto::{
    AgentMessage, MetricsReport, ToolInvocationSample, ToolOutcome,
};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Default in-memory ring buffer size — at 5 calls/sec for 60s
/// that's a 60-second buffer of headroom even under spikes.
pub const DEFAULT_BUFFER_CAP: usize = 5_000;

/// Default cap on samples-per-MetricsReport. Bounds wire size
/// (~200B per sample × 500 = 100KB max) and per-tx insert cost
/// on the CP side.
pub const DEFAULT_BATCH_CAP: usize = 500;

/// Default flush interval — 30 seconds. Smaller than the
/// 60-second `MAX_AGE` for the next-message pipeline so even
/// idle gateways send something every minute.
pub const DEFAULT_FLUSH_INTERVAL: Duration = Duration::from_secs(30);

/// Captured at the dispatch site. Cheap to construct — no
/// allocations beyond the two strings (plugin_id, tool_name)
/// which the plugin host typically already has interned.
#[derive(Clone, Debug)]
pub struct ToolCallSample {
    pub plugin_id: String,
    pub tool_name: String,
    pub binding_id: Option<String>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub duration: Duration,
    pub outcome: SampleOutcome,
    pub error_code: Option<String>,
    /// BLAKE3 hash of the error message string (or empty when no
    /// error). The dispatch site should use
    /// `MetricsBuffer::hash_error(...)` so a single canonical
    /// hash function is used everywhere.
    pub error_hash: Option<String>,
    pub request_id: Option<String>,
    pub caller_subject: Option<String>,
    /// OPTIONAL request/response payload bytes (Enterprise
    /// opt-in; off by default). Empty unless the gateway captured
    /// payloads at dispatch time.
    ///
    /// When the gateway encrypted these at dispatch time with the
    /// per-tenant DEK, `payload_encrypted` is `true` and
    /// `dek_version` carries the key version that produced the
    /// ciphertext. When `payload_encrypted` is `false`, the bytes
    /// are plaintext and the CP wraps them at ingest (legacy
    /// path, preserved for backward compat).
    pub request_payload: Option<Vec<u8>>,
    pub response_payload: Option<Vec<u8>>,
    pub payload_encrypted: bool,
    pub dek_version: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleOutcome {
    Ok,
    ClientError,
    ServerError,
    PolicyDenied,
    /// Gateway-side pre-dispatch refusal because CP-pushed quota
    /// status said exhausted. No upstream tool ran; the sample
    /// lets operators see the refusal in metrics without the cost
    /// of executing the call.
    QuotaExceeded,
    /// `dev.mcpg/idempotency` cache hit: a previously-cached
    /// terminal envelope was replayed instead of running a new
    /// dispatch. The caller got a success, but no new execution
    /// happened — the CP excludes this from billing/quota math.
    IdempotentReplay,
}

impl SampleOutcome {
    fn to_proto(self) -> ToolOutcome {
        match self {
            Self::Ok => ToolOutcome::Ok,
            Self::ClientError => ToolOutcome::ClientError,
            Self::ServerError => ToolOutcome::ServerError,
            Self::PolicyDenied => ToolOutcome::PolicyDenied,
            Self::QuotaExceeded => ToolOutcome::QuotaExceeded,
            Self::IdempotentReplay => ToolOutcome::IdempotentReplay,
        }
    }
}

/// Cheap-to-clone handle (internal `Arc`). Each clone shares the
/// same buffer + counters.
#[derive(Clone)]
pub struct MetricsBuffer {
    inner: Arc<Inner>,
}

struct Inner {
    buf: Mutex<VecDeque<ToolCallSample>>,
    cap: usize,
    batch_cap: usize,
    dropped_overflow: AtomicU64,
    seq: AtomicU64,
}

impl MetricsBuffer {
    pub fn new() -> Self {
        Self::with_caps(DEFAULT_BUFFER_CAP, DEFAULT_BATCH_CAP)
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

    /// Record one sample. Drops the oldest entry when the buffer
    /// is full (incrementing `dropped_overflow`). Synchronous +
    /// fast — safe to call from any dispatch path.
    pub fn record(&self, sample: ToolCallSample) {
        let mut buf = self.inner.buf.lock();
        if buf.len() >= self.inner.cap {
            buf.pop_front();
            self.inner.dropped_overflow.fetch_add(1, Ordering::Relaxed);
        }
        buf.push_back(sample);
    }

    /// Drain up to `batch_cap` oldest samples and the current
    /// `dropped_overflow` count. Resets the dropped counter so
    /// each flush reports only what was dropped *since the last
    /// flush*.
    pub fn drain(&self) -> (Vec<ToolCallSample>, u64, u64) {
        let mut buf = self.inner.buf.lock();
        let n = buf.len().min(self.inner.batch_cap);
        let drained: Vec<_> = buf.drain(..n).collect();
        let dropped = self.inner.dropped_overflow.swap(0, Ordering::Relaxed);
        let seq = self.inner.seq.fetch_add(1, Ordering::Relaxed) + 1;
        (drained, dropped, seq)
    }

    /// Put a drained batch back at the front of the buffer, oldest first, and
    /// restore its dropped count. Samples that no longer fit are counted as
    /// dropped rather than discarded quietly — the ledger stays neutral to
    /// buffer overflow either way.
    fn requeue_front(&self, samples: Vec<ToolCallSample>, dropped: u64) {
        let total = samples.len();
        let mut buf = self.inner.buf.lock();
        let mut readmitted = 0;
        // Reverse, because each push_front puts its sample ahead of the last.
        for sample in samples.into_iter().rev() {
            if buf.len() >= self.inner.cap {
                break;
            }
            buf.push_front(sample);
            readmitted += 1;
        }
        // Whatever no longer fits is counted, not silently discarded.
        let overflowed = total.saturating_sub(readmitted) as u64;
        self.inner
            .dropped_overflow
            .fetch_add(dropped + overflowed, Ordering::Relaxed);
    }

    /// BLAKE3 hex hash of an error message — operators correlate
    /// the on-CP `error_hash` against gateway logs without ever
    /// shipping the literal string. `None` for empty input.
    pub fn hash_error(msg: &str) -> Option<String> {
        if msg.is_empty() {
            return None;
        }
        Some(blake3::hash(msg.as_bytes()).to_hex().to_string())
    }
}

impl Default for MetricsBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a wire-shape `AgentMessage` from a drained batch.
/// `None` when the batch is empty AND nothing was dropped (we
/// don't want to spam the CP with empty reports — but we DO send
/// when only `dropped > 0` so the operator sees it).
pub fn batch_to_message(
    samples: &[ToolCallSample],
    dropped: u64,
    seq: u64,
) -> Option<AgentMessage> {
    if samples.is_empty() && dropped == 0 {
        return None;
    }
    let invocations: Vec<ToolInvocationSample> = samples
        .iter()
        .map(|s| ToolInvocationSample {
            plugin_id: s.plugin_id.clone(),
            tool_name: s.tool_name.clone(),
            binding_id: s.binding_id.clone().unwrap_or_default(),
            started_at: Some(prost_types::Timestamp {
                seconds: s.started_at.timestamp(),
                nanos: s.started_at.timestamp_subsec_nanos() as i32,
            }),
            duration_ms: s.duration.as_millis().min(u32::MAX as u128) as u32,
            outcome: s.outcome.to_proto() as i32,
            error_code: s.error_code.clone().unwrap_or_default(),
            error_hash: s.error_hash.clone().unwrap_or_default(),
            request_id: s.request_id.clone().unwrap_or_default(),
            caller_subject: s.caller_subject.clone().unwrap_or_default(),
            request_payload: s.request_payload.clone().unwrap_or_default(),
            response_payload: s.response_payload.clone().unwrap_or_default(),
            // Gateway-side encryption flag + key version.
            // Defensive: drop the version unless encryption was
            // actually applied so a buggy caller can't mislabel
            // a plaintext blob as version-stamped ciphertext.
            payload_encrypted: s.payload_encrypted,
            dek_version: if s.payload_encrypted {
                s.dek_version
            } else {
                0
            },
        })
        .collect();
    Some(AgentMessage {
        kind: Some(AgentKind::MetricsReport(MetricsReport {
            at: Some(prost_types::Timestamp {
                seconds: chrono::Utc::now().timestamp(),
                nanos: 0,
            }),
            seq,
            invocations,
            dropped_overflow: dropped,
        })),
    })
}

/// Returns an undelivered batch to the buffer unless disarmed.
///
/// Cancelling a future drops its locals, so this covers both halves of the
/// same problem: a send that fails, and a task aborted while awaiting one.
struct InFlight<'a> {
    buffer: &'a MetricsBuffer,
    samples: Vec<ToolCallSample>,
    dropped: u64,
}

impl InFlight<'_> {
    /// The batch is on its way; stop tracking it.
    fn disarm(&mut self) {
        self.samples = Vec::new();
        self.dropped = 0;
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        if self.samples.is_empty() && self.dropped == 0 {
            return;
        }
        warn!(
            samples = self.samples.len(),
            dropped = self.dropped,
            "metrics flush: batch undelivered; returning it to the buffer"
        );
        self.buffer
            .requeue_front(std::mem::take(&mut self.samples), self.dropped);
    }
}

/// Background loop: every `interval`, drain the buffer + ship
/// the result over `out_tx`. Stops when `out_tx` is closed
/// (Channel reconnecting).
pub async fn flush_loop(
    buffer: MetricsBuffer,
    out_tx: mpsc::Sender<AgentMessage>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // immediate
    loop {
        let (drained, dropped, seq) = buffer.drain();
        let count = drained.len();
        // The batch is out of the buffer and lives only in this local. The
        // task is aborted on every Channel reconnect, and an abort drops the
        // future — and with it the batch — at the `send` below. The guard
        // hands it back instead, so a reconnect costs no billable calls.
        let mut inflight = InFlight {
            buffer: &buffer,
            samples: drained,
            dropped,
        };
        if let Some(msg) = batch_to_message(&inflight.samples, dropped, seq) {
            if out_tx.send(msg).await.is_err() {
                // Nothing was queued, so the batch is still owed. Leave the
                // guard armed to return it and let the next session ship it.
                debug!("metrics flush: outbound channel closed; stopping");
                break;
            }
            debug!(count, dropped, seq, "metrics flush: shipped batch");
        }
        inflight.disarm();
        ticker.tick().await;
    }
    if buffer.inner.buf.lock().is_empty() {
        debug!("metrics flush: buffer empty at shutdown");
    } else {
        warn!(
            buffered = buffer.inner.buf.lock().len(),
            "metrics flush: shutdown with samples still in buffer"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(plugin: &str, tool: &str, outcome: SampleOutcome, dur: Duration) -> ToolCallSample {
        ToolCallSample {
            plugin_id: plugin.into(),
            tool_name: tool.into(),
            binding_id: None,
            started_at: chrono::Utc::now(),
            duration: dur,
            outcome,
            error_code: None,
            error_hash: None,
            request_id: None,
            caller_subject: None,
            request_payload: None,
            response_payload: None,
            payload_encrypted: false,
            dek_version: 0,
        }
    }

    #[test]
    fn record_and_drain_round_trip() {
        let b = MetricsBuffer::new();
        for i in 0..3 {
            b.record(sample(
                "p",
                "t",
                SampleOutcome::Ok,
                Duration::from_millis(10 + i),
            ));
        }
        let (drained, dropped, seq) = b.drain();
        assert_eq!(drained.len(), 3);
        assert_eq!(dropped, 0);
        assert_eq!(seq, 1);
        // FIFO order preserved.
        assert_eq!(drained[0].duration, Duration::from_millis(10));
        assert_eq!(drained[2].duration, Duration::from_millis(12));
    }

    #[test]
    fn overflow_drops_oldest_and_increments_counter() {
        let b = MetricsBuffer::with_caps(3, 10);
        for i in 0..5 {
            b.record(sample(
                "p",
                "t",
                SampleOutcome::Ok,
                Duration::from_millis(10 + i),
            ));
        }
        let (drained, dropped, _) = b.drain();
        // Oldest 2 dropped; 3 newest remain.
        assert_eq!(drained.len(), 3);
        assert_eq!(dropped, 2);
        assert_eq!(drained[0].duration, Duration::from_millis(12));
        assert_eq!(drained[2].duration, Duration::from_millis(14));
    }

    #[test]
    fn batch_cap_respected_on_drain() {
        let b = MetricsBuffer::with_caps(100, 5);
        for i in 0..20 {
            b.record(sample(
                "p",
                "t",
                SampleOutcome::Ok,
                Duration::from_millis(i),
            ));
        }
        let (drained, _, _) = b.drain();
        assert_eq!(drained.len(), 5);
        // Oldest 5; the rest stay buffered.
        assert_eq!(drained[0].duration, Duration::from_millis(0));
        assert_eq!(drained[4].duration, Duration::from_millis(4));
    }

    #[test]
    fn dropped_counter_resets_on_drain() {
        let b = MetricsBuffer::with_caps(2, 10);
        for i in 0..5 {
            b.record(sample(
                "p",
                "t",
                SampleOutcome::Ok,
                Duration::from_millis(i),
            ));
        }
        let (_, dropped1, _) = b.drain();
        assert_eq!(dropped1, 3);
        let (_, dropped2, _) = b.drain();
        assert_eq!(dropped2, 0);
    }

    #[test]
    fn batch_to_message_skips_empty_no_drops() {
        let msg = batch_to_message(&[], 0, 1);
        assert!(msg.is_none());
    }

    #[test]
    fn batch_to_message_emits_when_only_drops() {
        let msg = batch_to_message(&[], 5, 1).unwrap();
        match msg.kind {
            Some(AgentKind::MetricsReport(m)) => {
                assert!(m.invocations.is_empty());
                assert_eq!(m.dropped_overflow, 5);
            }
            _ => panic!("expected MetricsReport"),
        }
    }

    #[test]
    fn hash_error_is_stable() {
        let h1 = MetricsBuffer::hash_error("connection refused");
        let h2 = MetricsBuffer::hash_error("connection refused");
        assert_eq!(h1, h2);
        assert!(h1.is_some());
        assert_eq!(MetricsBuffer::hash_error(""), None);
    }

    /// Every sample in the buffer is a billable tool call. The flush task is
    /// aborted on each Channel reconnect, and it used to be aborted holding a
    /// batch it had already removed from the buffer — so a reconnect silently
    /// destroyed up to a full flush interval of billing data.
    #[tokio::test]
    async fn an_aborted_flush_returns_its_batch_to_the_buffer() {
        let buffer = MetricsBuffer::new();
        for i in 0..5 {
            buffer.record(sample(
                "github",
                &format!("t{i}"),
                SampleOutcome::Ok,
                Duration::from_millis(1),
            ));
        }

        // A one-slot channel, already full and never read: the flush loop
        // blocks in `send` with the batch drained and in hand.
        let (tx, _rx) = mpsc::channel(1);
        tx.send(AgentMessage { kind: None }).await.unwrap();
        let handle = {
            let buffer = buffer.clone();
            tokio::spawn(async move { flush_loop(buffer, tx, Duration::from_millis(5)).await })
        };
        tokio::time::sleep(Duration::from_millis(60)).await;
        handle.abort();
        let _ = handle.await;

        let (recovered, _, _) = buffer.drain();
        assert_eq!(
            recovered.len(),
            5,
            "an aborted flush must hand its batch back, not take it to the grave"
        );
        // Order is preserved: the buffer is a FIFO the CP reads as a timeline.
        let names: Vec<_> = recovered.iter().map(|s| s.tool_name.as_str()).collect();
        assert_eq!(names, ["t0", "t1", "t2", "t3", "t4"]);
    }

    /// A send that fails delivered nothing, so the batch is still owed.
    #[tokio::test]
    async fn a_failed_send_returns_its_batch_to_the_buffer() {
        let buffer = MetricsBuffer::new();
        buffer.record(sample(
            "github",
            "list_repos",
            SampleOutcome::Ok,
            Duration::from_millis(1),
        ));
        let (tx, rx) = mpsc::channel(1);
        drop(rx); // closed: every send fails
        flush_loop(buffer.clone(), tx, Duration::from_millis(5)).await;

        let (recovered, _, _) = buffer.drain();
        assert_eq!(recovered.len(), 1, "a failed send loses nothing");
    }

    #[test]
    fn batch_to_message_carries_payload_encrypted_flag_and_version() {
        let mut s = sample(
            "github",
            "list_repos",
            SampleOutcome::Ok,
            Duration::from_millis(5),
        );
        s.request_payload = Some(b"ciphertext-blob".to_vec());
        s.payload_encrypted = true;
        s.dek_version = 7;
        let msg = batch_to_message(&[s], 0, 1).unwrap();
        match msg.kind {
            Some(AgentKind::MetricsReport(m)) => {
                assert_eq!(m.invocations.len(), 1);
                assert!(m.invocations[0].payload_encrypted);
                assert_eq!(m.invocations[0].dek_version, 7);
                assert_eq!(m.invocations[0].request_payload, b"ciphertext-blob");
            }
            _ => panic!("expected MetricsReport"),
        }
    }

    #[test]
    fn batch_to_message_strips_dek_version_when_not_encrypted() {
        // Buggy caller scenario: payload_encrypted=false but
        // dek_version!=0. The wire shape must drop the version
        // so the CP doesn't mislabel a plaintext blob.
        let mut s = sample(
            "github",
            "list_repos",
            SampleOutcome::Ok,
            Duration::from_millis(5),
        );
        s.payload_encrypted = false;
        s.dek_version = 99;
        let msg = batch_to_message(&[s], 0, 1).unwrap();
        match msg.kind {
            Some(AgentKind::MetricsReport(m)) => {
                assert!(!m.invocations[0].payload_encrypted);
                assert_eq!(m.invocations[0].dek_version, 0);
            }
            _ => panic!("expected MetricsReport"),
        }
    }

    #[test]
    fn batch_to_message_carries_outcome_correctly() {
        let s = sample(
            "github",
            "list_repos",
            SampleOutcome::ServerError,
            Duration::from_millis(50),
        );
        let msg = batch_to_message(&[s], 0, 1).unwrap();
        match msg.kind {
            Some(AgentKind::MetricsReport(m)) => {
                assert_eq!(m.invocations.len(), 1);
                assert_eq!(m.invocations[0].outcome, ToolOutcome::ServerError as i32);
                assert_eq!(m.invocations[0].duration_ms, 50);
            }
            _ => panic!("expected MetricsReport"),
        }
    }
}
