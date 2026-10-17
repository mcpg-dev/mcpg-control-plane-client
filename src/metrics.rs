//! Per-call tool invocation metrics — gateway-side capture +
//! batched ship to the CP via Channel `MetricsReport`.
//!
//! Design:
//! - `MetricsBuffer` is a bounded ring buffer protected by a
//!   `Mutex<VecDeque>` (writes are short — pushing one sample —
//!   so contention is minimal even under heavy load).
//! - The plugin host calls `record(sample)` synchronously on
//!   every tool dispatch. If the buffer is full, one sample is
//!   dropped and counted: a non-billable one (policy-denied,
//!   quota-refused, replayed) — the arriving one, or the oldest
//!   buffered one — whenever there is one, else the oldest billable
//!   one. The two counts ride the next MetricsReport as
//!   `dropped_non_billable` and `dropped_overflow`.
//!
//!   DELIBERATE TRADEOFF: drop-with-counter, NOT back-pressure. The
//!   recorder sits on the gateway's dispatch hot path — blocking it to
//!   preserve a metrics sample would trade tenant-visible latency for
//!   billing precision. The exact drop COUNT always survives (the
//!   counter rides every report), so the CP knows precisely how many
//!   billable samples were lost and folds exactly that many into the
//!   ledger; a dropped refusal is never billed. Each flush ships the
//!   whole buffer, and a buffer four-fifths full flushes early (at
//!   most once per `EARLY_FLUSH_SPACING`), so a drop needs the Channel
//!   to be down or calls to outpace one full buffer per second — not a
//!   sustained rate above cap / interval.
//! - `flush_loop` is the async task spawned alongside the agent's
//!   Channel session. It wakes every flush interval, or early when the
//!   buffer fills, drains the buffer in `MetricsReport`s of up to
//!   `batch_cap` samples, and sends them via the agent's outbound mpsc.
//!
//! Privacy invariant: tool *names* + aggregate stats only. Tool
//! arguments and responses are NEVER captured here.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use mcpg_control_plane_core::proto::agent_message::Kind as AgentKind;
use mcpg_control_plane_core::proto::{
    AgentMessage, EventUsageSample, MetricsReport, ToolInvocationSample, ToolOutcome,
};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Default in-memory ring buffer size. A buffer four-fifths full ships
/// early, so this bounds memory and a burst, not the sustained call rate.
pub const DEFAULT_BUFFER_CAP: usize = 5_000;

/// The shortest time between the starts of two flushes when the second is
/// an early one. Bounds the report rate a runaway producer can cause at one
/// full buffer per interval of this length.
pub const EARLY_FLUSH_SPACING: Duration = Duration::from_secs(1);

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
    /// Whether a call with this outcome counts toward billing and quota:
    /// the same set as the control plane's
    /// `ToolOutcome::counts_toward_usage`.
    pub fn is_billable(self) -> bool {
        !matches!(
            self,
            Self::PolicyDenied | Self::QuotaExceeded | Self::IdempotentReplay
        )
    }

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
    buf: Mutex<Ring>,
    cap: usize,
    batch_cap: usize,
    /// Buffered samples at which the flush loop is woken before its tick.
    flush_early_at: usize,
    /// Wakes the flush loop early. A wake sent while the loop is busy is
    /// kept, so the loop flushes again as soon as it is done.
    flush_early: tokio::sync::Notify,
    /// Billable samples dropped since the last drain.
    dropped_overflow: AtomicU64,
    /// Non-billable samples dropped since the last drain.
    dropped_non_billable: AtomicU64,
    seq: AtomicU64,
    /// MCP Events deliveries and ingests since the last drain.
    events: Mutex<EventsRollup>,
}

/// MCP Events usage counted per (event type, mode) since `since`.
#[derive(Default)]
struct EventsRollup {
    since: Option<chrono::DateTime<chrono::Utc>>,
    counts: BTreeMap<(String, String), EventCounts>,
}

/// What MCP Events delivered or took in of one type in one mode: a delivery
/// mode for deliveries, a source kind for ingests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventCounts {
    /// First deliveries acknowledged.
    pub delivered: u64,
    /// Events given up.
    pub abandoned: u64,
    /// Occurrences taken into the event log.
    pub ingested: u64,
    /// Bytes of the delivered bodies, or of the ingested occurrences.
    pub bytes: u64,
}

impl EventCounts {
    fn add(&mut self, other: EventCounts) {
        self.delivered = self.delivered.saturating_add(other.delivered);
        self.abandoned = self.abandoned.saturating_add(other.abandoned);
        self.ingested = self.ingested.saturating_add(other.ingested);
        self.bytes = self.bytes.saturating_add(other.bytes);
    }
}

/// One MCP Events rollup row of a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventUsage {
    pub event_name: String,
    pub mode: String,
    pub counts: EventCounts,
    pub window_start: chrono::DateTime<chrono::Utc>,
    pub window_end: chrono::DateTime<chrono::Utc>,
}

/// The buffered samples, and how many of them are non-billable so a full
/// buffer knows without a scan whether it has one to give up.
struct Ring {
    samples: VecDeque<ToolCallSample>,
    non_billable: usize,
}

impl Ring {
    fn push_back(&mut self, sample: ToolCallSample) {
        self.non_billable += usize::from(!sample.outcome.is_billable());
        self.samples.push_back(sample);
    }

    fn push_front(&mut self, sample: ToolCallSample) {
        self.non_billable += usize::from(!sample.outcome.is_billable());
        self.samples.push_front(sample);
    }

    fn remove(&mut self, at: usize) -> Option<ToolCallSample> {
        let sample = self.samples.remove(at)?;
        self.non_billable = self
            .non_billable
            .saturating_sub(usize::from(!sample.outcome.is_billable()));
        Some(sample)
    }
}

/// Samples drained for one `MetricsReport`, with the drops counted since the
/// previous drain.
#[derive(Debug)]
pub struct Drained {
    pub samples: Vec<ToolCallSample>,
    /// Billable samples dropped on overflow; the CP bills them.
    pub dropped_overflow: u64,
    /// Non-billable samples dropped on overflow; never billed.
    pub dropped_non_billable: u64,
    pub seq: u64,
    /// MCP Events deliveries since the previous drain.
    pub events: Vec<EventUsage>,
}

impl Drained {
    /// Nothing to report: no samples, no drops and no event deliveries.
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
            && self.dropped_overflow == 0
            && self.dropped_non_billable == 0
            && self.events.is_empty()
    }
}

impl MetricsBuffer {
    pub fn new() -> Self {
        Self::with_caps(DEFAULT_BUFFER_CAP, DEFAULT_BATCH_CAP)
    }

    pub fn with_caps(cap: usize, batch_cap: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                buf: Mutex::new(Ring {
                    samples: VecDeque::with_capacity(cap),
                    non_billable: 0,
                }),
                cap,
                batch_cap,
                flush_early_at: (cap - cap / 5).max(1),
                flush_early: tokio::sync::Notify::new(),
                dropped_overflow: AtomicU64::new(0),
                dropped_non_billable: AtomicU64::new(0),
                seq: AtomicU64::new(0),
                events: Mutex::new(EventsRollup::default()),
            }),
        }
    }

    /// Count MCP Events usage of `event_name` in `mode` into the next
    /// report. Synchronous and fast.
    pub fn record_events(&self, event_name: &str, mode: &str, counts: EventCounts) {
        if counts == EventCounts::default() {
            return;
        }
        let mut events = self.inner.events.lock();
        events.since.get_or_insert_with(chrono::Utc::now);
        events
            .counts
            .entry((event_name.to_owned(), mode.to_owned()))
            .or_default()
            .add(counts);
    }

    fn count_drop(&self, outcome: SampleOutcome) {
        let counter = if outcome.is_billable() {
            &self.inner.dropped_overflow
        } else {
            &self.inner.dropped_non_billable
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one sample. A full buffer drops an arriving non-billable
    /// sample outright; an arriving billable one takes the place of the
    /// oldest non-billable sample, or of the oldest billable one when there
    /// is none. Every drop is counted by its billability. A buffer that
    /// reaches four-fifths of its cap wakes the flush loop. Synchronous +
    /// fast — safe to call from any dispatch path.
    pub fn record(&self, sample: ToolCallSample) {
        let mut ring = self.inner.buf.lock();
        let buffered = ring.samples.len();
        if buffered + 1 >= self.inner.flush_early_at {
            self.inner.flush_early.notify_one();
        }
        if buffered >= self.inner.cap {
            // A billable drop is billed from its count and a non-billable one
            // never is, so the buffer spends non-billable samples first. A
            // flood of refusals is dropped on arrival, without a scan.
            if !sample.outcome.is_billable() {
                self.count_drop(sample.outcome);
                return;
            }
            let victim = if ring.non_billable > 0 {
                ring.samples
                    .iter()
                    .position(|s| !s.outcome.is_billable())
                    .unwrap_or(0)
            } else {
                0
            };
            if let Some(dropped) = ring.remove(victim) {
                self.count_drop(dropped.outcome);
            }
        }
        ring.push_back(sample);
    }

    /// Drain up to `batch_cap` oldest samples and the drops counted since
    /// the previous drain, resetting both counters.
    pub fn drain(&self) -> Drained {
        let mut ring = self.inner.buf.lock();
        let n = ring.samples.len().min(self.inner.batch_cap);
        let samples: Vec<_> = ring.samples.drain(..n).collect();
        let drained_non_billable = samples.iter().filter(|s| !s.outcome.is_billable()).count();
        ring.non_billable = ring.non_billable.saturating_sub(drained_non_billable);
        let rollup = std::mem::take(&mut *self.inner.events.lock());
        let window_end = chrono::Utc::now();
        let window_start = rollup.since.unwrap_or(window_end);
        let events = rollup
            .counts
            .into_iter()
            .map(|((event_name, mode), counts)| EventUsage {
                event_name,
                mode,
                counts,
                window_start,
                window_end,
            })
            .collect();
        Drained {
            samples,
            dropped_overflow: self.inner.dropped_overflow.swap(0, Ordering::Relaxed),
            dropped_non_billable: self.inner.dropped_non_billable.swap(0, Ordering::Relaxed),
            seq: self.inner.seq.fetch_add(1, Ordering::Relaxed) + 1,
            events,
        }
    }

    /// Put a drained batch back at the front of the buffer, oldest first, and
    /// restore its dropped counts. Samples that no longer fit are counted as
    /// dropped, by billability, rather than discarded quietly — the ledger
    /// stays neutral to buffer overflow either way.
    fn requeue_front(&self, batch: Drained) {
        let mut ring = self.inner.buf.lock();
        // Reverse, because each push_front puts its sample ahead of the last.
        for sample in batch.samples.into_iter().rev() {
            if ring.samples.len() >= self.inner.cap {
                self.count_drop(sample.outcome);
            } else {
                ring.push_front(sample);
            }
        }
        self.inner
            .dropped_overflow
            .fetch_add(batch.dropped_overflow, Ordering::Relaxed);
        self.inner
            .dropped_non_billable
            .fetch_add(batch.dropped_non_billable, Ordering::Relaxed);
        let mut events = self.inner.events.lock();
        for usage in batch.events {
            let since = events.since.get_or_insert(usage.window_start);
            *since = (*since).min(usage.window_start);
            events
                .counts
                .entry((usage.event_name, usage.mode))
                .or_default()
                .add(usage.counts);
        }
    }

    /// Samples waiting for the next flush.
    fn buffered(&self) -> usize {
        self.inner.buf.lock().samples.len()
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
fn timestamp(at: chrono::DateTime<chrono::Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: at.timestamp(),
        nanos: at.timestamp_subsec_nanos() as i32,
    }
}

/// `None` when the batch is empty AND nothing was dropped (we
/// don't want to spam the CP with empty reports — but we DO send
/// when only drops were counted so the operator sees them).
pub fn batch_to_message(batch: &Drained) -> Option<AgentMessage> {
    if batch.is_empty() {
        return None;
    }
    let invocations: Vec<ToolInvocationSample> = batch
        .samples
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
            seq: batch.seq,
            invocations,
            dropped_overflow: batch.dropped_overflow,
            dropped_non_billable: batch.dropped_non_billable,
            events: batch
                .events
                .iter()
                .map(|usage| EventUsageSample {
                    event_name: usage.event_name.clone(),
                    mode: usage.mode.clone(),
                    delivered: usage.counts.delivered,
                    abandoned: usage.counts.abandoned,
                    ingested: usage.counts.ingested,
                    bytes: usage.counts.bytes,
                    window_start: Some(timestamp(usage.window_start)),
                    window_end: Some(timestamp(usage.window_end)),
                })
                .collect(),
        })),
    })
}

/// Returns an undelivered batch to the buffer unless disarmed.
///
/// Cancelling a future drops its locals, so this covers both halves of the
/// same problem: a send that fails, and a task aborted while awaiting one.
struct InFlight<'a> {
    buffer: &'a MetricsBuffer,
    batch: Option<Drained>,
}

impl InFlight<'_> {
    /// The batch is on its way; stop tracking it.
    fn disarm(&mut self) {
        self.batch = None;
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        let Some(batch) = self.batch.take().filter(|b| !b.is_empty()) else {
            return;
        };
        warn!(
            samples = batch.samples.len(),
            dropped = batch.dropped_overflow,
            dropped_non_billable = batch.dropped_non_billable,
            "metrics flush: batch undelivered; returning it to the buffer"
        );
        self.buffer.requeue_front(batch);
    }
}

/// Background loop: every `interval`, and early when the buffer is
/// four-fifths full, ship the whole buffer over `out_tx` in reports of up to
/// `batch_cap` samples. Stops when `out_tx` is closed (Channel reconnecting).
pub async fn flush_loop(
    buffer: MetricsBuffer,
    out_tx: mpsc::Sender<AgentMessage>,
    interval: Duration,
) {
    // A full buffer is this many batches. The bound keeps a producer that
    // outpaces the channel from holding one tick open forever; what it
    // leaves behind ships on the next tick.
    let batches_per_tick = buffer
        .inner
        .cap
        .div_ceil(buffer.inner.batch_cap.max(1))
        .max(1);
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await; // immediate
    'session: loop {
        let started = tokio::time::Instant::now();
        for _ in 0..batches_per_tick {
            let batch = buffer.drain();
            let count = batch.samples.len();
            let (dropped, dropped_non_billable, seq) = (
                batch.dropped_overflow,
                batch.dropped_non_billable,
                batch.seq,
            );
            // The batch is out of the buffer and lives only in this local. The
            // task is aborted on every Channel reconnect, and an abort drops
            // the future — and with it the batch — at the `send` below. The
            // guard hands it back instead, so a reconnect costs no billable
            // calls.
            let mut inflight = InFlight {
                buffer: &buffer,
                batch: Some(batch),
            };
            let msg = inflight.batch.as_ref().and_then(batch_to_message);
            if let Some(msg) = msg {
                if out_tx.send(msg).await.is_err() {
                    // Nothing was queued, so the batch is still owed. Leave
                    // the guard armed to return it and let the next session
                    // ship it.
                    debug!("metrics flush: outbound channel closed; stopping");
                    break 'session;
                }
                debug!(
                    count,
                    dropped, dropped_non_billable, seq, "metrics flush: shipped batch"
                );
            }
            inflight.disarm();
            if count < buffer.inner.batch_cap {
                break;
            }
        }
        tokio::select! {
            _ = ticker.tick() => {}
            () = buffer.inner.flush_early.notified() => {
                tokio::time::sleep_until(started + EARLY_FLUSH_SPACING).await;
            }
        }
    }
    match buffer.buffered() {
        0 => debug!("metrics flush: buffer empty at shutdown"),
        buffered => warn!(
            buffered,
            "metrics flush: shutdown with samples still in buffer"
        ),
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
        let batch = b.drain();
        let drained = &batch.samples;
        assert_eq!(drained.len(), 3);
        assert_eq!(batch.dropped_overflow, 0);
        assert_eq!(batch.seq, 1);
        // FIFO order preserved.
        assert_eq!(drained[0].duration, Duration::from_millis(10));
        assert_eq!(drained[2].duration, Duration::from_millis(12));
    }

    fn batch(samples: Vec<ToolCallSample>, dropped_overflow: u64) -> Drained {
        Drained {
            samples,
            dropped_overflow,
            dropped_non_billable: 0,
            seq: 1,
            events: Vec::new(),
        }
    }

    #[test]
    fn event_deliveries_roll_up_per_type_and_reach_the_report() {
        let buf = MetricsBuffer::with_caps(10, 10);
        let counts = |delivered, bytes| EventCounts {
            delivered,
            bytes,
            ..EventCounts::default()
        };
        buf.record_events("orders.created", "webhook", counts(2, 200));
        buf.record_events("orders.created", "webhook", counts(1, 50));
        buf.record_events("invoices.paid", "webhook", EventCounts::default());
        buf.record_events(
            "orders.created",
            "inbound",
            EventCounts {
                ingested: 4,
                bytes: 40,
                ..EventCounts::default()
            },
        );
        let drained = buf.drain();
        assert!(!drained.is_empty(), "event usage alone is worth a report");
        assert_eq!(drained.events.len(), 2, "a zero count adds no row");
        let webhook = drained
            .events
            .iter()
            .find(|usage| usage.mode == "webhook")
            .unwrap();
        assert_eq!(webhook.counts, counts(3, 250));
        let Some(AgentMessage {
            kind: Some(AgentKind::MetricsReport(report)),
        }) = batch_to_message(&drained)
        else {
            panic!("a metrics report");
        };
        let webhook = report.events.iter().find(|e| e.mode == "webhook").unwrap();
        assert_eq!(webhook.event_name, "orders.created");
        assert_eq!(webhook.delivered, 3);
        let inbound = report.events.iter().find(|e| e.mode == "inbound").unwrap();
        assert_eq!((inbound.ingested, inbound.delivered), (4, 0));
        assert!(buf.drain().events.is_empty(), "drained once");

        // A report that could not be sent comes back, counts and window.
        buf.record_events("orders.created", "webhook", counts(1, 10));
        let batch = buf.drain();
        buf.requeue_front(batch);
        buf.record_events("orders.created", "webhook", counts(1, 10));
        assert_eq!(buf.drain().events[0].counts, counts(2, 20));
    }

    fn outcomes(samples: &[ToolCallSample]) -> Vec<SampleOutcome> {
        samples.iter().map(|s| s.outcome).collect()
    }

    /// A dropped billable sample is billed through its count; a dropped
    /// refusal must not be. A buffer flooded with refusals — an exhausted
    /// tenant's client retrying — counts none of them as billable drops.
    #[test]
    fn overflow_of_refusals_counts_no_billable_drop() {
        let b = MetricsBuffer::with_caps(3, 10);
        for _ in 0..5 {
            b.record(sample(
                "p",
                "t",
                SampleOutcome::QuotaExceeded,
                Duration::from_millis(1),
            ));
        }
        let batch = b.drain();
        assert_eq!(batch.samples.len(), 3);
        assert_eq!(batch.dropped_overflow, 0, "no billable call was lost");
        assert_eq!(batch.dropped_non_billable, 2);
    }

    /// A full buffer gives up its non-billable samples before any billable
    /// one, and a refusal arriving at a buffer of billable samples is the one
    /// dropped.
    #[test]
    fn a_full_buffer_drops_non_billable_samples_first() {
        let b = MetricsBuffer::with_caps(3, 10);
        let rec = |outcome| b.record(sample("p", "t", outcome, Duration::from_millis(1)));
        rec(SampleOutcome::Ok);
        rec(SampleOutcome::PolicyDenied);
        rec(SampleOutcome::ServerError);
        // Full: the policy denial goes, not the older billable call.
        rec(SampleOutcome::Ok);
        // Full of billable calls: an arriving replay is itself dropped.
        rec(SampleOutcome::IdempotentReplay);
        let batch = b.drain();
        assert_eq!(
            outcomes(&batch.samples),
            [
                SampleOutcome::Ok,
                SampleOutcome::ServerError,
                SampleOutcome::Ok
            ]
        );
        assert_eq!(batch.dropped_overflow, 0);
        assert_eq!(batch.dropped_non_billable, 2);

        // Only billable samples left to give: the oldest one goes, and counts.
        rec(SampleOutcome::Ok);
        rec(SampleOutcome::ServerError);
        rec(SampleOutcome::QuotaExceeded);
        rec(SampleOutcome::ClientError);
        let batch = b.drain();
        assert_eq!(
            outcomes(&batch.samples),
            [
                SampleOutcome::Ok,
                SampleOutcome::ServerError,
                SampleOutcome::ClientError
            ]
        );
        assert_eq!(batch.dropped_overflow, 0);
        assert_eq!(batch.dropped_non_billable, 1);
        for outcome in [
            SampleOutcome::Ok,
            SampleOutcome::Ok,
            SampleOutcome::Ok,
            SampleOutcome::ClientError,
        ] {
            rec(outcome);
        }
        let batch = b.drain();
        assert_eq!(
            batch.dropped_overflow, 1,
            "the oldest billable call is counted"
        );
        assert_eq!(batch.dropped_non_billable, 0);
    }

    /// Billable exactly when the control plane counts the outcome toward
    /// usage: everything but policy denials, quota refusals and replays.
    #[test]
    fn billable_outcomes_are_the_ones_that_ran() {
        use SampleOutcome::*;
        for (outcome, billable) in [
            (Ok, true),
            (ClientError, true),
            (ServerError, true),
            (PolicyDenied, false),
            (QuotaExceeded, false),
            (IdempotentReplay, false),
        ] {
            assert_eq!(outcome.is_billable(), billable, "{outcome:?}");
        }
    }

    /// One tick ships the whole buffer, a report per `batch_cap` samples, so
    /// the sustained rate before any drop is cap / interval rather than
    /// batch_cap / interval.
    #[tokio::test]
    async fn one_flush_tick_ships_the_whole_buffer() {
        let buffer = MetricsBuffer::with_caps(5_000, 500);
        for i in 0..1_234 {
            buffer.record(sample(
                "p",
                &format!("t{i}"),
                SampleOutcome::Ok,
                Duration::from_millis(1),
            ));
        }
        let (tx, mut rx) = mpsc::channel(64);
        let handle = {
            let buffer = buffer.clone();
            tokio::spawn(async move { flush_loop(buffer, tx, Duration::from_secs(3_600)).await })
        };
        let mut sizes = Vec::new();
        while sizes.iter().sum::<usize>() < 1_234 {
            let msg = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("the first tick ships the rest of the buffer")
                .expect("flush loop running");
            match msg.kind {
                Some(AgentKind::MetricsReport(m)) => sizes.push(m.invocations.len()),
                _ => panic!("expected MetricsReport"),
            }
        }
        handle.abort();
        assert_eq!(sizes, [500, 500, 234]);
        assert_eq!(buffer.buffered(), 0);
    }

    /// A buffer past four-fifths of its cap ships long before its tick, so
    /// bursts that add up to more than cap / interval lose no row.
    #[tokio::test]
    async fn a_filling_buffer_ships_before_its_tick() {
        let buffer = MetricsBuffer::with_caps(100, 10);
        let (tx, mut rx) = mpsc::channel(1_024);
        let handle = {
            let buffer = buffer.clone();
            tokio::spawn(async move { flush_loop(buffer, tx, Duration::from_secs(3_600)).await })
        };
        let started = tokio::time::Instant::now();
        let (mut shipped, mut dropped) = (0usize, 0u64);
        for burst in 0..3 {
            for i in 0..90 {
                buffer.record(sample(
                    "p",
                    &format!("t{burst}-{i}"),
                    SampleOutcome::Ok,
                    Duration::from_millis(1),
                ));
            }
            while shipped < (burst + 1) * 90 {
                let msg = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                    .await
                    .expect("a buffer past its high-water mark ships before its tick")
                    .expect("flush loop running");
                let Some(AgentKind::MetricsReport(report)) = msg.kind else {
                    panic!("expected MetricsReport");
                };
                shipped += report.invocations.len();
                dropped += report.dropped_overflow + report.dropped_non_billable;
            }
        }
        handle.abort();
        assert_eq!(shipped, 270);
        assert_eq!(dropped, 0);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
    }

    /// Early flushes start at most once per `EARLY_FLUSH_SPACING`, however
    /// fast the buffer refills.
    #[tokio::test]
    async fn early_flushes_are_spaced() {
        let buffer = MetricsBuffer::with_caps(100, 100);
        let (tx, mut rx) = mpsc::channel(1_024);
        let handle = {
            let buffer = buffer.clone();
            tokio::spawn(async move { flush_loop(buffer, tx, Duration::from_secs(3_600)).await })
        };
        let mut arrivals = Vec::new();
        for burst in 0..4 {
            for i in 0..90 {
                buffer.record(sample(
                    "p",
                    &format!("t{burst}-{i}"),
                    SampleOutcome::Ok,
                    Duration::from_millis(1),
                ));
            }
            rx.recv().await.expect("flush loop running");
            arrivals.push(tokio::time::Instant::now());
        }
        handle.abort();
        // A round's report arrives a little after the round starts, and the
        // spacing is measured between starts.
        let slack = Duration::from_millis(100);
        for pair in arrivals.windows(2) {
            assert!(
                pair[1] - pair[0] + slack >= EARLY_FLUSH_SPACING,
                "{arrivals:?}"
            );
        }
    }

    /// A batch handed back after a failed send keeps its drop counts, and
    /// the samples that no longer fit are counted by their billability.
    #[test]
    fn a_requeued_batch_counts_what_no_longer_fits_by_billability() {
        let b = MetricsBuffer::with_caps(2, 10);
        let mut back = batch(
            vec![
                sample("p", "a", SampleOutcome::PolicyDenied, Duration::ZERO),
                sample("p", "b", SampleOutcome::Ok, Duration::ZERO),
                sample("p", "c", SampleOutcome::Ok, Duration::ZERO),
            ],
            4,
        );
        back.dropped_non_billable = 5;
        b.record(sample("p", "d", SampleOutcome::Ok, Duration::ZERO));
        b.requeue_front(back);
        let batch = b.drain();
        let names: Vec<_> = batch.samples.iter().map(|s| s.tool_name.as_str()).collect();
        assert_eq!(names, ["c", "d"]);
        assert_eq!(batch.dropped_overflow, 4 + 1);
        assert_eq!(batch.dropped_non_billable, 5 + 1);
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
        let batch = b.drain();
        let drained = &batch.samples;
        // Oldest 2 dropped; 3 newest remain.
        assert_eq!(drained.len(), 3);
        assert_eq!(batch.dropped_overflow, 2);
        assert_eq!(batch.dropped_non_billable, 0);
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
        let drained = b.drain().samples;
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
        assert_eq!(b.drain().dropped_overflow, 3);
        assert_eq!(b.drain().dropped_overflow, 0);
    }

    #[test]
    fn batch_to_message_skips_empty_no_drops() {
        let msg = batch_to_message(&batch(vec![], 0));
        assert!(msg.is_none());
    }

    #[test]
    fn batch_to_message_emits_when_only_drops() {
        let msg = batch_to_message(&batch(vec![], 5)).unwrap();
        match msg.kind {
            Some(AgentKind::MetricsReport(m)) => {
                assert!(m.invocations.is_empty());
                assert_eq!(m.dropped_overflow, 5);
                assert_eq!(m.dropped_non_billable, 0);
            }
            _ => panic!("expected MetricsReport"),
        }
        let mut refusals = batch(vec![], 0);
        refusals.dropped_non_billable = 7;
        match batch_to_message(&refusals).map(|m| m.kind) {
            Some(Some(AgentKind::MetricsReport(m))) => {
                assert_eq!(m.dropped_overflow, 0);
                assert_eq!(m.dropped_non_billable, 7);
            }
            _ => panic!("a report of non-billable drops alone is still sent"),
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

        let recovered = buffer.drain().samples;
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

        let recovered = buffer.drain().samples;
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
        let msg = batch_to_message(&batch(vec![s], 0)).unwrap();
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
        let msg = batch_to_message(&batch(vec![s], 0)).unwrap();
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
        let msg = batch_to_message(&batch(vec![s], 0)).unwrap();
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
