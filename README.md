# mcpg-control-plane-client

> The gateway-side agent that attaches a running MCPG gateway to a Control Plane: register, heartbeat, ship telemetry, and apply pushed config.

This crate drives one side of the `mcpg.cp.v1` agent contract. Given an
enrollment URL it registers with the Control Plane, caches the credentials the
CP issues, opens a long-lived bidirectional gRPC channel, and then keeps it
alive: heartbeats, batched tool-call metrics and log lines outbound; config
bundles, quota status and credential rotations inbound, with jittered
exponential backoff across reconnects. It is a plain Rust library rather than a
loadable MCPG plugin — the gateway compiles it in behind a Cargo feature, and
tests drive it directly to stand up a CP-attached agent without booting a full
gateway. Everything the agent needs to keep serving through a Control Plane
outage is on disk before the outage starts.

## What's here
- `AgentRunner` — the lifecycle driver. `new(cfg)`, `with_config_applier(…)`,
  and `run()`; `subscribe()` yields a broadcast stream of `AgentEvent`
  (`Registered`, `ChannelConnected`, `ChannelDisconnected`, `HeartbeatSent`,
  `ConfigReceived`, `Error`); `shutdown_handle()` returns an `AgentShutdown`
  with `trigger()` and `finished()`; `metrics()` and `logs()` hand out the
  buffers the dispatch path writes into; `quota_status_handle()` and
  `payload_dek_handle()` expose `ArcSwap` handles the gateway's hot path reads
  without taking a lock.
- `ConfigApplier` — the host hook that applies a pushed `ConfigBundle` to the
  running process. Its `Result` drives a truthful `ConfigAck`: an `Err(reason)`
  tells the CP the host kept its previous config and why. With no applier wired,
  the agent caches the bundle and acks without applying.
- `AgentRunnerConfig` — `cp_endpoint`, `enrollment_url`, `instance_uid`,
  `version`, `state_dir`, `heartbeat_interval`, `backoff_initial`,
  `backoff_max`, and `bootstrap_ca_pem` for the very first connect, before the
  CP has issued the agent its own certificate.
- `AgentClient` and `ClientTlsMaterial` — the tonic client for `AgentControl`,
  with the instance JWT injected as `mcpg-instance-token` metadata on every call
  and CP-issued mTLS material applied when the endpoint is `https`.
- `ControlPlaneClientConfig` — the serde config shape: `endpoint`, an
  `enrollment` source of `Env { name }`, `File { path }` or `Inline { url }`,
  `state_dir` (default `/var/lib/mcpg/cp-client`), `heartbeat` (default 30s),
  and a `Backoff` block of `initial` (1s), `max` (60s) and `jitter` (true).
- `backoff::Backoff` — exponential backoff with `next_delay()` and `reset()`,
  doubling up to a capped exponent, clamped to `max`, and spread by a ±25%
  jitter factor so a fleet does not reconnect in lockstep.
- `LkgCache` / `LkgEntry` — the last-known-good config cache. A pushed bundle
  is written to disk before the applier runs, so a crash mid-apply still leaves
  the new config on disk, and it is preloaded at boot so the gateway serves
  traffic through a CP outage. Sealed on disk with AES-256-GCM under a
  key derived by HKDF-SHA256 from a node-stable secret: `/etc/machine-id` where
  it exists, otherwise 32 random bytes written once to `<state_dir>/.node-secret`
  with mode 600. The file is a version byte, a 12-byte nonce, then the
  ciphertext, so the sealing scheme can change without a schema rewrite.
- `MetricsBuffer`, `ToolCallSample` and `SampleOutcome` (`Ok`, `ClientError`,
  `ServerError`, `PolicyDenied`, `QuotaExceeded`, `IdempotentReplay`) — the
  per-call metrics lane: a bounded ring (`DEFAULT_BUFFER_CAP` 5,000) drained
  every `DEFAULT_FLUSH_INTERVAL` (30s) into reports of at most
  `DEFAULT_BATCH_CAP` (500) samples. Recording is synchronous on the dispatch
  hot path and never back-pressures it: on overflow the oldest sample is dropped
  and a counter rides the next report, so the CP knows exactly how many samples
  were lost. Tool names and aggregate statistics only — arguments and responses
  are never captured here, and error messages travel as BLAKE3 hashes via
  `MetricsBuffer::hash_error`.
- `LogBuffer`, `LogLineSample` and `LogLevel` — the same ring-and-flush shape for
  gateway log lines (`DEFAULT_LOG_BUFFER_CAP` 5,000, `DEFAULT_LOG_BATCH_CAP`
  500, `DEFAULT_LOG_FLUSH_INTERVAL` 45s, deliberately staggered against the
  co-ticking heartbeat and metrics cadences). Unlike metrics, a log line carries
  its rendered message, because these are the tenant's own gateway logs surfaced
  back to them.
- `DekHandle` / `DekError` — source-side payload encryption. When the CP issues
  a per-tenant data encryption key at registration, optionally captured
  request/response payloads are sealed with AES-256-GCM before they ever enter
  the metrics buffer, so the CP host never sees plaintext. Blobs are
  `nonce(12) || ciphertext` under a fixed AAD domain separator, and the key
  version is stamped on every blob. If encryption fails the bytes are dropped
  rather than shipped in the clear.
- `QuotaStatus` and `ConfigBundle`, re-exported from
  `mcpg-control-plane-core` so a host can name them without depending on that
  crate directly.

## Used by
- `apps/gateway`, behind its `cp-attached` Cargo feature (implied by
  `embedded-cp`) and wired from the `gateway.control_plane` config block, which
  supplies the CP URL, enrollment URL, instance uid, state directory, heartbeat
  interval and the payload-capture opt-in.
- `apps/control-plane/server`, as a development dependency, so its integration
  tests exercise registration, mTLS and the metrics lane against a real Control
  Plane rather than a mock.

## Build / test
```bash
cargo build -p mcpg-control-plane-client
cargo test  -p mcpg-control-plane-client
```

## Licence
Apache-2.0.

## See also
- [Cloud overview](https://mcpg.dev/docs/cloud/overview) — what attaching a gateway to a Control Plane buys.
- [Gateway configuration reference](https://mcpg.dev/docs/reference/configuration) — the `gateway.control_plane` block.
- `libs/control-plane/core` — the `mcpg.cp.v1` contract this crate speaks.
