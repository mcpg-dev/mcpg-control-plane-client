//! `dev.mcpg.control_plane_client` — gateway-side plugin that
//! connects an MCPG instance to a Control Plane.
//!
//! Lifecycle: read enrollment URL → POST to CP's Register
//! endpoint → cache mTLS cert + JWT → open long-lived gRPC
//! Channel → heartbeat + apply config updates.
//!
//! This crate is consumed two ways:
//! - As an MCPG plugin (loaded into a running gateway).
//! - As a standalone Rust library (e.g. behind `mcpg --enroll <URL>`)
//!   to run a CP-attached agent, useful for the Tier 0 wedge UX +
//!   integration tests.

pub mod agent;
pub mod backoff;
pub mod client;
pub mod config;
pub mod lkg;
pub mod logs;
pub mod metrics;
pub mod payload_dek;

pub use agent::{AgentEvent, AgentRunner, AgentRunnerConfig, AgentShutdown, ConfigApplier};
pub use client::AgentClient;
pub use config::ControlPlaneClientConfig;
pub use lkg::{LkgCache, LkgEntry};
pub use logs::{LogBuffer, LogLevel, LogLineSample};
pub use metrics::{MetricsBuffer, SampleOutcome, ToolCallSample};
pub use payload_dek::{DekError, DekHandle};

/// Re-exported so gateway / consumers can refer to the
/// CP's QuotaStatus type without depending on
/// `mcpg-control-plane-core` directly.
pub use mcpg_control_plane_core::proto::QuotaStatus;

/// Re-exported so a host implementing [`ConfigApplier`] can name the bundle
/// type without depending on `mcpg-control-plane-core` directly.
pub use mcpg_control_plane_core::proto::ConfigBundle;
