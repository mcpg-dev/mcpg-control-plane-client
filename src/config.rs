//! Plugin config schema. Loaded from `MCPGPluginSet` entry config
//! at boot.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlPlaneClientConfig {
    /// Where to dial the CP (`https://cp.acme.com`).
    pub endpoint: String,

    /// How to obtain the enrollment URL on first boot.
    pub enrollment: EnrollmentSource,

    /// Per-instance state dir (creds, LKG cache).
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,

    /// Heartbeat cadence.
    #[serde(default = "default_heartbeat", with = "humantime_serde")]
    pub heartbeat: Duration,

    /// Reconnect backoff.
    #[serde(default)]
    pub backoff: Backoff,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EnrollmentSource {
    /// Read from environment variable.
    Env { name: String },
    /// Read from a file (e.g. K8s Secret mount).
    File { path: PathBuf },
    /// Inline literal (for tests / local dev).
    Inline { url: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Backoff {
    #[serde(default = "default_backoff_initial", with = "humantime_serde")]
    pub initial: Duration,
    #[serde(default = "default_backoff_max", with = "humantime_serde")]
    pub max: Duration,
    #[serde(default = "default_backoff_jitter")]
    pub jitter: bool,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: default_backoff_initial(),
            max: default_backoff_max(),
            jitter: default_backoff_jitter(),
        }
    }
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/mcpg/cp-client")
}
fn default_heartbeat() -> Duration {
    Duration::from_secs(30)
}
fn default_backoff_initial() -> Duration {
    Duration::from_secs(1)
}
fn default_backoff_max() -> Duration {
    Duration::from_secs(60)
}
fn default_backoff_jitter() -> bool {
    true
}

mod humantime_serde {
    use super::*;
    use serde::{Deserializer, Serializer, de::Error};
    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{}s", d.as_secs()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let s = String::deserialize(d)?;
        humantime::parse_duration(&s).map_err(D::Error::custom)
    }
}
