//! The licence the control plane delivers to this instance.
//!
//! The CP pushes a `LicenseUpdate` when the Channel opens and whenever the
//! org's licence changes. The agent keeps the latest one on disk, so a restart
//! while the CP is unreachable still has the licence it last delivered, and
//! hands each delivery to the host's [`LicenseApplier`]. The host verifies the
//! token itself; this module never trusts it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One delivery: the org's licence (empty when the org holds none) and the
/// slug of the org the CP enrolled this instance into.
///
/// The proof is kept with the nonce and the instance uid it binds, so a
/// restart can check it again: the host counts a cached licence it proves
/// only for a bounded time after the proof was signed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseDelivery {
    pub license_jwt: String,
    pub org_slug: String,
    /// The CP reports that its refresh of this licence is failing.
    #[serde(default)]
    pub refresh_failing: bool,
    /// The delivery proof the CP sent with it (`LicenseUpdate.delivery_proof`).
    #[serde(default)]
    pub delivery_proof: String,
    /// The nonce this agent sent when it opened the Channel the delivery came
    /// down.
    #[serde(default)]
    pub channel_nonce: String,
    /// The instance uid that Channel was authenticated as.
    #[serde(default)]
    pub instance_uid: String,
}

/// Host hook that receives every licence delivery.
#[async_trait::async_trait]
pub trait LicenseApplier: Send + Sync {
    async fn apply_license(&self, delivery: &LicenseDelivery);

    /// The CP refused this process's Channel because another Channel of the
    /// instance holds its slot, and the agent tries again in `retry_in`, once
    /// the CP frees the slot unless that Channel speaks again. No licence
    /// arrives before then.
    async fn channel_slot_held(&self, _retry_in: std::time::Duration) {}
}

const CACHE_FILE: &str = "platform-license.json";

/// Where the latest delivery is kept: `<state_dir>/platform-license.json`.
pub fn cache_path(state_dir: &Path) -> PathBuf {
    state_dir.join(CACHE_FILE)
}

/// The latest delivery kept under `state_dir`, if any is readable.
pub fn load_cached(state_dir: &Path) -> Option<LicenseDelivery> {
    let bytes = std::fs::read(cache_path(state_dir)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Keep `delivery` as the latest one. Written to a temporary file and renamed,
/// so a crash mid-write leaves the previous delivery in place.
pub fn save_cached(state_dir: &Path, delivery: &LicenseDelivery) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let path = cache_path(state_dir);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(delivery)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delivery_round_trips_and_replaces_the_previous_one() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load_cached(dir.path()), None);
        let first = LicenseDelivery {
            license_jwt: "a.b.c".into(),
            org_slug: "acme".into(),
            refresh_failing: true,
            ..Default::default()
        };
        save_cached(dir.path(), &first).unwrap();
        assert_eq!(load_cached(dir.path()), Some(first));
        let none = LicenseDelivery {
            license_jwt: String::new(),
            org_slug: "acme".into(),
            ..Default::default()
        };
        save_cached(dir.path(), &none).unwrap();
        assert_eq!(load_cached(dir.path()), Some(none));
        assert!(!cache_path(dir.path()).with_extension("json.tmp").exists());
    }

    /// The proof is kept with what it binds, so a restart can check it again;
    /// a cache written before it was kept reads back with none.
    #[test]
    fn the_proof_is_kept_with_its_nonce_and_instance() {
        let dir = tempfile::tempdir().unwrap();
        let proven = LicenseDelivery {
            license_jwt: "a.b.c".into(),
            org_slug: "acme".into(),
            refresh_failing: false,
            delivery_proof: "proof.of.delivery".into(),
            channel_nonce: "nonce-of-this-channel".into(),
            instance_uid: "gw-1".into(),
        };
        save_cached(dir.path(), &proven).unwrap();
        assert_eq!(load_cached(dir.path()), Some(proven));

        std::fs::write(
            cache_path(dir.path()),
            br#"{"license_jwt":"a.b.c","org_slug":"acme","refresh_failing":false}"#,
        )
        .unwrap();
        let older = load_cached(dir.path()).unwrap();
        assert_eq!(older.license_jwt, "a.b.c");
        assert!(older.delivery_proof.is_empty() && older.instance_uid.is_empty());
    }

    #[test]
    fn an_unreadable_cache_is_no_delivery() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(cache_path(dir.path()), b"not json").unwrap();
        assert_eq!(load_cached(dir.path()), None);
    }
}
