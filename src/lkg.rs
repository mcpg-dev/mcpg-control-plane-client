//! Last-known-good config cache.
//!
//! When the CP pushes a `ConfigBundle`, the agent persists it to
//! disk *after* successfully applying it. On boot, the agent
//! preloads the LKG so it can serve traffic during a CP outage.
//!
//! ## At-rest encryption
//!
//! The bundle on disk is sealed with AES-256-GCM. The key is
//! derived from a node-stable secret via HKDF-SHA256:
//!
//! - On Linux, `/etc/machine-id` (the standard systemd-issued
//!   identifier) is used directly. The file is world-readable but
//!   not the same across machines.
//! - On other platforms (or when `/etc/machine-id` is missing) we
//!   fall back to `<state_dir>/.node-secret`: 32 random bytes
//!   generated on first run and chmod-600.
//!
//! HKDF salt and `info` strings pin the derivation to the LKG use
//! case so the same node-secret can't accidentally be reused for
//! a different purpose later.
//!
//! File layout:
//! ```text
//! ┌────────┬───────────────┬──────────────────────────────┐
//! │ ver=1  │ nonce (12 B)  │ AES-GCM(JSON envelope) + tag │
//! └────────┴───────────────┴──────────────────────────────┘
//! ```
//! The JSON envelope inside is the same `LkgEntry` shape — that
//! lets us swap algorithms later without rewriting the schema.

use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use mcpg_control_plane_core::proto::ConfigBundle;
use prost::Message;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::warn;

const FILE_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const HKDF_SALT: &[u8] = b"mcpg-lkg-cache-v1";
const HKDF_INFO: &[u8] = b"aes-256-gcm:lkg-bundle";
const NODE_SECRET_FILE: &str = ".node-secret";
const NODE_SECRET_LEN: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LkgEntry {
    pub config_hash: String,
    /// Protobuf-encoded `ConfigBundle` bytes. Stable across
    /// minor proto changes (additive fields ignored on read).
    #[serde(with = "base64_bytes")]
    pub bundle_proto: Vec<u8>,
    pub written_at: chrono::DateTime<chrono::Utc>,
}

pub struct LkgCache {
    path: PathBuf,
    state_dir: PathBuf,
}

impl LkgCache {
    pub fn new(path: PathBuf) -> Self {
        let state_dir = path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        Self { path, state_dir }
    }

    /// Default location: `<state_dir>/lkg-config.bin`.
    /// (Renamed from the legacy `.json` to make the on-disk
    /// encryption visible.)
    pub fn in_state_dir(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join("lkg-config.bin"),
            state_dir: state_dir.to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> anyhow::Result<Option<LkgEntry>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&self.path)?;
        let plain = decrypt(&bytes, &self.state_dir)?;
        let entry: LkgEntry = serde_json::from_slice(&plain)?;
        Ok(Some(entry))
    }

    /// Convenience: load + decode the protobuf payload.
    pub fn load_bundle(&self) -> anyhow::Result<Option<(String, ConfigBundle)>> {
        let Some(entry) = self.load()? else {
            return Ok(None);
        };
        let bundle = ConfigBundle::decode(entry.bundle_proto.as_slice())?;
        Ok(Some((entry.config_hash, bundle)))
    }

    pub fn save(&self, hash: &str, bundle: &ConfigBundle) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut buf = Vec::with_capacity(bundle.encoded_len());
        bundle.encode(&mut buf)?;
        let entry = LkgEntry {
            config_hash: hash.to_owned(),
            bundle_proto: buf,
            written_at: chrono::Utc::now(),
        };
        let json = serde_json::to_vec(&entry)?;
        let sealed = encrypt(&json, &self.state_dir)?;

        // Atomic write: write to temp file, fsync, rename.
        let tmp = self.path.with_extension("bin.tmp");
        std::fs::write(&tmp, &sealed)?;
        std::fs::rename(&tmp, &self.path)?;

        // chmod 600 best-effort.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

fn derive_key(state_dir: &Path) -> anyhow::Result<Key<Aes256Gcm>> {
    let secret = node_secret(state_dir)?;
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &secret);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_INFO, &mut okm)
        .map_err(|e| anyhow::anyhow!("hkdf expand: {e}"))?;
    Ok(*Key::<Aes256Gcm>::from_slice(&okm))
}

fn node_secret(state_dir: &Path) -> anyhow::Result<Vec<u8>> {
    if let Ok(s) = std::fs::read_to_string("/etc/machine-id") {
        let s = s.trim();
        if !s.is_empty() {
            return Ok(s.as_bytes().to_vec());
        }
    }
    // Fallback: a 32-byte random secret persisted next to the LKG.
    let p = state_dir.join(NODE_SECRET_FILE);
    if p.exists() {
        let bytes = std::fs::read(&p)?;
        if bytes.len() == NODE_SECRET_LEN {
            return Ok(bytes);
        }
        warn!("node-secret has unexpected length, regenerating");
    }
    std::fs::create_dir_all(state_dir)?;
    let mut bytes = [0u8; NODE_SECRET_LEN];
    OsRng.fill_bytes(&mut bytes);
    std::fs::write(&p, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(bytes.to_vec())
}

fn encrypt(plaintext: &[u8], state_dir: &Path) -> anyhow::Result<Vec<u8>> {
    let key = derive_key(state_dir)?;
    let cipher = Aes256Gcm::new(&key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("aes-gcm encrypt: {e}"))?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(FILE_VERSION);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(sealed: &[u8], state_dir: &Path) -> anyhow::Result<Vec<u8>> {
    if sealed.is_empty() {
        anyhow::bail!("LKG file is empty");
    }
    let ver = sealed[0];
    if ver != FILE_VERSION {
        anyhow::bail!("unsupported LKG file version: {ver}");
    }
    if sealed.len() < 1 + NONCE_LEN {
        anyhow::bail!("LKG file truncated");
    }
    let nonce = Nonce::from_slice(&sealed[1..1 + NONCE_LEN]);
    let ct = &sealed[1 + NONCE_LEN..];
    let key = derive_key(state_dir)?;
    let cipher = Aes256Gcm::new(&key);
    cipher
        .decrypt(nonce, ct)
        .map_err(|e| anyhow::anyhow!("aes-gcm decrypt (corrupt or wrong key): {e}"))
}

mod base64_bytes {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpg_control_plane_core::proto::PluginSet;

    fn sample_bundle() -> ConfigBundle {
        ConfigBundle {
            schema_version: 1,
            config_toml: b"foo = 1".to_vec(),
            plugin_set: Some(PluginSet {
                id: "ps-1".into(),
                content_hash: "abc".into(),
                entries: vec![],
                capability_grants: Default::default(),
            }),
            revocation_list: None,
            license_jwt: String::new(),
        }
    }

    #[test]
    fn round_trip_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let cache = LkgCache::in_state_dir(dir.path());
        let bundle = sample_bundle();
        cache.save("hash-xyz", &bundle).unwrap();

        let (h, loaded) = cache.load_bundle().unwrap().unwrap();
        assert_eq!(h, "hash-xyz");
        assert_eq!(loaded.config_toml, bundle.config_toml);
        assert_eq!(loaded.plugin_set.unwrap().id, "ps-1");
    }

    #[test]
    fn missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let cache = LkgCache::in_state_dir(dir.path());
        assert!(cache.load_bundle().unwrap().is_none());
    }

    #[test]
    fn ciphertext_does_not_leak_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let cache = LkgCache::in_state_dir(dir.path());
        let bundle = ConfigBundle {
            schema_version: 1,
            config_toml: b"VERY_DISTINCTIVE_MARKER".to_vec(),
            plugin_set: None,
            revocation_list: None,
            license_jwt: String::new(),
        };
        cache.save("h", &bundle).unwrap();
        let raw = std::fs::read(cache.path()).unwrap();
        assert_eq!(raw[0], FILE_VERSION);
        assert!(raw.len() > 1 + NONCE_LEN);
        // Plaintext marker must not appear anywhere on disk.
        let needle = b"VERY_DISTINCTIVE_MARKER";
        assert!(
            raw.windows(needle.len()).all(|w| w != needle),
            "plaintext leaked into encrypted LKG file"
        );
    }

    #[test]
    fn tamper_detection_rejects_modified_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let cache = LkgCache::in_state_dir(dir.path());
        cache.save("h", &sample_bundle()).unwrap();
        let mut raw = std::fs::read(cache.path()).unwrap();
        // Flip a bit in the ciphertext region.
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        std::fs::write(cache.path(), &raw).unwrap();
        assert!(cache.load_bundle().is_err(), "tamper should fail decrypt");
    }
}
