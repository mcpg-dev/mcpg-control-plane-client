//! Source-side payload encryption (gateway side).
//!
//! At Register the CP issues a per-tenant 32-byte Data Encryption
//! Key (`RegisterResponse.payload_dek`) and a monotonic
//! `payload_dek_version`. The gateway uses the DEK to encrypt
//! tool-call request/response payloads BEFORE buffering them in
//! `MetricsBuffer`, so the CP host never sees plaintext.
//!
//! Key handling:
//! - Loaded from `RegisterResponse` and refreshed on every
//!   `CredentialRotation` push (best-effort; if the new push is
//!   missed the agent's reconnect path falls back to Register).
//! - Held lock-free behind `Arc<ArcSwap<Option<DekHandle>>>` so
//!   the dispatch hot path reads it without taking a lock.
//! - Persisted in `agent-creds.json` (chmod-600) base64-encoded
//!   so a restart doesn't lose source-side encryption capability.
//!
//! Wire format (per ciphertext blob):
//!   `nonce(12) || aes-256-gcm(plaintext, AAD)`
//!   AAD = b"mcpg-payload-source-v1" — domain separator pinning
//!   this scheme so a leaked DEK can't be repurposed against a
//!   different gateway encryption context.
//!
//! Backward compat: when the CP returns an empty `payload_dek`
//! (no master key configured, or older CP), `DekHandle::from_proto`
//! returns `None` and the gateway falls through to legacy
//! plaintext capture (CP encrypts at ingest as before).

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::RngCore;

/// AAD domain separator. Bumped only when the framing changes.
const AAD: &[u8] = b"mcpg-payload-source-v1";

/// Per-tenant DEK + the version stamped on every encrypted blob.
/// Cheap to clone (32 bytes + a u32). Stored behind `ArcSwap` on
/// the runner so reads on the hot path are lock-free.
#[derive(Clone, Debug)]
pub struct DekHandle {
    raw: [u8; 32],
    version: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum DekError {
    #[error("payload_dek must be 32 bytes, got {0}")]
    BadKeyLen(usize),
    #[error("payload_dek_version must be non-zero")]
    ZeroVersion,
    #[error("aes-gcm encrypt: {0}")]
    Encrypt(String),
}

impl DekHandle {
    /// Build from `RegisterResponse` / `CredentialRotation` fields.
    /// Returns `Ok(None)` when the CP returned an empty DEK
    /// (legacy / no master key configured) — caller falls through
    /// to the plaintext capture path.
    pub fn from_proto(raw: &[u8], version: u32) -> Result<Option<Self>, DekError> {
        if raw.is_empty() {
            return Ok(None);
        }
        if raw.len() != 32 {
            return Err(DekError::BadKeyLen(raw.len()));
        }
        if version == 0 {
            return Err(DekError::ZeroVersion);
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(raw);
        Ok(Some(Self { raw: buf, version }))
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    /// Encrypt a payload with a fresh 96-bit nonce. Output is
    /// `nonce || ciphertext+tag` ready for the wire.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, DekError> {
        let cipher =
            Aes256Gcm::new_from_slice(&self.raw).map_err(|e| DekError::Encrypt(e.to_string()))?;
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad: AAD,
                },
            )
            .map_err(|e| DekError::Encrypt(e.to_string()))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Tests-only: decrypt back. Production code on the CP side
    /// uses its own copy of the DEK + the `mcpg-payload-source-v1`
    /// AAD; this helper exists so unit tests can round-trip.
    #[doc(hidden)]
    pub fn decrypt_for_test(&self, blob: &[u8]) -> Result<Vec<u8>, DekError> {
        if blob.len() < 12 {
            return Err(DekError::Encrypt("blob shorter than nonce".into()));
        }
        let cipher =
            Aes256Gcm::new_from_slice(&self.raw).map_err(|e| DekError::Encrypt(e.to_string()))?;
        let nonce = Nonce::from_slice(&blob[..12]);
        cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload {
                    msg: &blob[12..],
                    aad: AAD,
                },
            )
            .map_err(|e| DekError::Encrypt(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_dek() -> Vec<u8> {
        let mut k = vec![0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn from_proto_empty_returns_none() {
        let got = DekHandle::from_proto(&[], 0).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn from_proto_rejects_short_key() {
        let err = DekHandle::from_proto(&[1, 2, 3], 1).unwrap_err();
        assert!(matches!(err, DekError::BadKeyLen(3)));
    }

    #[test]
    fn from_proto_rejects_zero_version_with_key_present() {
        let err = DekHandle::from_proto(&fake_dek(), 0).unwrap_err();
        assert!(matches!(err, DekError::ZeroVersion));
    }

    #[test]
    fn round_trip_encrypts_and_decrypts() {
        let dek = DekHandle::from_proto(&fake_dek(), 7).unwrap().unwrap();
        let pt = b"hello payload, 12345";
        let blob = dek.encrypt(pt).unwrap();
        // nonce(12) || ciphertext+tag(16+pt.len)
        assert_eq!(blob.len(), 12 + 16 + pt.len());
        let back = dek.decrypt_for_test(&blob).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn fresh_nonce_per_encrypt() {
        let dek = DekHandle::from_proto(&fake_dek(), 7).unwrap().unwrap();
        let a = dek.encrypt(b"same plaintext").unwrap();
        let b = dek.encrypt(b"same plaintext").unwrap();
        // Nonce-misuse resistance: distinct nonces ⇒ distinct
        // ciphertexts even for identical plaintext.
        assert_ne!(a, b);
        assert_ne!(&a[..12], &b[..12]);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let dek = DekHandle::from_proto(&fake_dek(), 7).unwrap().unwrap();
        let mut blob = dek.encrypt(b"sensitive").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let err = dek.decrypt_for_test(&blob).unwrap_err();
        assert!(matches!(err, DekError::Encrypt(_)));
    }

    #[test]
    fn aad_separation_blocks_cross_context_decrypt() {
        let dek = DekHandle::from_proto(&fake_dek(), 7).unwrap().unwrap();
        let pt = b"payload";
        let blob = dek.encrypt(pt).unwrap();
        // Manually decrypt with a different AAD — must fail.
        let cipher = Aes256Gcm::new_from_slice(&dek.raw).unwrap();
        let nonce = Nonce::from_slice(&blob[..12]);
        let bad = cipher.decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: &blob[12..],
                aad: b"different-context",
            },
        );
        assert!(bad.is_err(), "AAD must be authenticated");
    }

    #[test]
    fn version_is_carried() {
        let dek = DekHandle::from_proto(&fake_dek(), 42).unwrap().unwrap();
        assert_eq!(dek.version(), 42);
    }
}
