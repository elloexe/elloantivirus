//! Signed signature-database updates.
//!
//! An update file is the plain-text `.ellodb` content. Its detached signature
//! is an Ed25519 signature over the exact bytes of that file, produced by
//! `ello-sigtool`. The engine ships with one or more trusted public keys; an
//! update is accepted only if its signature verifies against a trusted key and
//! its `@version` is newer than what is installed. This prevents an attacker
//! (or a corrupted mirror) from feeding the scanner forged or rolled-back
//! signatures.

pub use ed25519_dalek::VerifyingKey;
use ed25519_dalek::{Signature, Verifier};

use crate::sigdb::SignatureDb;

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("no trusted signing key accepted the update signature")]
    BadSignature,
    #[error("malformed public key: {0}")]
    BadKey(String),
    #[error("malformed signature: expected 64 bytes, got {0}")]
    BadSignatureLen(usize),
    #[error("update rejected: version {offered} is not newer than installed {installed}")]
    NotNewer { offered: u64, installed: u64 },
    #[error(transparent)]
    Parse(#[from] crate::sigdb::SigDbError),
}

/// Parses a 32-byte Ed25519 public key from raw or hex bytes.
pub fn parse_public_key(bytes: &[u8]) -> Result<VerifyingKey, UpdateError> {
    let raw: Vec<u8> = if bytes.len() == 64 {
        hex::decode(bytes).map_err(|e| UpdateError::BadKey(e.to_string()))?
    } else {
        bytes.to_vec()
    };
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| UpdateError::BadKey(format!("expected 32 bytes, got {}", raw.len())))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| UpdateError::BadKey(e.to_string()))
}

/// Verifies `signature` over `content` against any of the `trusted_keys`.
pub fn verify(
    content: &[u8],
    signature: &[u8],
    trusted_keys: &[VerifyingKey],
) -> Result<(), UpdateError> {
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| UpdateError::BadSignatureLen(signature.len()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    if trusted_keys.iter().any(|k| k.verify(content, &sig).is_ok()) {
        Ok(())
    } else {
        Err(UpdateError::BadSignature)
    }
}

/// Verifies and loads a signed update, enforcing monotonic versioning.
///
/// Returns the parsed database on success. `installed_version` is the version
/// currently in use (0 if none).
pub fn accept_update(
    content: &[u8],
    signature: &[u8],
    trusted_keys: &[VerifyingKey],
    installed_version: u64,
) -> Result<SignatureDb, UpdateError> {
    verify(content, signature, trusted_keys)?;
    let text = String::from_utf8_lossy(content);
    let db = SignatureDb::parse(&text)?;
    if db.version() <= installed_version {
        return Err(UpdateError::NotNewer {
            offered: db.version(),
            installed: installed_version,
        });
    }
    Ok(db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn keypair() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn accepts_valid_signed_update() {
        let sk = keypair();
        let content = format!("@version 100\nH {} Test\n", "ab".repeat(32));
        let content = content.as_bytes();
        let sig = sk.sign(content).to_bytes();
        let keys = [sk.verifying_key()];
        let db = accept_update(content, &sig, &keys, 50).unwrap();
        assert_eq!(db.version(), 100);
        assert_eq!(db.hash_count(), 1);
    }

    #[test]
    fn rejects_tampered_content() {
        let sk = keypair();
        let content = b"@version 100\n";
        let sig = sk.sign(content).to_bytes();
        let tampered = b"@version 101\n";
        assert!(matches!(
            accept_update(tampered, &sig, &[sk.verifying_key()], 0),
            Err(UpdateError::BadSignature)
        ));
    }

    #[test]
    fn rejects_wrong_key() {
        let sk = keypair();
        let other = keypair();
        let content = b"@version 5\n";
        let sig = sk.sign(content).to_bytes();
        assert!(matches!(
            verify(content, &sig, &[other.verifying_key()]),
            Err(UpdateError::BadSignature)
        ));
    }

    #[test]
    fn rejects_rollback() {
        let sk = keypair();
        let content = b"@version 10\n";
        let sig = sk.sign(content).to_bytes();
        assert!(matches!(
            accept_update(content, &sig, &[sk.verifying_key()], 10),
            Err(UpdateError::NotNewer {
                offered: 10,
                installed: 10
            })
        ));
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let sk = keypair();
        let vk = sk.verifying_key();
        let hex = hex::encode(vk.to_bytes());
        let parsed = parse_public_key(hex.as_bytes()).unwrap();
        assert_eq!(parsed.to_bytes(), vk.to_bytes());
        let raw = parse_public_key(&vk.to_bytes()).unwrap();
        assert_eq!(raw.to_bytes(), vk.to_bytes());
    }
}
