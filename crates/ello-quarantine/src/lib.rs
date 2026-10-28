//! Encrypted quarantine vault.
//!
//! When the engine confirms a threat, the file is moved here rather than left
//! in place or deleted outright. Quarantined files are encrypted with
//! ChaCha20-Poly1305 under a per-vault key so they cannot execute, be opened by
//! other tools, or be re-detected by a scan of the vault, while remaining
//! fully restorable. A JSON index records the original location and threat so
//! items can be listed, restored, or purged.
//!
//! The vault key is stored beside the index. This protects against accidental
//! execution and casual inspection; it is not a defence against an attacker who
//! already has administrative read access to the vault directory.

use std::fs;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"ELLOQ1\0\0";

#[derive(Debug, thiserror::Error)]
pub enum QuarantineError {
    #[error("io error on {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("crypto failure (data corrupt or wrong key)")]
    Crypto,
    #[error("vault file is corrupt: {0}")]
    Corrupt(String),
    #[error("no quarantined item with id {0}")]
    NotFound(String),
    #[error("serializing index: {0}")]
    Index(#[from] serde_json::Error),
    #[error("restore target {0} already exists")]
    RestoreExists(PathBuf),
}

fn io(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> QuarantineError {
    let path = path.into();
    move |source| QuarantineError::Io { path, source }
}

/// Metadata recorded for each quarantined object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub threat: String,
    pub sha256: String,
    pub size: u64,
    pub quarantined_at: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Index {
    entries: Vec<QuarantineEntry>,
}

pub struct Quarantine {
    dir: PathBuf,
    cipher: ChaCha20Poly1305,
    index: Index,
}

impl Quarantine {
    /// Opens (or initializes) the vault at `dir`, creating a random key on
    /// first use.
    pub fn open(dir: &Path) -> Result<Self, QuarantineError> {
        fs::create_dir_all(dir).map_err(io(dir))?;
        let key_path = dir.join("vault.key");
        let key = match fs::read(&key_path) {
            Ok(k) if k.len() == 32 => {
                let arr: [u8; 32] = k.try_into().unwrap();
                arr
            }
            _ => {
                let mut k = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
                write_private(&key_path, &k)?;
                k
            }
        };
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let index_path = dir.join("index.json");
        let index = match fs::read(&index_path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| QuarantineError::Corrupt(e.to_string()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Index::default(),
            Err(e) => return Err(io(&index_path)(e)),
        };
        Ok(Quarantine { dir: dir.to_path_buf(), cipher, index })
    }

    pub fn entries(&self) -> &[QuarantineEntry] {
        &self.index.entries
    }

    fn save_index(&self) -> Result<(), QuarantineError> {
        let path = self.dir.join("index.json");
        let bytes = serde_json::to_vec_pretty(&self.index)?;
        write_private(&path, &bytes)
    }

    fn blob_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.q"))
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, QuarantineError> {
        let mut nonce = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let ct = self.cipher.encrypt(Nonce::from_slice(&nonce), plaintext).map_err(|_| QuarantineError::Crypto)?;
        let mut out = Vec::with_capacity(MAGIC.len() + 12 + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>, QuarantineError> {
        if blob.len() < MAGIC.len() + 12 || &blob[..MAGIC.len()] != MAGIC {
            return Err(QuarantineError::Corrupt("bad vault blob header".into()));
        }
        let nonce = &blob[MAGIC.len()..MAGIC.len() + 12];
        let ct = &blob[MAGIC.len() + 12..];
        self.cipher.decrypt(Nonce::from_slice(nonce), ct).map_err(|_| QuarantineError::Crypto)
    }

    /// Reads `src`, stores an encrypted copy, and (on success) removes the
    /// original. Returns the new entry.
    pub fn quarantine_file(&mut self, src: &Path, threat: &str) -> Result<QuarantineEntry, QuarantineError> {
        let data = fs::read(src).map_err(io(src))?;
        let entry = self.store_bytes(src, threat, &data)?;
        fs::remove_file(src).map_err(io(src))?;
        Ok(entry)
    }

    /// Stores `data` as a quarantined object attributed to `original_path`,
    /// without touching the filesystem source (used for data already in memory
    /// or for testing).
    pub fn store_bytes(&mut self, original_path: &Path, threat: &str, data: &[u8]) -> Result<QuarantineEntry, QuarantineError> {
        let sha256 = hex::encode::<[u8; 32]>(Sha256::digest(data).into());
        let id = format!("{}-{}", now_compact(), &sha256[..16]);
        let blob = self.encrypt(data)?;
        let path = self.blob_path(&id);
        write_private(&path, &blob)?;
        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: original_path.to_path_buf(),
            threat: threat.to_string(),
            sha256,
            size: data.len() as u64,
            quarantined_at: now_rfc3339(),
        };
        self.index.entries.push(entry.clone());
        self.save_index()?;
        Ok(entry)
    }

    /// Decrypts a quarantined object back into memory.
    pub fn read_item(&self, id: &str) -> Result<Vec<u8>, QuarantineError> {
        if !self.index.entries.iter().any(|e| e.id == id) {
            return Err(QuarantineError::NotFound(id.into()));
        }
        let blob = fs::read(self.blob_path(id)).map_err(io(self.blob_path(id)))?;
        self.decrypt(&blob)
    }

    /// Restores an item to `dest` (or its original path when `dest` is `None`)
    /// and removes it from the vault. Refuses to overwrite an existing file.
    pub fn restore(&mut self, id: &str, dest: Option<&Path>) -> Result<PathBuf, QuarantineError> {
        let entry = self.index.entries.iter().find(|e| e.id == id).ok_or_else(|| QuarantineError::NotFound(id.into()))?.clone();
        let target = dest.map(Path::to_path_buf).unwrap_or(entry.original_path.clone());
        if target.exists() {
            return Err(QuarantineError::RestoreExists(target));
        }
        let data = self.read_item(id)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(io(parent))?;
        }
        fs::write(&target, &data).map_err(io(&target))?;
        self.remove(id)?;
        Ok(target)
    }

    /// Permanently deletes a quarantined object.
    pub fn remove(&mut self, id: &str) -> Result<(), QuarantineError> {
        let before = self.index.entries.len();
        self.index.entries.retain(|e| e.id != id);
        if self.index.entries.len() == before {
            return Err(QuarantineError::NotFound(id.into()));
        }
        let _ = fs::remove_file(self.blob_path(id));
        self.save_index()
    }

    pub fn clear(&mut self) -> Result<usize, QuarantineError> {
        let ids: Vec<String> = self.index.entries.iter().map(|e| e.id.clone()).collect();
        let n = ids.len();
        for id in ids {
            let _ = fs::remove_file(self.blob_path(&id));
        }
        self.index.entries.clear();
        self.save_index()?;
        Ok(n)
    }
}

/// Writes a file with owner-only permissions where the platform supports it.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), QuarantineError> {
    fs::write(path, bytes).map_err(io(path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn now_compact() -> String {
    chrono::Utc::now().format("%Y%m%d%H%M%S%3f").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> (tempfile::TempDir, Quarantine) {
        let dir = tempfile::tempdir().unwrap();
        let q = Quarantine::open(dir.path()).unwrap();
        (dir, q)
    }

    #[test]
    fn store_encrypts_and_reads_back() {
        let (dir, mut q) = vault();
        let e = q.store_bytes(Path::new("/tmp/evil.exe"), "Win32.Test", b"malware-bytes").unwrap();
        // The stored blob must not contain the plaintext.
        let blob = fs::read(dir.path().join(format!("{}.q", e.id))).unwrap();
        assert!(!blob.windows(13).any(|w| w == b"malware-bytes"));
        assert_eq!(q.read_item(&e.id).unwrap(), b"malware-bytes");
    }

    #[test]
    fn quarantine_removes_original_and_restore_brings_it_back() {
        let (dir, mut q) = vault();
        let src = dir.path().join("sample.bin");
        fs::write(&src, b"payload").unwrap();
        let e = q.quarantine_file(&src, "Test.Threat").unwrap();
        assert!(!src.exists(), "original should be gone");
        assert_eq!(q.entries().len(), 1);
        let restored = q.restore(&e.id, None).unwrap();
        assert_eq!(restored, src);
        assert_eq!(fs::read(&src).unwrap(), b"payload");
        assert_eq!(q.entries().len(), 0);
    }

    #[test]
    fn restore_refuses_to_overwrite() {
        let (dir, mut q) = vault();
        let e = q.store_bytes(Path::new("x"), "t", b"data").unwrap();
        let dest = dir.path().join("occupied");
        fs::write(&dest, b"existing").unwrap();
        assert!(matches!(q.restore(&e.id, Some(&dest)), Err(QuarantineError::RestoreExists(_))));
    }

    #[test]
    fn index_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let id = {
            let mut q = Quarantine::open(dir.path()).unwrap();
            q.store_bytes(Path::new("a"), "t", b"abc").unwrap().id
        };
        let q2 = Quarantine::open(dir.path()).unwrap();
        assert_eq!(q2.entries().len(), 1);
        assert_eq!(q2.read_item(&id).unwrap(), b"abc");
    }

    #[test]
    fn remove_and_clear() {
        let (_dir, mut q) = vault();
        let a = q.store_bytes(Path::new("a"), "t", b"1").unwrap();
        q.store_bytes(Path::new("b"), "t", b"2").unwrap();
        q.remove(&a.id).unwrap();
        assert_eq!(q.entries().len(), 1);
        assert!(matches!(q.remove(&a.id), Err(QuarantineError::NotFound(_))));
        assert_eq!(q.clear().unwrap(), 1);
        assert_eq!(q.entries().len(), 0);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let id = {
            let mut q = Quarantine::open(dir.path()).unwrap();
            q.store_bytes(Path::new("a"), "t", b"secret").unwrap().id
        };
        // Replace the key, simulating a mismatched vault.
        write_private(&dir.path().join("vault.key"), &[7u8; 32]).unwrap();
        let q = Quarantine::open(dir.path()).unwrap();
        assert!(matches!(q.read_item(&id), Err(QuarantineError::Crypto)));
    }
}
