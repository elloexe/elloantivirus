//! Standard filesystem layout. On Windows the data root is
//! `%ProgramData%\ElloAntivirus`; elsewhere it falls back to the user's local
//! data dir so the tools are testable off-Windows.

use std::path::PathBuf;

/// Root for all persistent state. Overridable with `ELLO_DATA_DIR` (used by
/// tests and portable installs).
pub fn data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("ELLO_DATA_DIR") {
        return PathBuf::from(dir);
    }
    #[cfg(windows)]
    {
        if let Some(pd) = std::env::var_os("ProgramData") {
            return PathBuf::from(pd).join("ElloAntivirus");
        }
    }
    dirs::data_local_dir()
        .unwrap_or_else(|| std::env::temp_dir())
        .join("ElloAntivirus")
}

pub fn signatures_dir() -> PathBuf {
    data_dir().join("signatures")
}

/// Directory holding the trusted update-signing public keys (`*.pub`).
pub fn keys_dir() -> PathBuf {
    data_dir().join("keys")
}

pub fn quarantine_dir() -> PathBuf {
    data_dir().join("quarantine")
}

pub fn logs_dir() -> PathBuf {
    data_dir().join("logs")
}

pub fn config_file() -> PathBuf {
    data_dir().join("config.toml")
}

/// Creates the full directory tree, returning the data root.
pub fn ensure_layout() -> std::io::Result<PathBuf> {
    for d in [signatures_dir(), keys_dir(), quarantine_dir(), logs_dir()] {
        std::fs::create_dir_all(d)?;
    }
    Ok(data_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_override_wins() {
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("ELLO_DATA_DIR", tmp.path());
        assert_eq!(data_dir(), tmp.path());
        assert_eq!(quarantine_dir(), tmp.path().join("quarantine"));
        ensure_layout().unwrap();
        assert!(signatures_dir().is_dir());
        std::env::remove_var("ELLO_DATA_DIR");
    }
}
