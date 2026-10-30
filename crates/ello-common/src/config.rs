//! User-facing configuration, persisted as TOML in the data directory.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    Off,
    Low,
    #[default]
    Normal,
    High,
}

/// Default action for a confirmed malicious object during automated scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultAction {
    Report,
    #[default]
    Quarantine,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub heuristic_sensitivity: Sensitivity,
    /// Skip files larger than this many bytes (0 = no limit).
    pub max_file_size: u64,
    /// Maximum nesting depth for archives/containers.
    pub max_archive_depth: u32,
    /// Abort an archive once decompressed output exceeds this ratio of input.
    pub max_compression_ratio: u64,
    /// Cap on total decompressed bytes per top-level archive.
    pub max_archive_output: u64,
    /// File extensions never scanned (lower-case, no dot).
    pub skip_extensions: Vec<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            heuristic_sensitivity: Sensitivity::default(),
            max_file_size: 512 * 1024 * 1024,
            max_archive_depth: 8,
            max_compression_ratio: 200,
            max_archive_output: 2 * 1024 * 1024 * 1024,
            skip_extensions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RealtimeConfig {
    pub enabled: bool,
    /// Directories watched for changes.
    pub watch_paths: Vec<PathBuf>,
    pub action: DefaultAction,
    /// Debounce window (ms) before scanning a changed file.
    pub debounce_ms: u64,
}

impl Default for RealtimeConfig {
    fn default() -> Self {
        RealtimeConfig {
            enabled: false,
            watch_paths: default_watch_paths(),
            action: DefaultAction::Quarantine,
            debounce_ms: 750,
        }
    }
}

fn default_watch_paths() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let mut v = Vec::new();
        if let Some(up) = std::env::var_os("USERPROFILE") {
            let up = PathBuf::from(up);
            v.push(up.join("Downloads"));
            v.push(up.join("Desktop"));
            v.push(up.join("Documents"));
        }
        if let Some(tmp) = std::env::var_os("TEMP") {
            v.push(PathBuf::from(tmp));
        }
        v
    }
    #[cfg(not(windows))]
    {
        dirs::download_dir().into_iter().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateConfig {
    /// Base URL serving `latest.ellodb` and `latest.ellodb.sig`.
    pub url: String,
    pub auto_update: bool,
    pub interval_hours: u64,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        UpdateConfig {
            url: "https://updates.example.invalid/ello".into(),
            auto_update: false,
            interval_hours: 6,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub scan: ScanConfig,
    pub realtime: RealtimeConfig,
    pub update: UpdateConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing {path}: {source}")]
    Parse {
        path: PathBuf,
        // Boxed: toml's error type is large, which would otherwise bloat every
        // `Result<_, ConfigError>` (clippy::result_large_err).
        source: Box<toml::de::Error>,
    },
    #[error("serializing config: {0}")]
    Serialize(Box<toml::ser::Error>),
}

impl From<toml::ser::Error> for ConfigError {
    fn from(e: toml::ser::Error) -> Self {
        ConfigError::Serialize(Box::new(e))
    }
}

impl Config {
    /// Loads config from `path`, returning defaults if the file is absent.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str(&text).map_err(|source| ConfigError::Parse {
                path: path.into(),
                source: Box::new(source),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(source) => Err(ConfigError::Io {
                path: path.into(),
                source,
            }),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let text = toml::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ConfigError::Io {
                path: parent.into(),
                source,
            })?;
        }
        std::fs::write(path, text).map_err(|source| ConfigError::Io {
            path: path.into(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_roundtrip_through_toml() {
        let c = Config::default();
        let text = toml::to_string_pretty(&c).unwrap();
        assert_eq!(toml::from_str::<Config>(&text).unwrap(), c);
    }

    #[test]
    fn partial_config_fills_defaults() {
        let c: Config = toml::from_str("[scan]\nheuristic_sensitivity = \"high\"\n").unwrap();
        assert_eq!(c.scan.heuristic_sensitivity, Sensitivity::High);
        assert_eq!(
            c.scan.max_archive_depth,
            ScanConfig::default().max_archive_depth
        );
        assert_eq!(c.update.interval_hours, 6);
    }

    #[test]
    fn load_missing_is_default() {
        let p = std::env::temp_dir().join("ello-nonexistent-xyz.toml");
        let _ = std::fs::remove_file(&p);
        assert_eq!(Config::load(&p).unwrap(), Config::default());
    }

    #[test]
    fn save_then_load() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("config.toml");
        let mut c = Config::default();
        c.realtime.enabled = true;
        c.save(&p).unwrap();
        assert_eq!(Config::load(&p).unwrap(), c);
    }
}
