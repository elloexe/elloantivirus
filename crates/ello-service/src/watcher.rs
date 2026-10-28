//! The real-time protection loop: watch configured folders, debounce events,
//! scan changed files, and remediate detections.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::{after, select, Receiver};
use ello_common::config::{Config, DefaultAction};
use ello_common::{paths, Confidence, ScanOutcome};
use ello_engine::scanner::{self, Engine};
use ello_quarantine::Quarantine;
use notify::{Event, RecursiveMode, Watcher};

use crate::debounce::Debouncer;

/// Outcome of handling one changed file (surfaced for logging/tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handled {
    Clean,
    Skipped,
    Detected { threat: String, action: String },
}

/// Decides and applies remediation for a single scan outcome. Suspicious-only
/// detections are logged, never auto-removed.
pub fn handle_outcome(
    outcome: &ScanOutcome,
    action: DefaultAction,
    quarantine: &mut Option<Quarantine>,
) -> Handled {
    let Some(worst) = outcome.worst() else {
        return if outcome.error.is_some() {
            Handled::Skipped
        } else {
            Handled::Clean
        };
    };
    if worst.confidence < Confidence::Malicious || action == DefaultAction::Report {
        tracing::warn!(path = %outcome.path.display(), threat = %worst.name, "detection (reported)");
        return Handled::Detected {
            threat: worst.name.clone(),
            action: "reported".into(),
        };
    }
    let applied = match action {
        DefaultAction::Report => "reported".to_string(),
        DefaultAction::Delete => match std::fs::remove_file(&outcome.path) {
            Ok(()) => "deleted".into(),
            Err(e) => format!("delete failed: {e}"),
        },
        DefaultAction::Quarantine => match quarantine.as_mut() {
            Some(q) => match q.quarantine_file(&outcome.path, &worst.name) {
                Ok(e) => format!("quarantined ({})", e.id),
                Err(e) => format!("quarantine failed: {e}"),
            },
            None => "quarantine unavailable".into(),
        },
    };
    tracing::warn!(path = %outcome.path.display(), threat = %worst.name, action = %applied, "real-time detection");
    Handled::Detected {
        threat: worst.name.clone(),
        action: applied,
    }
}

/// Shared state for the running protection loop.
pub struct Protection {
    engine: Arc<Engine>,
    action: DefaultAction,
    quarantine: Option<Quarantine>,
}

impl Protection {
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let sig = paths::signatures_dir().join("latest.ellodb");
        let engine = scanner::load_engine(&sig, &config.scan)?;
        let quarantine = if config.realtime.action == DefaultAction::Quarantine {
            Some(Quarantine::open(&paths::quarantine_dir())?)
        } else {
            None
        };
        Ok(Protection {
            engine: Arc::new(engine),
            action: config.realtime.action,
            quarantine,
        })
    }

    /// Scans one path and remediates. Exposed for testing the pipeline without
    /// real filesystem events.
    pub fn handle_path(&mut self, path: &Path) -> Handled {
        if !path.is_file() {
            return Handled::Skipped;
        }
        let outcome = self.engine.scan_file(path);
        handle_outcome(&outcome, self.action, &mut self.quarantine)
    }
}

/// Runs the protection loop until `shutdown` fires. `watch_paths` are the
/// directories (or files) to monitor recursively.
pub fn run(
    mut protection: Protection,
    watch_paths: &[PathBuf],
    debounce: Duration,
    shutdown: Receiver<()>,
) -> anyhow::Result<()> {
    let (tx, rx) = crossbeam_channel::unbounded::<notify::Result<Event>>();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })?;

    let mut watching = 0;
    for p in watch_paths {
        if p.exists() {
            match watcher.watch(p, RecursiveMode::Recursive) {
                Ok(()) => {
                    watching += 1;
                    tracing::info!(path = %p.display(), "watching");
                }
                Err(e) => tracing::warn!(path = %p.display(), error = %e, "cannot watch path"),
            }
        } else {
            tracing::warn!(path = %p.display(), "watch path does not exist; skipping");
        }
    }
    if watching == 0 {
        anyhow::bail!("no watchable paths configured");
    }

    let mut debouncer = Debouncer::new(debounce);
    tracing::info!("real-time protection active");

    loop {
        // Sleep only as long as the soonest pending file needs, so an idle
        // watcher does no work and a busy one scans promptly. When nothing is
        // pending, wake occasionally to stay responsive to shutdown.
        let wake = if debouncer.is_empty() {
            Duration::from_secs(1)
        } else {
            debouncer.next_deadline(Instant::now()).unwrap_or_default()
        };
        select! {
            recv(shutdown) -> _ => {
                tracing::info!("shutdown requested");
                return Ok(());
            }
            recv(rx) -> msg => {
                if let Ok(Ok(event)) = msg {
                    if is_interesting(&event) {
                        let now = Instant::now();
                        for path in event.paths {
                            debouncer.note(path, now);
                        }
                    }
                }
            }
            recv(after(wake)) -> _ => {}
        }
        for path in debouncer.take_due(Instant::now()) {
            protection.handle_path(&path);
        }
    }
}

/// We only care about events that can introduce or modify file content.
fn is_interesting(event: &Event) -> bool {
    use notify::EventKind;
    matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Any
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ello_common::config::ScanConfig;
    use ello_engine::scanner::EICAR;
    use ello_engine::sigdb::SignatureDb;

    fn protection(action: DefaultAction, vault: Option<&Path>) -> Protection {
        let hex = scanner::eicar_sha256_hex();
        let db = SignatureDb::parse(&format!("@version 1\nH {hex} EICAR-Test-File\n")).unwrap();
        Protection {
            engine: Arc::new(Engine::new(db, &ScanConfig::default())),
            action,
            quarantine: vault.map(|v| Quarantine::open(v).unwrap()),
        }
    }

    #[test]
    fn clean_file_handled_clean() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("ok.txt");
        std::fs::write(&f, b"hello").unwrap();
        let mut p = protection(DefaultAction::Report, None);
        assert_eq!(p.handle_path(&f), Handled::Clean);
    }

    #[test]
    fn malicious_file_quarantined() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("eicar.com");
        std::fs::write(&f, EICAR).unwrap();
        let mut p = protection(DefaultAction::Quarantine, Some(&dir.path().join("vault")));
        match p.handle_path(&f) {
            Handled::Detected { threat, action } => {
                assert_eq!(threat, "EICAR-Test-File");
                assert!(action.starts_with("quarantined"), "{action}");
            }
            other => panic!("expected detection, got {other:?}"),
        }
        assert!(!f.exists(), "file should have been quarantined");
    }

    #[test]
    fn malicious_file_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("eicar.com");
        std::fs::write(&f, EICAR).unwrap();
        let mut p = protection(DefaultAction::Delete, None);
        assert!(matches!(p.handle_path(&f), Handled::Detected { .. }));
        assert!(!f.exists());
    }

    #[test]
    fn report_mode_leaves_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("eicar.com");
        std::fs::write(&f, EICAR).unwrap();
        let mut p = protection(DefaultAction::Report, None);
        assert!(matches!(p.handle_path(&f), Handled::Detected { .. }));
        assert!(f.exists(), "report mode must not remove the file");
    }

    #[test]
    fn missing_path_skipped() {
        let mut p = protection(DefaultAction::Report, None);
        assert_eq!(
            p.handle_path(Path::new("/nonexistent/xyz")),
            Handled::Skipped
        );
    }
}
