//! Parallel filesystem walking and detection handling.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use ello_common::config::DefaultAction;
use ello_common::{Confidence, ScanOutcome, ScanStats};
use ello_engine::scanner::Engine;
use ello_quarantine::Quarantine;
use rayon::prelude::*;
use walkdir::WalkDir;

/// What to do with confirmed-malicious files found during the scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remediation {
    ReportOnly,
    Quarantine,
    Delete,
}

impl From<DefaultAction> for Remediation {
    fn from(a: DefaultAction) -> Self {
        match a {
            DefaultAction::Report => Remediation::ReportOnly,
            DefaultAction::Quarantine => Remediation::Quarantine,
            DefaultAction::Delete => Remediation::Delete,
        }
    }
}

/// Records what remediation actually happened to an infected file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Remediated {
    Reported,
    Quarantined { id: String },
    Deleted,
    Failed { error: String },
}

/// Collects every regular file under `roots`, following the directory tree but
/// not symlinks (to avoid loops and escaping the intended scope).
pub fn collect_files(roots: &[PathBuf], recurse: bool) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for root in roots {
        if root.is_file() {
            files.push(root.clone());
            continue;
        }
        let walker = WalkDir::new(root).follow_links(false);
        let walker = if recurse { walker } else { walker.max_depth(1) };
        for entry in walker.into_iter().filter_map(Result::ok) {
            if entry.file_type().is_file() {
                files.push(entry.into_path());
            }
        }
    }
    files
}

/// Scans `files` in parallel, invoking `on_result` as each completes (for live
/// progress). Returns all outcomes plus aggregate stats.
pub fn scan_files(
    engine: &Engine,
    files: &[PathBuf],
    on_result: impl Fn(&ScanOutcome) + Sync,
) -> (Vec<ScanOutcome>, ScanStats) {
    let bytes = AtomicU64::new(0);
    let outcomes: Vec<ScanOutcome> = files
        .par_iter()
        .map(|path| {
            let outcome = engine.scan_file(path);
            if let Ok(meta) = std::fs::metadata(path) {
                bytes.fetch_add(meta.len(), Ordering::Relaxed);
            }
            on_result(&outcome);
            outcome
        })
        .collect();
    let mut stats = ScanStats {
        bytes: bytes.load(Ordering::Relaxed),
        ..Default::default()
    };
    for o in &outcomes {
        stats.record(o);
    }
    (outcomes, stats)
}

/// Applies remediation to every infected outcome. Suspicious-only detections
/// are always reported (never auto-deleted). Returns the actions taken, keyed
/// by path.
pub fn remediate(
    outcomes: &[ScanOutcome],
    action: Remediation,
    quarantine: &Mutex<Option<Quarantine>>,
) -> Vec<(PathBuf, Remediated)> {
    let mut results = Vec::new();
    for outcome in outcomes.iter().filter(|o| o.is_infected()) {
        let worst = outcome.worst().expect("infected has a detection");
        // Only act automatically on malicious/known verdicts.
        let act = action != Remediation::ReportOnly && worst.confidence >= Confidence::Malicious;
        let done = if !act {
            Remediated::Reported
        } else {
            match action {
                Remediation::ReportOnly => Remediated::Reported,
                Remediation::Delete => match std::fs::remove_file(&outcome.path) {
                    Ok(()) => Remediated::Deleted,
                    Err(e) => Remediated::Failed {
                        error: e.to_string(),
                    },
                },
                Remediation::Quarantine => {
                    let mut guard = quarantine.lock().unwrap();
                    match guard.as_mut() {
                        Some(q) => match q.quarantine_file(&outcome.path, &worst.name) {
                            Ok(entry) => Remediated::Quarantined { id: entry.id },
                            Err(e) => Remediated::Failed {
                                error: e.to_string(),
                            },
                        },
                        None => Remediated::Failed {
                            error: "quarantine unavailable".into(),
                        },
                    }
                }
            }
        };
        results.push((outcome.path.clone(), done));
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use ello_engine::scanner::{Engine, EICAR};
    use ello_engine::sigdb::SignatureDb;

    fn eicar_engine() -> Engine {
        let hex = ello_engine::scanner::eicar_sha256_hex();
        Engine::with_db(
            SignatureDb::parse(&format!("@version 1\nH {hex} EICAR-Test-File\n")).unwrap(),
        )
    }

    #[test]
    fn collect_and_scan_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("clean.txt"), b"hello").unwrap();
        std::fs::write(dir.path().join("bad.com"), EICAR).unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("alsoclean.txt"), b"ok").unwrap();

        let files = collect_files(&[dir.path().to_path_buf()], true);
        assert_eq!(files.len(), 3);
        let (outcomes, stats) = scan_files(&eicar_engine(), &files, |_| {});
        assert_eq!(stats.scanned, 3);
        assert_eq!(stats.infected, 1);
        assert_eq!(outcomes.iter().filter(|o| o.is_infected()).count(), 1);
    }

    #[test]
    fn non_recursive_skips_subdirs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("top.txt"), b"x").unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("deep.txt"), b"y").unwrap();
        assert_eq!(collect_files(&[dir.path().to_path_buf()], false).len(), 1);
    }

    #[test]
    fn remediate_quarantines_malicious() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("evil.com");
        std::fs::write(&bad, EICAR).unwrap();
        let (outcomes, _) = scan_files(&eicar_engine(), std::slice::from_ref(&bad), |_| {});
        let q = Quarantine::open(&dir.path().join("vault")).unwrap();
        let qm = Mutex::new(Some(q));
        let actions = remediate(&outcomes, Remediation::Quarantine, &qm);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0].1, Remediated::Quarantined { .. }));
        assert!(
            !bad.exists(),
            "quarantined file should be removed from disk"
        );
    }

    #[test]
    fn report_only_leaves_files() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("evil.com");
        std::fs::write(&bad, EICAR).unwrap();
        let (outcomes, _) = scan_files(&eicar_engine(), std::slice::from_ref(&bad), |_| {});
        let actions = remediate(&outcomes, Remediation::ReportOnly, &Mutex::new(None));
        assert_eq!(actions[0].1, Remediated::Reported);
        assert!(bad.exists());
    }
}
