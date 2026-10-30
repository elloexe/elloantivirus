//! Background scan worker. The UI thread must never block on a scan, so a scan
//! runs on its own thread and streams progress back over a channel. The UI
//! drains the channel each frame.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crossbeam_channel::{Receiver, Sender};
use ello_common::config::Config;
use ello_common::{paths, ScanOutcome, ScanStats};
use ello_engine::scanner;
use ello_quarantine::Quarantine;
use ello_scan::{collect_files, remediate, Remediated, Remediation};

/// Messages sent from the scan thread to the UI.
pub enum ScanMsg {
    /// Enumeration finished; `total` files will be scanned.
    Counted { total: usize },
    /// One file scanned. `infected` carries the outcome only when it is a hit.
    Progress {
        done: usize,
        infected: Option<ScanOutcome>,
    },
    /// Scan completed (or was cancelled); carries final stats and actions.
    Done {
        stats: ScanStats,
        actions: Vec<(PathBuf, Remediated)>,
        cancelled: bool,
    },
    /// Fatal error before/around scanning (e.g. engine load failed).
    Failed(String),
}

/// Handle the UI keeps for an in-flight scan.
pub struct ScanJob {
    pub rx: Receiver<ScanMsg>,
    cancel: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl ScanJob {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

impl Drop for ScanJob {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Spawns a scan over `roots`, returning a handle immediately.
pub fn start(roots: Vec<PathBuf>, recurse: bool, config: Config, action: Remediation) -> ScanJob {
    let (tx, rx) = crossbeam_channel::unbounded();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_worker = cancel.clone();
    let handle = std::thread::spawn(move || {
        run(roots, recurse, config, action, &tx, &cancel_worker);
    });
    ScanJob {
        rx,
        cancel,
        handle: Some(handle),
    }
}

fn run(
    roots: Vec<PathBuf>,
    recurse: bool,
    config: Config,
    action: Remediation,
    tx: &Sender<ScanMsg>,
    cancel: &AtomicBool,
) {
    let sig = paths::signatures_dir().join("latest.ellodb");
    let engine = match scanner::load_engine(&sig, &config.scan) {
        Ok(e) => e,
        Err(e) => {
            let _ = tx.send(ScanMsg::Failed(format!("loading signatures: {e}")));
            return;
        }
    };

    let files = collect_files(&roots, recurse);
    let _ = tx.send(ScanMsg::Counted { total: files.len() });

    let done = AtomicU64::new(0);
    let bytes = AtomicU64::new(0);
    let outcomes: Mutex<Vec<ScanOutcome>> = Mutex::new(Vec::with_capacity(files.len()));

    // Sequential scan: predictable progress and prompt, clean cancellation.
    // The per-file cost is dominated by I/O, so a worker thread keeps the UI
    // smooth without the added complexity of cancelling a parallel pool.
    for path in &files {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let outcome = engine.scan_file(path);
        if let Ok(meta) = std::fs::metadata(path) {
            bytes.fetch_add(meta.len(), Ordering::Relaxed);
        }
        let n = done.fetch_add(1, Ordering::Relaxed) + 1;
        let infected = outcome.is_infected().then(|| outcome.clone());
        outcomes.lock().unwrap().push(outcome);
        let _ = tx.send(ScanMsg::Progress {
            done: n as usize,
            infected,
        });
    }

    let cancelled = cancel.load(Ordering::Relaxed);
    let outcomes = outcomes.into_inner().unwrap();

    // Remediate confirmed detections (suspicious-only are left as reports).
    let quarantine = Mutex::new(if action == Remediation::Quarantine {
        Quarantine::open(&paths::quarantine_dir()).ok()
    } else {
        None
    });
    let actions = remediate(&outcomes, action, &quarantine);

    let mut stats = ScanStats {
        bytes: bytes.load(Ordering::Relaxed),
        ..Default::default()
    };
    for o in &outcomes {
        stats.record(o);
    }
    let _ = tx.send(ScanMsg::Done {
        stats,
        actions,
        cancelled,
    });
}
