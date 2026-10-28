//! Coalesces rapid filesystem events into a single scan per file.
//!
//! Editors and installers touch a file many times in quick succession (create,
//! write, rename, chmod). Scanning on every event wastes work and can read a
//! half-written file. The debouncer records the latest event time per path and
//! only releases a path for scanning once it has been quiet for the debounce
//! window.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub struct Debouncer {
    window: Duration,
    pending: HashMap<PathBuf, Instant>,
}

impl Debouncer {
    pub fn new(window: Duration) -> Self {
        Debouncer { window, pending: HashMap::new() }
    }

    /// Records activity on `path` at `now`, resetting its quiet timer.
    pub fn note(&mut self, path: PathBuf, now: Instant) {
        self.pending.insert(path, now);
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Removes and returns every path that has been quiet for at least the
    /// debounce window as of `now`.
    pub fn take_due(&mut self, now: Instant) -> Vec<PathBuf> {
        let window = self.window;
        let due: Vec<PathBuf> = self
            .pending
            .iter()
            .filter(|(_, &t)| now.duration_since(t) >= window)
            .map(|(p, _)| p.clone())
            .collect();
        for p in &due {
            self.pending.remove(p);
        }
        due
    }

    /// How long until the next pending path becomes due (for sleeping).
    pub fn next_deadline(&self, now: Instant) -> Option<Duration> {
        self.pending
            .values()
            .map(|&t| self.window.saturating_sub(now.duration_since(t)))
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn releases_only_after_quiet_window() {
        let mut d = Debouncer::new(Duration::from_millis(500));
        let t0 = Instant::now();
        d.note(PathBuf::from("/a"), t0);
        // Still within the window: not due.
        assert!(d.take_due(t0 + Duration::from_millis(400)).is_empty());
        // A new event resets the timer.
        d.note(PathBuf::from("/a"), t0 + Duration::from_millis(400));
        assert!(d.take_due(t0 + Duration::from_millis(800)).is_empty());
        // Finally quiet long enough.
        let due = d.take_due(t0 + Duration::from_millis(901));
        assert_eq!(due, vec![PathBuf::from("/a")]);
        assert!(d.is_empty());
    }

    #[test]
    fn independent_paths() {
        let mut d = Debouncer::new(Duration::from_millis(100));
        let t0 = Instant::now();
        d.note(PathBuf::from("/a"), t0);
        d.note(PathBuf::from("/b"), t0 + Duration::from_millis(50));
        let due = d.take_due(t0 + Duration::from_millis(120));
        assert_eq!(due, vec![PathBuf::from("/a")]);
        let due = d.take_due(t0 + Duration::from_millis(160));
        assert_eq!(due, vec![PathBuf::from("/b")]);
    }

    #[test]
    fn next_deadline_reports_soonest() {
        let mut d = Debouncer::new(Duration::from_millis(1000));
        let t0 = Instant::now();
        assert_eq!(d.next_deadline(t0), None);
        d.note(PathBuf::from("/a"), t0);
        let dl = d.next_deadline(t0 + Duration::from_millis(600)).unwrap();
        assert!(dl <= Duration::from_millis(400) && dl > Duration::from_millis(300));
    }
}
