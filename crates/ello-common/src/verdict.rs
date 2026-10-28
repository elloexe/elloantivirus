//! The result types produced by a scan.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// How a detection was identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionKind {
    /// Exact SHA-256 match against the signature database.
    Hash,
    /// Byte/string pattern rule.
    Pattern,
    /// Score-based heuristic.
    Heuristic,
}

/// Confidence attached to a detection, which drives default handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Heuristics crossed the "suspicious" but not the "malicious" threshold.
    Suspicious,
    /// Pattern rule or heuristics crossed the "malicious" threshold.
    Malicious,
    /// Exact known-bad hash: as certain as the engine gets.
    Known,
}

/// A single threat found in a scanned object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    /// Threat name, e.g. `Ransom.Win32.Generic` or `Heuristic.Downloader`.
    pub name: String,
    pub kind: DetectionKind,
    pub confidence: Confidence,
    /// Human-readable reasons (heuristic findings, matched rule, etc.).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    /// For objects inside archives: the path within the container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inner_path: Option<String>,
}

impl Detection {
    pub fn display_location(&self) -> String {
        match &self.inner_path {
            Some(inner) => format!("\u{2192} {inner}"),
            None => String::new(),
        }
    }
}

/// The outcome of scanning one filesystem object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanOutcome {
    pub path: PathBuf,
    /// Empty when the object is clean.
    pub detections: Vec<Detection>,
    /// Set when the object could not be fully scanned (unreadable, too large,
    /// malformed archive). Not itself a detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ScanOutcome {
    pub fn clean(path: PathBuf) -> Self {
        ScanOutcome { path, detections: Vec::new(), error: None }
    }

    pub fn is_infected(&self) -> bool {
        !self.detections.is_empty()
    }

    /// The most severe detection, used to pick a single action for the object.
    pub fn worst(&self) -> Option<&Detection> {
        self.detections.iter().max_by_key(|d| d.confidence)
    }
}

/// What was (or should be) done about an infected object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Reported only.
    Report,
    /// Moved to encrypted quarantine.
    Quarantine,
    /// Deleted outright.
    Delete,
}

/// Aggregate counters for a scan session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanStats {
    pub scanned: u64,
    pub infected: u64,
    pub suspicious: u64,
    pub errors: u64,
    pub skipped: u64,
    pub bytes: u64,
}

impl ScanStats {
    pub fn record(&mut self, outcome: &ScanOutcome) {
        self.scanned += 1;
        if let Some(e) = &outcome.error {
            if e != "skipped" {
                self.errors += 1;
            } else {
                self.skipped += 1;
            }
        }
        match outcome.worst().map(|d| d.confidence) {
            Some(Confidence::Suspicious) => self.suspicious += 1,
            Some(_) => self.infected += 1,
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(c: Confidence) -> Detection {
        Detection { name: "X".into(), kind: DetectionKind::Heuristic, confidence: c, reasons: vec![], inner_path: None }
    }

    #[test]
    fn worst_picks_highest_confidence() {
        let o = ScanOutcome {
            path: "a".into(),
            detections: vec![det(Confidence::Suspicious), det(Confidence::Known), det(Confidence::Malicious)],
            error: None,
        };
        assert_eq!(o.worst().unwrap().confidence, Confidence::Known);
        assert!(o.is_infected());
    }

    #[test]
    fn stats_categorize() {
        let mut s = ScanStats::default();
        s.record(&ScanOutcome::clean("c".into()));
        s.record(&ScanOutcome { path: "m".into(), detections: vec![det(Confidence::Malicious)], error: None });
        s.record(&ScanOutcome { path: "s".into(), detections: vec![det(Confidence::Suspicious)], error: None });
        s.record(&ScanOutcome { path: "e".into(), detections: vec![], error: Some("io".into()) });
        assert_eq!(s.scanned, 4);
        assert_eq!(s.infected, 1);
        assert_eq!(s.suspicious, 1);
        assert_eq!(s.errors, 1);
    }

    #[test]
    fn verdict_roundtrips_json() {
        let o = ScanOutcome { path: "p".into(), detections: vec![det(Confidence::Known)], error: None };
        let j = serde_json::to_string(&o).unwrap();
        assert_eq!(serde_json::from_str::<ScanOutcome>(&j).unwrap(), o);
    }
}
