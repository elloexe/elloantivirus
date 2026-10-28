//! Human-readable and JSON reporting of scan results.

use std::path::PathBuf;

use ello_common::{Confidence, ScanOutcome, ScanStats};
use serde::Serialize;

use crate::scan::Remediated;

#[derive(Serialize)]
pub struct JsonReport<'a> {
    pub signature_version: u64,
    pub stats: &'a ScanStats,
    pub detections: Vec<JsonDetection<'a>>,
    pub actions: Vec<JsonAction<'a>>,
}

#[derive(Serialize)]
pub struct JsonDetection<'a> {
    pub path: &'a PathBuf,
    pub threat: &'a str,
    pub confidence: Confidence,
    pub location: Option<&'a str>,
    pub reasons: &'a [String],
}

#[derive(Serialize)]
pub struct JsonAction<'a> {
    pub path: &'a PathBuf,
    pub action: &'a Remediated,
}

const C_RED: &str = "\x1b[31m";
const C_YELLOW: &str = "\x1b[33m";
const C_GREEN: &str = "\x1b[32m";
const C_BOLD: &str = "\x1b[1m";
const C_DIM: &str = "\x1b[2m";
const C_RESET: &str = "\x1b[0m";

fn color_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none()
}

fn paint(color: &str, s: &str) -> String {
    if color_enabled() {
        format!("{color}{s}{C_RESET}")
    } else {
        s.to_string()
    }
}

/// Prints each detection as it is discovered (for live scanning feedback).
pub fn print_detection(outcome: &ScanOutcome) {
    for d in &outcome.detections {
        let (c, label) = match d.confidence {
            Confidence::Known => (C_RED, "THREAT"),
            Confidence::Malicious => (C_RED, "THREAT"),
            Confidence::Suspicious => (C_YELLOW, "SUSPECT"),
        };
        let loc = d
            .inner_path
            .as_deref()
            .map(|p| format!(" {}", paint(C_DIM, &format!("[{p}]"))))
            .unwrap_or_default();
        println!(
            "  {} {} {}{}",
            paint(c, &format!("[{label}]")),
            outcome.path.display(),
            paint(C_BOLD, &d.name),
            loc
        );
        for reason in &d.reasons {
            println!("          {}", paint(C_DIM, reason));
        }
    }
    if let Some(err) = &outcome.error {
        if err != "skipped" {
            eprintln!(
                "  {} {}: {}",
                paint(C_YELLOW, "[ERROR]"),
                outcome.path.display(),
                err
            );
        }
    }
}

/// Prints the end-of-scan summary and any remediation actions.
pub fn print_summary(stats: &ScanStats, version: u64, actions: &[(PathBuf, Remediated)]) {
    if !actions.is_empty() {
        println!("\n{}", paint(C_BOLD, "Actions taken:"));
        for (path, done) in actions {
            let desc = match done {
                Remediated::Quarantined { id } => paint(C_GREEN, &format!("quarantined (id {id})")),
                Remediated::Deleted => paint(C_GREEN, "deleted"),
                Remediated::Reported => paint(C_YELLOW, "reported only"),
                Remediated::Failed { error } => paint(C_RED, &format!("FAILED: {error}")),
            };
            println!("  {} -> {}", path.display(), desc);
        }
    }
    let infected_color = if stats.infected > 0 { C_RED } else { C_GREEN };
    println!("\n{}", paint(C_BOLD, "Scan complete"));
    println!("  signatures   v{version}");
    println!(
        "  scanned      {} files ({:.1} MiB)",
        stats.scanned,
        stats.bytes as f64 / (1024.0 * 1024.0)
    );
    println!(
        "  {}      {}",
        paint(infected_color, "infected"),
        paint(infected_color, &stats.infected.to_string())
    );
    if stats.suspicious > 0 {
        println!("  {}   {}", paint(C_YELLOW, "suspicious"), stats.suspicious);
    }
    if stats.errors > 0 {
        println!("  errors       {}", stats.errors);
    }
    if stats.skipped > 0 {
        println!("  skipped      {} (size/type filtered)", stats.skipped);
    }
}

/// Builds the structured JSON report.
pub fn json_report<'a>(
    outcomes: &'a [ScanOutcome],
    stats: &'a ScanStats,
    version: u64,
    actions: &'a [(PathBuf, Remediated)],
) -> JsonReport<'a> {
    let detections = outcomes
        .iter()
        .filter(|o| o.is_infected())
        .flat_map(|o| {
            o.detections.iter().map(move |d| JsonDetection {
                path: &o.path,
                threat: &d.name,
                confidence: d.confidence,
                location: d.inner_path.as_deref(),
                reasons: &d.reasons,
            })
        })
        .collect();
    let actions = actions
        .iter()
        .map(|(p, a)| JsonAction { path: p, action: a })
        .collect();
    JsonReport {
        signature_version: version,
        stats,
        detections,
        actions,
    }
}
