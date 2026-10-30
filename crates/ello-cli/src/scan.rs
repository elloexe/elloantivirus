//! Scan orchestration lives in the shared `ello-scan` crate; re-exported here
//! so the rest of the CLI keeps using `crate::scan::*`.
pub use ello_scan::{collect_files, remediate, scan_files, Remediated, Remediation};
