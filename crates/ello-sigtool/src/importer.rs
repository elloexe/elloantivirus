//! Converts public malware hash feeds into the `.ellodb` signature format.
//!
//! Many threat-intel feeds (abuse.ch MalwareBazaar exports, VirusShare lists,
//! internal CSVs) publish one SHA-256 per sample, sometimes with a signature
//! or family label. This module normalizes those into `H <sha256> <name>`
//! records. It is deliberately tolerant: it accepts plain hash-per-line files
//! and CSV rows, skips comments and headers, and rejects malformed hashes
//! rather than emitting garbage signatures.

/// A parsed hash signature ready to serialize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashSig {
    pub sha256: String,
    pub name: String,
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn sanitize_name(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .trim_matches('"')
        .chars()
        .map(|c| if c.is_whitespace() { '_' } else { c })
        .filter(|c| !c.is_control())
        .collect();
    if cleaned.is_empty() {
        "Imported.Malware".to_string()
    } else {
        cleaned
    }
}

/// Splits a feed line into fields. Both commas and runs of unquoted
/// whitespace separate fields, so plain `<hash> <name>` lines and CSV rows are
/// handled the same way. Double-quoted fields keep their inner whitespace.
fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut pending = false; // a field boundary not yet committed
    for c in line.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut cur));
                pending = false;
            }
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    pending = true;
                }
            }
            _ => {
                if pending {
                    fields.push(std::mem::take(&mut cur));
                    pending = false;
                }
                cur.push(c);
            }
        }
    }
    fields.push(cur);
    fields
}

/// Parses one line, returning a signature if it carries a SHA-256.
///
/// `default_name` is used when the line has no usable label. `name_prefix`
/// (e.g. `Imported`) is prepended to produce namespaced threat names.
pub fn parse_line(line: &str, default_name: &str, name_prefix: &str) -> Option<HashSig> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
        return None;
    }
    let fields = csv_fields(line);
    // Find the first field that is a bare SHA-256.
    let hash_idx = fields.iter().position(|f| is_sha256(f.trim().trim_matches('"')))?;
    let sha256 = fields[hash_idx].trim().trim_matches('"').to_ascii_lowercase();
    // Choose a label: prefer a later non-hash, non-numeric field (family/sig).
    let label = fields
        .iter()
        .enumerate()
        .filter(|(i, f)| {
            *i != hash_idx && {
                let t = f.trim().trim_matches('"');
                // A family/signature name contains letters; this rejects
                // dates, timestamps, sizes, and other numeric columns.
                !is_sha256(t) && t.len() <= 64 && t.chars().any(|c| c.is_ascii_alphabetic())
            }
        })
        .map(|(_, f)| sanitize_name(f))
        .find(|s| s != "Imported.Malware")
        .unwrap_or_else(|| default_name.to_string());
    let name = if name_prefix.is_empty() {
        label
    } else {
        format!("{name_prefix}.{label}")
    };
    Some(HashSig { sha256, name })
}

/// Imports an entire feed, deduplicating by hash. Returns `(signatures, skipped)`.
pub fn import_feed(text: &str, default_name: &str, name_prefix: &str) -> (Vec<HashSig>, usize) {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    let mut skipped = 0;
    for line in text.lines() {
        match parse_line(line, default_name, name_prefix) {
            Some(sig) if seen.insert(sig.sha256.clone()) => out.push(sig),
            Some(_) => {} // duplicate
            None => {
                let t = line.trim();
                if !t.is_empty() && !t.starts_with('#') && !t.starts_with("//") {
                    skipped += 1;
                }
            }
        }
    }
    (out, skipped)
}

/// Serializes signatures as `.ellodb` `H` records.
pub fn to_ellodb(sigs: &[HashSig]) -> String {
    let mut out = String::new();
    for s in sigs {
        out.push_str(&format!("H {} {}\n", s.sha256, s.name));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    #[test]
    fn plain_hash_per_line() {
        let (sigs, skipped) = import_feed(&format!("{H}\n# comment\n{}\n", "ab".repeat(32)), "Generic", "Imported");
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0], HashSig { sha256: H.into(), name: "Imported.Generic".into() });
        assert_eq!(skipped, 0);
    }

    #[test]
    fn csv_with_family_label() {
        let line = format!("\"2024-01-01\",\"{H}\",\"TrojanDownloader\",\"32768\"");
        let sig = parse_line(&line, "Generic", "Imported").unwrap();
        assert_eq!(sig.sha256, H);
        assert_eq!(sig.name, "Imported.TrojanDownloader");
    }

    #[test]
    fn dedupes_and_counts_skips() {
        let text = format!("{H}\n{H}\nnot-a-hash-line garbage\n");
        let (sigs, skipped) = import_feed(&text, "Generic", "");
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].name, "Generic");
        assert_eq!(skipped, 1);
    }

    #[test]
    fn rejects_short_hash() {
        assert!(parse_line("deadbeef some label", "Generic", "Imported").is_none());
    }

    #[test]
    fn output_parses_back_into_engine() {
        let (sigs, _) = import_feed(&format!("{H} Ransom.Conti\n"), "Generic", "Imported");
        let text = format!("@version 1\n{}", to_ellodb(&sigs));
        let db = ello_engine::sigdb::SignatureDb::parse(&text).unwrap();
        assert_eq!(db.hash_count(), 1);
    }

    #[test]
    fn sanitizes_dangerous_label_chars() {
        let line = format!("{H},\"evil name\twith\ncontrol\"");
        let sig = parse_line(&line, "Generic", "Imported").unwrap();
        assert!(!sig.name.contains(char::is_whitespace) || sig.name.contains('_'));
        assert!(!sig.name.chars().any(|c| c.is_control()));
    }
}
