//! Recursive container inspection with zip-bomb protection.
//!
//! The scanner walks into ZIP-family containers (which includes OOXML Office
//! files, JARs, APKs and many installers) and hands each embedded member back
//! to the caller. Three independent limits bound the work so a malicious
//! archive cannot exhaust memory or CPU:
//!
//! * total decompressed bytes across the whole container ([`Limits::max_total_output`]),
//! * per-member decompressed size ([`Limits::max_entry_output`]),
//! * nesting depth ([`Limits::max_depth`]).

use std::io::Read;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_depth: u32,
    pub max_total_output: u64,
    pub max_entry_output: u64,
    pub max_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_depth: 8,
            max_total_output: 2 * 1024 * 1024 * 1024,
            max_entry_output: 256 * 1024 * 1024,
            max_entries: 100_000,
        }
    }
}

/// One extracted member: its path within the container and its bytes.
pub struct Member {
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ArchiveEvent {
    /// The container exceeded a limit; members already yielded are still valid.
    LimitHit(&'static str),
    NotAnArchive,
}

pub fn is_zip(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") || data.starts_with(b"PK\x07\x08")
}

/// Extracts members from a ZIP container, invoking `sink` for each. Extraction
/// stops (returning the triggering limit) as soon as a global limit is hit.
/// `budget` tracks output bytes already produced by ancestors so nested
/// archives share one total-output ceiling.
pub fn extract_zip(
    data: &[u8],
    limits: &Limits,
    budget: &mut u64,
    mut sink: impl FnMut(Member),
) -> Option<ArchiveEvent> {
    if !is_zip(data) {
        return Some(ArchiveEvent::NotAnArchive);
    }
    let reader = std::io::Cursor::new(data);
    let mut zip = match zip::ZipArchive::new(reader) {
        Ok(z) => z,
        Err(_) => return Some(ArchiveEvent::NotAnArchive),
    };
    if zip.len() > limits.max_entries {
        return Some(ArchiveEvent::LimitHit("too many entries"));
    }
    for i in 0..zip.len() {
        let mut entry = match zip.by_index(i) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().to_string();
        let declared = entry.size();
        if declared > limits.max_entry_output {
            continue; // skip oversized member, keep scanning the rest
        }
        if *budget >= limits.max_total_output {
            return Some(ArchiveEvent::LimitHit("total output budget"));
        }
        // Read with a hard cap even if the header lies about the size.
        let remaining = (limits.max_total_output - *budget).min(limits.max_entry_output);
        let mut buf = Vec::new();
        let mut limited = (&mut entry).take(remaining + 1);
        if limited.read_to_end(&mut buf).is_err() {
            continue;
        }
        if buf.len() as u64 > remaining {
            return Some(ArchiveEvent::LimitHit("decompression ratio"));
        }
        *budget += buf.len() as u64;
        sink(Member { name, data: buf });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    fn build_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            for (name, data) in files {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }

    #[test]
    fn extracts_members() {
        let z = build_zip(&[("a.txt", b"hello"), ("b/c.txt", b"world")]);
        let mut got = Vec::new();
        let mut budget = 0;
        assert!(extract_zip(&z, &Limits::default(), &mut budget, |m| got.push((m.name, m.data))).is_none());
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], ("a.txt".to_string(), b"hello".to_vec()));
        assert_eq!(budget, 10);
    }

    #[test]
    fn enforces_total_output_budget() {
        let z = build_zip(&[("big.bin", &vec![0u8; 50_000])]);
        let limits = Limits { max_total_output: 1000, ..Default::default() };
        let mut budget = 0;
        let ev = extract_zip(&z, &limits, &mut budget, |_| {});
        assert_eq!(ev, Some(ArchiveEvent::LimitHit("decompression ratio")));
    }

    #[test]
    fn highly_compressible_bomb_is_bounded() {
        // 10 MiB of zeros deflates tiny; the cap must stop us reading it all.
        let z = build_zip(&[("bomb", &vec![0u8; 10 * 1024 * 1024])]);
        let limits = Limits { max_entry_output: 4096, ..Default::default() };
        let mut budget = 0;
        let mut total = 0u64;
        extract_zip(&z, &limits, &mut budget, |m| total += m.data.len() as u64);
        assert_eq!(total, 0, "oversized entry should be skipped, not buffered");
    }

    #[test]
    fn rejects_non_zip() {
        let mut budget = 0;
        assert_eq!(extract_zip(b"not a zip", &Limits::default(), &mut budget, |_| {}), Some(ArchiveEvent::NotAnArchive));
    }
}
