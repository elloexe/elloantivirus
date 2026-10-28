//! Signature database: exact SHA-256 hash signatures plus byte-pattern rules.
//!
//! # Text format (`.ellodb`)
//!
//! ```text
//! # comment
//! @version 2026102801
//! H <sha256-hex> <ThreatName>
//! R <target> <min-matches> <ThreatName> <pattern> [<pattern> ...]
//! ```
//!
//! `target` is one of `any`, `pe`, `script`, `ole`, `pdf`, `zip`.
//! A pattern is either a hex string (`4d5a??00`, `??` = any byte), an ASCII
//! string literal (`"text"`) or a UTF-16LE string literal (`w"text"`).
//! A rule fires when at least `min-matches` of its patterns are present.

use std::collections::{HashMap, HashSet};
use std::fmt;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use crate::filetype::FileType;

/// Smallest literal run a pattern must contain; shorter anchors make the
/// prefilter useless and produce excessive candidate checks.
pub const MIN_ANCHOR_LEN: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum SigDbError {
    #[error("line {line}: {msg}")]
    Parse { line: usize, msg: String },
}

fn perr<T>(line: usize, msg: impl Into<String>) -> Result<T, SigDbError> {
    Err(SigDbError::Parse { line, msg: msg.into() })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    Any,
    Pe,
    Script,
    Ole,
    Pdf,
    Zip,
}

impl Target {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "any" => Target::Any,
            "pe" => Target::Pe,
            "script" => Target::Script,
            "ole" => Target::Ole,
            "pdf" => Target::Pdf,
            "zip" => Target::Zip,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Target::Any => "any",
            Target::Pe => "pe",
            Target::Script => "script",
            Target::Ole => "ole",
            Target::Pdf => "pdf",
            Target::Zip => "zip",
        }
    }

    pub fn applies_to(self, ft: FileType) -> bool {
        match self {
            Target::Any => true,
            Target::Pe => ft == FileType::Pe,
            Target::Script => ft == FileType::Script,
            Target::Ole => ft == FileType::Ole,
            Target::Pdf => ft == FileType::Pdf,
            Target::Zip => ft == FileType::Zip,
        }
    }
}

/// A byte pattern where `None` is a single-byte wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    bytes: Vec<Option<u8>>,
    anchor_start: usize,
    anchor_len: usize,
}

impl Pattern {
    pub fn new(bytes: Vec<Option<u8>>) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("empty pattern".into());
        }
        // Longest run of literal bytes becomes the Aho-Corasick anchor.
        let (mut best_start, mut best_len) = (0, 0);
        let mut run_start = 0;
        for (i, b) in bytes.iter().enumerate() {
            if b.is_none() {
                run_start = i + 1;
            } else if i + 1 - run_start > best_len {
                best_start = run_start;
                best_len = i + 1 - run_start;
            }
        }
        if best_len < MIN_ANCHOR_LEN {
            return Err(format!(
                "pattern needs at least {MIN_ANCHOR_LEN} consecutive literal bytes"
            ));
        }
        Ok(Pattern { bytes, anchor_start: best_start, anchor_len: best_len })
    }

    pub fn literal(bytes: &[u8]) -> Result<Self, String> {
        Self::new(bytes.iter().copied().map(Some).collect())
    }

    fn anchor(&self) -> Vec<u8> {
        self.bytes[self.anchor_start..self.anchor_start + self.anchor_len]
            .iter()
            .map(|b| b.expect("anchor is literal"))
            .collect()
    }

    /// Checks the full pattern given that its anchor matched at `anchor_pos`.
    fn matches_at(&self, data: &[u8], anchor_pos: usize) -> bool {
        let Some(start) = anchor_pos.checked_sub(self.anchor_start) else {
            return false;
        };
        let Some(window) = data.get(start..start + self.bytes.len()) else {
            return false;
        };
        window.iter().zip(&self.bytes).all(|(d, p)| p.map_or(true, |p| p == *d))
    }

    fn parse_token(tok: &str) -> Result<Self, String> {
        if let Some(s) = tok.strip_prefix("w\"") {
            let s = unescape(s.strip_suffix('"').ok_or("unterminated string")?)?;
            let wide: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            return Self::literal(&wide);
        }
        if let Some(s) = tok.strip_prefix('"') {
            let s = unescape(s.strip_suffix('"').ok_or("unterminated string")?)?;
            return Self::literal(s.as_bytes());
        }
        if tok.len() % 2 != 0 {
            return Err("hex pattern has odd length".into());
        }
        let mut out = Vec::with_capacity(tok.len() / 2);
        for chunk in tok.as_bytes().chunks(2) {
            if chunk == b"??" {
                out.push(None);
            } else {
                let s = std::str::from_utf8(chunk).map_err(|_| "invalid hex")?;
                out.push(Some(u8::from_str_radix(s, 16).map_err(|_| format!("invalid hex byte {s:?}"))?));
            }
        }
        Self::new(out)
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.bytes {
            match b {
                Some(b) => write!(f, "{b:02x}")?,
                None => f.write_str("??")?,
            }
        }
        Ok(())
    }
}

fn unescape(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('s') => out.push(' '),
            Some('x') => {
                let h: String = chars.by_ref().take(2).collect();
                let v = u8::from_str_radix(&h, 16).map_err(|_| format!("bad \\x escape {h:?}"))?;
                out.push(v as char);
            }
            other => return Err(format!("unknown escape \\{}", other.unwrap_or(' '))),
        }
    }
    Ok(out)
}

/// Splits a line on whitespace, keeping quoted strings (with escapes) intact.
fn tokenize(line: &str) -> Result<Vec<String>, String> {
    let mut toks = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    let mut escaped = false;
    for c in line.chars() {
        if in_str {
            cur.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if c.is_whitespace() {
            if !cur.is_empty() {
                toks.push(std::mem::take(&mut cur));
            }
        } else {
            if c == '"' {
                in_str = true;
            }
            cur.push(c);
        }
    }
    if in_str {
        return Err("unterminated string".into());
    }
    if !cur.is_empty() {
        toks.push(cur);
    }
    Ok(toks)
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub target: Target,
    pub min_matches: usize,
    pub patterns: Vec<Pattern>,
}

/// A hit produced by the pattern matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHit {
    pub name: String,
    pub matched: usize,
    pub total: usize,
}

#[derive(Default)]
pub struct SignatureDb {
    version: u64,
    hashes: HashMap<[u8; 32], String>,
    rules: Vec<Rule>,
    matcher: Option<Matcher>,
}

struct Matcher {
    ac: AhoCorasick,
    /// For each distinct anchor: (rule index, pattern index) pairs using it.
    anchors: Vec<Vec<(usize, usize)>>,
}

impl SignatureDb {
    pub fn parse(text: &str) -> Result<Self, SigDbError> {
        let mut db = SignatureDb::default();
        db.merge_text(text)?;
        Ok(db)
    }

    /// Adds the signatures from `text` to this database. The version becomes
    /// the highest version seen.
    pub fn merge_text(&mut self, text: &str) -> Result<(), SigDbError> {
        for (idx, raw) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let toks = match tokenize(line) {
                Ok(t) => t,
                Err(e) => return perr(line_no, e),
            };
            match toks[0].as_str() {
                "@version" => {
                    let Some(v) = toks.get(1).and_then(|v| v.parse::<u64>().ok()) else {
                        return perr(line_no, "@version needs a number");
                    };
                    self.version = self.version.max(v);
                }
                "H" => {
                    if toks.len() != 3 {
                        return perr(line_no, "expected: H <sha256> <name>");
                    }
                    let mut h = [0u8; 32];
                    if hex::decode_to_slice(&toks[1], &mut h).is_err() {
                        return perr(line_no, "invalid sha256");
                    }
                    self.hashes.insert(h, toks[2].clone());
                }
                "R" => {
                    if toks.len() < 5 {
                        return perr(line_no, "expected: R <target> <min> <name> <pattern>...");
                    }
                    let Some(target) = Target::parse(&toks[1]) else {
                        return perr(line_no, format!("unknown target {:?}", toks[1]));
                    };
                    let Ok(min_matches) = toks[2].parse::<usize>() else {
                        return perr(line_no, "min-matches must be a number");
                    };
                    let mut patterns = Vec::new();
                    for t in &toks[4..] {
                        match Pattern::parse_token(t) {
                            Ok(p) => patterns.push(p),
                            Err(e) => return perr(line_no, e),
                        }
                    }
                    if min_matches == 0 || min_matches > patterns.len() {
                        return perr(line_no, "min-matches must be between 1 and the pattern count");
                    }
                    self.rules.push(Rule { name: toks[3].clone(), target, min_matches, patterns });
                }
                other => return perr(line_no, format!("unknown record type {other:?}")),
            }
        }
        self.rebuild();
        Ok(())
    }

    pub fn add_hash(&mut self, sha256: [u8; 32], name: impl Into<String>) {
        self.hashes.insert(sha256, name.into());
    }

    fn rebuild(&mut self) {
        let mut index: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut anchors: Vec<Vec<(usize, usize)>> = Vec::new();
        let mut literals: Vec<Vec<u8>> = Vec::new();
        for (ri, rule) in self.rules.iter().enumerate() {
            for (pi, pat) in rule.patterns.iter().enumerate() {
                let a = pat.anchor();
                let slot = *index.entry(a.clone()).or_insert_with(|| {
                    literals.push(a);
                    anchors.push(Vec::new());
                    anchors.len() - 1
                });
                anchors[slot].push((ri, pi));
            }
        }
        self.matcher = if literals.is_empty() {
            None
        } else {
            let ac = AhoCorasickBuilder::new()
                .match_kind(MatchKind::Standard)
                .build(&literals)
                .expect("anchor automaton");
            Some(Matcher { ac, anchors })
        };
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn hash_count(&self) -> usize {
        self.hashes.len()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn lookup_hash(&self, sha256: &[u8; 32]) -> Option<&str> {
        self.hashes.get(sha256).map(String::as_str)
    }

    /// Runs all pattern rules applicable to `ft` over `data`.
    pub fn match_rules(&self, data: &[u8], ft: FileType) -> Vec<RuleHit> {
        let Some(m) = &self.matcher else { return Vec::new() };
        let mut found: HashSet<(usize, usize)> = HashSet::new();
        for hit in m.ac.find_overlapping_iter(data) {
            for &(ri, pi) in &m.anchors[hit.pattern().as_usize()] {
                if found.contains(&(ri, pi)) || !self.rules[ri].target.applies_to(ft) {
                    continue;
                }
                if self.rules[ri].patterns[pi].matches_at(data, hit.start()) {
                    found.insert((ri, pi));
                }
            }
        }
        let mut per_rule: HashMap<usize, usize> = HashMap::new();
        for (ri, _) in found {
            *per_rule.entry(ri).or_default() += 1;
        }
        let mut hits: Vec<RuleHit> = per_rule
            .into_iter()
            .filter(|&(ri, n)| n >= self.rules[ri].min_matches)
            .map(|(ri, n)| RuleHit {
                name: self.rules[ri].name.clone(),
                matched: n,
                total: self.rules[ri].patterns.len(),
            })
            .collect();
        hits.sort_by(|a, b| a.name.cmp(&b.name));
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_matches_wildcards() {
        let db = SignatureDb::parse(
            "@version 7\nR any 1 Test.Wild 41424344??46\nR pe 1 Test.PeOnly \"hello\"\n",
        )
        .unwrap();
        assert_eq!(db.version(), 7);
        let hits = db.match_rules(b"xxABCDzFyy", FileType::Unknown);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "Test.Wild");
        assert!(db.match_rules(b"hello", FileType::Unknown).is_empty());
        assert_eq!(db.match_rules(b"hello", FileType::Pe)[0].name, "Test.PeOnly");
    }

    #[test]
    fn min_matches_threshold() {
        let db = SignatureDb::parse(r#"R any 2 Test.TwoOf "alpha" "bravo" w"charlie""#).unwrap();
        assert!(db.match_rules(b"alpha only", FileType::Unknown).is_empty());
        let wide: Vec<u8> = "charlie".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut data = b"alpha ".to_vec();
        data.extend_from_slice(&wide);
        let hits = db.match_rules(&data, FileType::Unknown);
        assert_eq!(hits, vec![RuleHit { name: "Test.TwoOf".into(), matched: 2, total: 3 }]);
    }

    #[test]
    fn shared_anchors_and_overlaps() {
        let db = SignatureDb::parse("R any 1 A \"abcdef\"\nR any 1 B \"abcdef\"\nR any 1 C \"cdefgh\"\n").unwrap();
        let names: Vec<_> = db.match_rules(b"abcdefgh", FileType::Unknown).into_iter().map(|h| h.name).collect();
        assert_eq!(names, ["A", "B", "C"]);
    }

    #[test]
    fn quoted_strings_with_spaces_and_escapes() {
        let db = SignatureDb::parse(r#"R any 1 Q "a b \"c\" \x41""#).unwrap();
        assert_eq!(db.match_rules(b"..a b \"c\" A..", FileType::Unknown).len(), 1);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(SignatureDb::parse("R any 1 X 41??42").is_err()); // anchor too short
        assert!(SignatureDb::parse("R any 3 X \"aaaa\" \"bbbb\"").is_err());
        assert!(SignatureDb::parse("H nothex X").is_err());
        assert!(SignatureDb::parse("Z whatever").is_err());
        assert!(SignatureDb::parse("R nope 1 X \"aaaa\"").is_err());
    }

    #[test]
    fn hash_lookup() {
        let db = SignatureDb::parse(&format!("H {} Test.Hash", "ab".repeat(32))).unwrap();
        assert_eq!(db.lookup_hash(&[0xab; 32]), Some("Test.Hash"));
        assert_eq!(db.lookup_hash(&[0; 32]), None);
    }
}
