//! Content-based file type identification. Extensions are only used as a
//! tie-breaker for text formats, because malware routinely lies about them.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FileType {
    Pe,
    Elf,
    Zip,
    Ole,
    Pdf,
    Script,
    Lnk,
    Unknown,
}

pub const SCRIPT_EXTENSIONS: &[&str] = &[
    "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "bat", "cmd", "sct",
    "py", "sh", "lnk", "url", "inf", "reg",
];

pub const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "scr", "com", "cpl", "ocx", "drv", "efi", "msi", "pif",
];

pub fn extension_of(name: &str) -> String {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
        .unwrap_or_default()
}

pub fn detect(name: &str, data: &[u8]) -> FileType {
    if data.starts_with(b"MZ") {
        return FileType::Pe;
    }
    if data.starts_with(b"\x7fELF") {
        return FileType::Elf;
    }
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        return FileType::Zip;
    }
    if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return FileType::Ole;
    }
    if data.starts_with(&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]) {
        return FileType::Lnk;
    }
    if data.len() >= 5
        && data[..data.len().min(1024)]
            .windows(5)
            .any(|w| w == b"%PDF-")
    {
        return FileType::Pdf;
    }
    let ext = extension_of(name);
    if SCRIPT_EXTENSIONS.contains(&ext.as_str()) || looks_like_text(data) {
        return FileType::Script;
    }
    FileType::Unknown
}

/// Heuristic: mostly printable bytes in the first 4 KiB (handles UTF-16LE BOM too).
fn looks_like_text(data: &[u8]) -> bool {
    let head = &data[..data.len().min(4096)];
    if head.is_empty() {
        return false;
    }
    if head.starts_with(&[0xFF, 0xFE]) {
        return true;
    }
    let printable = head
        .iter()
        .filter(|&&b| {
            b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b) || b >= 0x80
        })
        .count();
    printable * 100 / head.len() >= 95 && !head.contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_by_magic_not_extension() {
        assert_eq!(detect("invoice.pdf", b"MZ\x90\x00"), FileType::Pe);
        assert_eq!(detect("a.txt", b"PK\x03\x04rest"), FileType::Zip);
        assert_eq!(detect("x", b"%PDF-1.7"), FileType::Pdf);
        assert_eq!(detect("run.ps1", b"\x00\x01binary"), FileType::Script);
        assert_eq!(detect("notes", b"plain text here\n"), FileType::Script);
        assert_eq!(detect("blob.bin", &[0u8, 1, 2, 3, 0, 0]), FileType::Unknown);
    }
}
