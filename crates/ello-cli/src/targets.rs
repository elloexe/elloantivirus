//! Target enumeration for quick and full scans.
//!
//! A *quick* scan looks at the places malware most often lives or runs from:
//! the images backing running processes, autostart entries, and the user's
//! high-traffic folders. A *full* scan walks entire drives.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// Extracts the executable path from an autostart command line.
///
/// Autorun values are frequently quoted and carry arguments, e.g.
/// `"C:\Program Files\App\app.exe" /background`. This returns just the
/// executable path so it can be scanned.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn executable_from_command(cmd: &str) -> Option<PathBuf> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return None;
    }
    let path = if let Some(rest) = cmd.strip_prefix('"') {
        rest.split('"').next().unwrap_or(rest)
    } else {
        // Unquoted: take up to the first argument that begins with a switch,
        // but keep spaces that are part of the path (best effort: stop at a
        // token starting with '/' or '-' that follows an existing path).
        match cmd.split_once(|c| c == ' ') {
            Some((head, _)) if head.to_ascii_lowercase().ends_with(".exe") => head,
            _ => cmd,
        }
    };
    let path = path.trim();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

/// Collects executables backing currently running processes.
pub fn running_process_images() -> BTreeSet<PathBuf> {
    use sysinfo::{ProcessesToUpdate, System};
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut out = BTreeSet::new();
    for proc in sys.processes().values() {
        if let Some(exe) = proc.exe() {
            if exe.is_file() {
                out.insert(exe.to_path_buf());
            }
        }
    }
    out
}

/// Startup-folder locations that hold autostart shortcuts/scripts.
pub fn startup_folders() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            v.push(PathBuf::from(appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
        }
        if let Some(pd) = std::env::var_os("ProgramData") {
            v.push(PathBuf::from(pd).join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
        }
    }
    v.retain(|p| p.is_dir());
    v
}

/// Registry autostart entries (Windows only). Parses `reg query` output into
/// the executable paths it references.
#[cfg(windows)]
pub fn registry_autoruns() -> BTreeSet<PathBuf> {
    const KEYS: &[&str] = &[
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ];
    let mut out = BTreeSet::new();
    for key in KEYS {
        let output = std::process::Command::new("reg").args(["query", key]).output();
        if let Ok(o) = output {
            out.extend(parse_reg_query(&String::from_utf8_lossy(&o.stdout)));
        }
    }
    out
}

#[cfg(not(windows))]
pub fn registry_autoruns() -> BTreeSet<PathBuf> {
    BTreeSet::new()
}

/// Parses `reg query` text output, pulling the command for each `REG_SZ` /
/// `REG_EXPAND_SZ` value and reducing it to an executable path.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn parse_reg_query(text: &str) -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        // Format: "<name>    REG_SZ    <data>"
        for marker in ["REG_SZ", "REG_EXPAND_SZ"] {
            if let Some(idx) = line.find(marker) {
                let data = line[idx + marker.len()..].trim();
                if let Some(exe) = executable_from_command(data) {
                    out.insert(exe);
                }
            }
        }
    }
    out
}

/// High-traffic user folders scanned during a quick scan.
pub fn hot_folders() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    #[cfg(windows)]
    {
        if let Some(up) = std::env::var_os("USERPROFILE") {
            let up = PathBuf::from(up);
            for sub in ["Downloads", "Desktop", "Documents"] {
                v.push(up.join(sub));
            }
        }
        if let Some(tmp) = std::env::var_os("TEMP") {
            v.push(PathBuf::from(tmp));
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(d) = dirs::download_dir() {
            v.push(d);
        }
    }
    v.retain(|p| p.is_dir());
    v
}

/// Roots for a full scan. On Windows, every fixed drive; elsewhere, `/`.
pub fn full_scan_roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let mut v = Vec::new();
        for letter in b'A'..=b'Z' {
            let root = PathBuf::from(format!("{}:\\", letter as char));
            if root.is_dir() {
                v.push(root);
            }
        }
        if v.is_empty() {
            v.push(PathBuf::from(r"C:\"));
        }
        v
    }
    #[cfg(not(windows))]
    {
        vec![PathBuf::from("/")]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_command() {
        assert_eq!(
            executable_from_command(r#""C:\Program Files\App\app.exe" /background"#),
            Some(PathBuf::from(r"C:\Program Files\App\app.exe"))
        );
    }

    #[test]
    fn parses_unquoted_with_args() {
        assert_eq!(
            executable_from_command(r"C:\Windows\system32\rundll32.exe shell32.dll,Control_RunDLL"),
            Some(PathBuf::from(r"C:\Windows\system32\rundll32.exe"))
        );
    }

    #[test]
    fn empty_command_is_none() {
        assert_eq!(executable_from_command("   "), None);
    }

    #[test]
    fn parses_reg_query_output() {
        let text = "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\r\n    OneDrive    REG_SZ    \"C:\\Users\\x\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background\r\n    Evil    REG_EXPAND_SZ    C:\\Temp\\dropper.exe\r\n";
        let paths = parse_reg_query(text);
        assert!(paths.contains(&PathBuf::from(r"C:\Users\x\AppData\Local\Microsoft\OneDrive\OneDrive.exe")));
        assert!(paths.contains(&PathBuf::from(r"C:\Temp\dropper.exe")));
        assert_eq!(paths.len(), 2);
    }
}
