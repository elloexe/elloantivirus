//! `ello` — the Ello Antivirus command-line scanner.

mod report;
mod scan;
mod targets;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Mutex;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ello_common::config::Sensitivity;
use ello_common::{paths, Config};
use ello_engine::scanner::{self, Engine};
use ello_engine::sigdb::SignatureDb;
use ello_engine::update;
use ello_quarantine::Quarantine;

use scan::Remediation;

#[derive(Parser)]
#[command(
    name = "ello",
    version,
    about = "Ello Antivirus — scan, quarantine, and update"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Emit machine-readable JSON instead of formatted text.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Scan specific files or directories.
    Scan {
        /// Files or directories to scan.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        #[command(flatten)]
        opts: ScanOpts,
        /// Do not descend into subdirectories.
        #[arg(long)]
        no_recurse: bool,
    },
    /// Quick scan: running processes, autostart entries, and hot folders.
    Quick {
        #[command(flatten)]
        opts: ScanOpts,
    },
    /// Full scan of all fixed drives.
    Full {
        #[command(flatten)]
        opts: ScanOpts,
    },
    /// Manage the quarantine vault.
    Quarantine {
        #[command(subcommand)]
        action: QuarantineCmd,
    },
    /// Apply or configure signed signature updates.
    Update {
        #[command(subcommand)]
        action: UpdateCmd,
    },
    /// Show engine status, signature version, and configuration.
    Status,
}

#[derive(Args)]
struct ScanOpts {
    /// Action for confirmed-malicious files (default: from config).
    #[arg(long, value_enum)]
    action: Option<ActionArg>,
    /// Heuristic sensitivity (default: from config).
    #[arg(long, value_enum)]
    sensitivity: Option<SensitivityArg>,
}

#[derive(Copy, Clone, ValueEnum)]
enum ActionArg {
    Report,
    Quarantine,
    Delete,
}

#[derive(Copy, Clone, ValueEnum)]
enum SensitivityArg {
    Off,
    Low,
    Normal,
    High,
}

#[derive(Subcommand)]
enum QuarantineCmd {
    /// List quarantined items.
    List,
    /// Restore an item by id (optionally to a new path).
    Restore {
        id: String,
        #[arg(long)]
        to: Option<PathBuf>,
    },
    /// Permanently delete an item by id.
    Remove { id: String },
    /// Permanently delete all quarantined items.
    Clear,
}

#[derive(Subcommand)]
enum UpdateCmd {
    /// Verify a signed `.ellodb` update and install it.
    Apply {
        /// Path to the `.ellodb` content file.
        #[arg(long)]
        file: PathBuf,
        /// Path to the detached signature (`.sig`).
        #[arg(long)]
        sig: PathBuf,
    },
    /// Trust an Ed25519 public key for future updates.
    Trust {
        /// Path to a key file (32 raw bytes or 64 hex chars).
        #[arg(long)]
        file: PathBuf,
        /// A short name for the key.
        #[arg(long, default_value = "default")]
        name: String,
    },
}

fn main() -> ExitCode {
    ello_common::init_logging();
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

/// Exit codes: 0 = clean, 1 = threats found, 2 = error.
fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let config = Config::load(&paths::config_file()).unwrap_or_default();

    match cli.command {
        Command::Scan {
            paths,
            opts,
            no_recurse,
        } => {
            let roots = paths;
            run_scan(&config, &opts, &roots, !no_recurse, cli.json)
        }
        Command::Quick { opts } => {
            let mut roots: Vec<PathBuf> = targets::running_process_images().into_iter().collect();
            roots.extend(targets::registry_autoruns());
            roots.extend(targets::startup_folders());
            roots.extend(targets::hot_folders());
            if !cli.json {
                eprintln!(
                    "Quick scan: {} process images + autoruns + hot folders",
                    roots.len()
                );
            }
            run_scan(&config, &opts, &roots, true, cli.json)
        }
        Command::Full { opts } => {
            let roots = targets::full_scan_roots();
            if !cli.json {
                eprintln!(
                    "Full scan of: {}",
                    roots
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            run_scan(&config, &opts, &roots, true, cli.json)
        }
        Command::Quarantine { action } => {
            run_quarantine(action, cli.json)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Update { action } => {
            run_update(&config, action, cli.json)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Status => {
            print_status(&config, cli.json)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn sig_path() -> PathBuf {
    paths::signatures_dir().join("latest.ellodb")
}

fn build_engine(config: &Config, opts: &ScanOpts) -> Result<Engine> {
    let mut scan_cfg = config.scan.clone();
    if let Some(s) = opts.sensitivity {
        scan_cfg.heuristic_sensitivity = match s {
            SensitivityArg::Off => Sensitivity::Off,
            SensitivityArg::Low => Sensitivity::Low,
            SensitivityArg::Normal => Sensitivity::Normal,
            SensitivityArg::High => Sensitivity::High,
        };
    }
    scanner::load_engine(&sig_path(), &scan_cfg).context("loading signature database")
}

fn resolve_action(config: &Config, opts: &ScanOpts) -> Remediation {
    match opts.action {
        Some(ActionArg::Report) => Remediation::ReportOnly,
        Some(ActionArg::Quarantine) => Remediation::Quarantine,
        Some(ActionArg::Delete) => Remediation::Delete,
        None => Remediation::from(config.realtime.action),
    }
}

fn run_scan(
    config: &Config,
    opts: &ScanOpts,
    roots: &[PathBuf],
    recurse: bool,
    json: bool,
) -> Result<ExitCode> {
    let engine = build_engine(config, opts)?;
    let action = resolve_action(config, opts);
    let files = scan::collect_files(roots, recurse);
    if !json {
        eprintln!(
            "Scanning {} files (signatures v{})...",
            files.len(),
            engine.signature_version()
        );
    }
    let (outcomes, stats) = scan::scan_files(&engine, &files, |o| {
        if !json && o.is_infected() {
            report::print_detection(o);
        }
    });

    // Prepare quarantine only if needed.
    let quarantine = Mutex::new(if action == Remediation::Quarantine {
        Quarantine::open(&paths::quarantine_dir()).ok()
    } else {
        None
    });
    let actions = scan::remediate(&outcomes, action, &quarantine);

    if json {
        let rep = report::json_report(&outcomes, &stats, engine.signature_version(), &actions);
        println!("{}", serde_json::to_string_pretty(&rep)?);
    } else {
        report::print_summary(&stats, engine.signature_version(), &actions);
    }

    Ok(if stats.infected > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn run_quarantine(action: QuarantineCmd, json: bool) -> Result<()> {
    let mut q = Quarantine::open(&paths::quarantine_dir()).context("opening quarantine vault")?;
    match action {
        QuarantineCmd::List => {
            if json {
                println!("{}", serde_json::to_string_pretty(q.entries())?);
            } else if q.entries().is_empty() {
                println!("Quarantine is empty.");
            } else {
                println!("{:<40} {:<24} ORIGINAL PATH", "ID", "THREAT");
                for e in q.entries() {
                    println!(
                        "{:<40} {:<24} {}",
                        e.id,
                        e.threat,
                        e.original_path.display()
                    );
                }
            }
        }
        QuarantineCmd::Restore { id, to } => {
            let dest = q.restore(&id, to.as_deref()).context("restoring item")?;
            println!("Restored to {}", dest.display());
        }
        QuarantineCmd::Remove { id } => {
            q.remove(&id).context("removing item")?;
            println!("Removed {id}");
        }
        QuarantineCmd::Clear => {
            let n = q.clear().context("clearing vault")?;
            println!("Removed {n} item(s)");
        }
    }
    Ok(())
}

fn load_trusted_keys() -> Vec<update::VerifyingKey> {
    let mut keys = Vec::new();
    if let Ok(dir) = std::fs::read_dir(paths::keys_dir()) {
        for entry in dir.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) == Some("pub") {
                if let Ok(bytes) = std::fs::read(entry.path()) {
                    let trimmed: Vec<u8> = bytes
                        .iter()
                        .copied()
                        .filter(|b| !b.is_ascii_whitespace())
                        .collect();
                    if let Ok(key) = update::parse_public_key(&trimmed) {
                        keys.push(key);
                    }
                }
            }
        }
    }
    keys
}

fn run_update(config: &Config, action: UpdateCmd, json: bool) -> Result<()> {
    match action {
        UpdateCmd::Apply { file, sig } => {
            let content =
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let sig_raw =
                std::fs::read(&sig).with_context(|| format!("reading {}", sig.display()))?;
            let signature = decode_sig(&sig_raw)?;
            let keys = load_trusted_keys();
            if keys.is_empty() {
                anyhow::bail!("no trusted signing keys installed; use `ello update trust --file <key.pub>` first");
            }
            let installed = SignatureDb::default();
            let current_version = scanner::load_engine(&sig_path(), &config.scan)
                .map(|e| e.signature_version())
                .unwrap_or(installed.version());
            let db = update::accept_update(&content, &signature, &keys, current_version)
                .context("verifying update")?;
            paths::ensure_layout()?;
            std::fs::write(sig_path(), &content).context("installing signatures")?;
            let msg = format!(
                "Installed signatures v{} ({} hashes, {} rules)",
                db.version(),
                db.hash_count(),
                db.rule_count()
            );
            if json {
                println!(
                    "{}",
                    serde_json::json!({"ok": true, "version": db.version(), "hashes": db.hash_count(), "rules": db.rule_count()})
                );
            } else {
                println!("{msg}");
            }
        }
        UpdateCmd::Trust { file, name } => {
            let bytes = std::fs::read(&file)?;
            let trimmed: Vec<u8> = bytes
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect();
            let key = update::parse_public_key(&trimmed).context("parsing public key")?;
            paths::ensure_layout()?;
            let dest = paths::keys_dir().join(format!("{name}.pub"));
            std::fs::write(&dest, hex::encode(key.to_bytes()))?;
            println!("Trusted key '{name}' installed ({}).", dest.display());
        }
    }
    Ok(())
}

/// Accepts a signature as 64 raw bytes or hex text.
fn decode_sig(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() == 64 {
        return Ok(raw.to_vec());
    }
    let text: String = raw
        .iter()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|&b| b as char)
        .collect();
    let decoded = hex::decode(&text).context("signature is neither 64 raw bytes nor hex")?;
    Ok(decoded)
}

fn print_status(config: &Config, json: bool) -> Result<()> {
    let version = scanner::load_engine(&sig_path(), &config.scan)
        .map(|e| e.signature_version())
        .unwrap_or(0);
    let sig_present = sig_path().exists();
    let trusted = load_trusted_keys().len();
    let quarantined = Quarantine::open(&paths::quarantine_dir())
        .map(|q| q.entries().len())
        .unwrap_or(0);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "signature_version": version,
                "signatures_installed": sig_present,
                "trusted_keys": trusted,
                "quarantined_items": quarantined,
                "data_dir": paths::data_dir(),
                "realtime_enabled": config.realtime.enabled,
                "sensitivity": config.scan.heuristic_sensitivity,
                "default_action": config.realtime.action,
            }))?
        );
    } else {
        println!("Ello Antivirus");
        println!(
            "  signatures        v{version}{}",
            if sig_present { "" } else { " (none installed)" }
        );
        println!("  trusted keys      {trusted}");
        println!("  quarantined items {quarantined}");
        println!("  data directory    {}", paths::data_dir().display());
        println!(
            "  realtime          {}",
            if config.realtime.enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        println!(
            "  sensitivity       {:?}",
            config.scan.heuristic_sensitivity
        );
        println!("  default action    {:?}", config.realtime.action);
    }
    Ok(())
}
