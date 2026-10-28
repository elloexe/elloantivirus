//! `ello-service` — Ello Antivirus real-time protection.
//!
//! `run` executes the protection loop in the foreground (and is also the entry
//! point used when the Windows Service Control Manager starts the service).
//! On Windows, `install`/`uninstall`/`start`/`stop` register and control the
//! service; elsewhere `run` is intended to be supervised by the init system.

mod debounce;
mod watcher;
#[cfg(windows)]
mod win_service;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ello_common::{paths, Config};

pub const SERVICE_NAME: &str = "ElloProtection";
pub const SERVICE_DISPLAY: &str = "Ello Antivirus Real-Time Protection";

#[derive(Parser)]
#[command(
    name = "ello-service",
    version,
    about = "Ello Antivirus real-time protection service"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the protection loop in the foreground.
    Run {
        /// Override the watched folders (defaults to config).
        #[arg(long)]
        watch: Vec<PathBuf>,
    },
    /// Install the Windows service (Windows only).
    Install,
    /// Remove the Windows service (Windows only).
    Uninstall,
    /// Start the installed Windows service (Windows only).
    Start,
    /// Stop the running Windows service (Windows only).
    Stop,
}

fn main() -> ExitCode {
    ello_common::init_logging();
    // When the Windows SCM launches the service, it runs us with this hidden
    // argument; hand off to the service dispatcher instead of clap.
    #[cfg(windows)]
    if std::env::args().nth(1).as_deref() == Some("service-main") {
        return match win_service::dispatch() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                tracing::error!(error = %e, "service dispatch failed");
                ExitCode::FAILURE
            }
        };
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run { watch } => run_foreground(watch),
        Command::Install => service_control("install"),
        Command::Uninstall => service_control("uninstall"),
        Command::Start => service_control("start"),
        Command::Stop => service_control("stop"),
    }
}

/// Loads config and resolves the effective watch list.
pub fn load_watch_config(overrides: Vec<PathBuf>) -> Result<(Config, Vec<PathBuf>, Duration)> {
    let config = Config::load(&paths::config_file()).unwrap_or_default();
    let watch = if overrides.is_empty() {
        config.realtime.watch_paths.clone()
    } else {
        overrides
    };
    let debounce = Duration::from_millis(config.realtime.debounce_ms.max(50));
    Ok((config, watch, debounce))
}

fn run_foreground(overrides: Vec<PathBuf>) -> Result<()> {
    let (config, watch, debounce) = load_watch_config(overrides)?;
    if watch.is_empty() {
        anyhow::bail!("no watch paths configured; set realtime.watch_paths in config.toml");
    }
    let protection = watcher::Protection::from_config(&config).context("initializing engine")?;
    let (tx, rx) = crossbeam_channel::bounded::<()>(1);
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })
    .context("installing Ctrl-C handler")?;
    tracing::info!(paths = ?watch, "starting real-time protection");
    watcher::run(protection, &watch, debounce, rx)
}

#[cfg(windows)]
fn service_control(action: &str) -> Result<()> {
    match action {
        "install" => win_service::install(),
        "uninstall" => win_service::uninstall(),
        "start" => win_service::start(),
        "stop" => win_service::stop(),
        _ => unreachable!(),
    }
}

#[cfg(not(windows))]
fn service_control(_action: &str) -> Result<()> {
    anyhow::bail!("service install/start/stop is only available on Windows; use `ello-service run` under your init system (systemd, etc.)")
}
