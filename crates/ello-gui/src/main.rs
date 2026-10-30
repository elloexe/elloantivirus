//! Ello Antivirus desktop application (egui/eframe).
//!
//! This is the primary user interface; the `ello` CLI remains for scripting.
//! The GUI wraps the same engine, quarantine and scan-session code as the CLI,
//! running scans on a background thread so the window stays responsive.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod worker;

fn main() -> eframe::Result<()> {
    ello_common::init_logging();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([860.0, 600.0])
            .with_min_inner_size([680.0, 460.0])
            .with_title("Ello Antivirus"),
        ..Default::default()
    };
    eframe::run_native(
        "Ello Antivirus",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
