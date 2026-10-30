//! The Ello Antivirus desktop application state and views.

use std::path::PathBuf;

use ello_common::config::{Config, DefaultAction, Sensitivity};
use ello_common::{paths, Confidence, ScanOutcome, ScanStats};
use ello_quarantine::{Quarantine, QuarantineEntry};
use ello_scan::{Remediated, Remediation};

use crate::worker::{self, ScanJob, ScanMsg};

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Scan,
    Quarantine,
    Protection,
    Status,
}

/// A detection row shown in the results list.
struct Hit {
    path: String,
    threat: String,
    confidence: Confidence,
    location: Option<String>,
}

#[derive(Default)]
struct ScanView {
    job: Option<ScanJob>,
    total: usize,
    done: usize,
    hits: Vec<Hit>,
    stats: Option<ScanStats>,
    actions: Vec<(PathBuf, Remediated)>,
    cancelled: bool,
    error: Option<String>,
    running: bool,
}

pub struct App {
    tab: Tab,
    config: Config,
    action: Remediation,
    scan: ScanView,
    quarantine: Vec<QuarantineEntry>,
    quarantine_error: Option<String>,
    status: StatusInfo,
    toast: Option<(String, bool)>, // (message, is_error)
}

#[derive(Default)]
struct StatusInfo {
    signature_version: u64,
    signatures_present: bool,
    trusted_keys: usize,
    quarantined: usize,
}

impl App {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let config = Config::load(&paths::config_file()).unwrap_or_default();
        let action = Remediation::from(config.realtime.action);
        let mut app = App {
            tab: Tab::Scan,
            config,
            action,
            scan: ScanView::default(),
            quarantine: Vec::new(),
            quarantine_error: None,
            status: StatusInfo::default(),
            toast: None,
        };
        app.refresh_status();
        app.refresh_quarantine();
        app
    }

    fn toast(&mut self, msg: impl Into<String>, is_error: bool) {
        self.toast = Some((msg.into(), is_error));
    }

    fn refresh_status(&mut self) {
        let sig = paths::signatures_dir().join("latest.ellodb");
        self.status.signatures_present = sig.exists();
        self.status.signature_version = ello_engine::scanner::load_engine(&sig, &self.config.scan)
            .map(|e| e.signature_version())
            .unwrap_or(0);
        self.status.trusted_keys = count_trusted_keys();
        self.status.quarantined = Quarantine::open(&paths::quarantine_dir())
            .map(|q| q.entries().len())
            .unwrap_or(0);
    }

    fn refresh_quarantine(&mut self) {
        match Quarantine::open(&paths::quarantine_dir()) {
            Ok(q) => {
                self.quarantine = q.entries().to_vec();
                self.quarantine_error = None;
            }
            Err(e) => self.quarantine_error = Some(e.to_string()),
        }
    }

    fn start_scan(&mut self, roots: Vec<PathBuf>, recurse: bool) {
        if roots.is_empty() {
            self.toast("Nothing to scan", true);
            return;
        }
        self.scan = ScanView {
            running: true,
            ..Default::default()
        };
        self.scan.job = Some(worker::start(
            roots,
            recurse,
            self.config.clone(),
            self.action,
        ));
    }

    /// Drains scan messages from the worker; returns true while a scan is live.
    fn pump_scan(&mut self) -> bool {
        let Some(job) = &self.scan.job else {
            return false;
        };
        let msgs: Vec<ScanMsg> = job.rx.try_iter().collect();
        for msg in msgs {
            match msg {
                ScanMsg::Counted { total } => self.scan.total = total,
                ScanMsg::Progress { done, infected } => {
                    self.scan.done = done;
                    if let Some(o) = infected {
                        push_hits(&mut self.scan.hits, &o);
                    }
                }
                ScanMsg::Done {
                    stats,
                    actions,
                    cancelled,
                } => {
                    self.scan.stats = Some(stats);
                    self.scan.actions = actions;
                    self.scan.cancelled = cancelled;
                    self.scan.running = false;
                }
                ScanMsg::Failed(e) => {
                    self.scan.error = Some(e);
                    self.scan.running = false;
                }
            }
        }
        if !self.scan.running {
            // Scan ended: refresh dependent views.
            self.scan.job = None;
            self.refresh_quarantine();
            self.refresh_status();
            return false;
        }
        true
    }
}

fn push_hits(hits: &mut Vec<Hit>, o: &ScanOutcome) {
    for d in &o.detections {
        hits.push(Hit {
            path: o.path.display().to_string(),
            threat: d.name.clone(),
            confidence: d.confidence,
            location: d.inner_path.clone(),
        });
    }
}

fn count_trusted_keys() -> usize {
    std::fs::read_dir(paths::keys_dir())
        .map(|d| {
            d.flatten()
                .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("pub"))
                .count()
        })
        .unwrap_or(0)
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let active = self.pump_scan();
        if active {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("🛡  Ello Antivirus");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let (txt, col) = if self.status.signatures_present {
                        (
                            format!("signatures v{}", self.status.signature_version),
                            egui::Color32::GRAY,
                        )
                    } else {
                        (
                            "no signatures installed".to_string(),
                            egui::Color32::from_rgb(0xd1, 0x8b, 0x1b),
                        )
                    };
                    ui.colored_label(col, txt);
                });
            });
            ui.add_space(6.0);
        });

        egui::SidePanel::left("nav")
            .exact_width(140.0)
            .resizable(false)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                for (tab, label) in [
                    (Tab::Scan, "Scan"),
                    (Tab::Quarantine, "Quarantine"),
                    (Tab::Protection, "Protection"),
                    (Tab::Status, "Status"),
                ] {
                    let selected = self.tab == tab;
                    if ui.selectable_label(selected, label).clicked() {
                        self.tab = tab;
                        if tab == Tab::Quarantine {
                            self.refresh_quarantine();
                        }
                        if tab == Tab::Status {
                            self.refresh_status();
                        }
                    }
                    ui.add_space(2.0);
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Scan => self.scan_tab(ui),
            Tab::Quarantine => self.quarantine_tab(ui),
            Tab::Protection => self.protection_tab(ui),
            Tab::Status => self.status_tab(ui),
        });

        if let Some((msg, is_error)) = self.toast.clone() {
            egui::TopBottomPanel::bottom("toast").show(ctx, |ui| {
                let col = if is_error {
                    egui::Color32::from_rgb(0xd9, 0x53, 0x4f)
                } else {
                    egui::Color32::from_rgb(0x3f, 0xa0, 0x5a)
                };
                ui.horizontal(|ui| {
                    ui.colored_label(col, &msg);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("✕").clicked() {
                            self.toast = None;
                        }
                    });
                });
            });
        }
    }
}

impl App {
    fn scan_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scan for threats");
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.add_enabled_ui(!self.scan.running, |ui| {
                if ui.button("📁  Choose folder…").clicked() {
                    if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                        self.start_scan(vec![dir], true);
                    }
                }
                if ui.button("📄  Choose file…").clicked() {
                    if let Some(f) = rfd::FileDialog::new().pick_file() {
                        self.start_scan(vec![f], false);
                    }
                }
                if ui
                    .button("⚡  Quick scan")
                    .on_hover_text("Hot folders: Downloads, Desktop, Documents, Temp")
                    .clicked()
                {
                    let roots = quick_scan_roots();
                    self.start_scan(roots, true);
                }
            });
            if self.scan.running && ui.button("⏹  Stop").clicked() {
                if let Some(j) = &self.scan.job {
                    j.cancel();
                }
            }
        });

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("On detection:");
            egui::ComboBox::from_id_salt("action")
                .selected_text(action_label(self.action))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.action, Remediation::Quarantine, "Quarantine");
                    ui.selectable_value(&mut self.action, Remediation::Delete, "Delete");
                    ui.selectable_value(&mut self.action, Remediation::ReportOnly, "Report only");
                });
            ui.separator();
            ui.label("Sensitivity:");
            let mut s = self.config.scan.heuristic_sensitivity;
            egui::ComboBox::from_id_salt("sens")
                .selected_text(format!("{s:?}"))
                .show_ui(ui, |ui| {
                    for v in [
                        Sensitivity::Off,
                        Sensitivity::Low,
                        Sensitivity::Normal,
                        Sensitivity::High,
                    ] {
                        ui.selectable_value(&mut s, v, format!("{v:?}"));
                    }
                });
            if s != self.config.scan.heuristic_sensitivity {
                self.config.scan.heuristic_sensitivity = s;
            }
        });

        ui.add_space(8.0);

        if self.scan.total > 0 || self.scan.running {
            let frac = if self.scan.total > 0 {
                self.scan.done as f32 / self.scan.total as f32
            } else {
                0.0
            };
            ui.add(
                egui::ProgressBar::new(frac)
                    .text(format!("{} / {} files", self.scan.done, self.scan.total)),
            );
        }

        if let Some(err) = &self.scan.error {
            ui.colored_label(
                egui::Color32::from_rgb(0xd9, 0x53, 0x4f),
                format!("Error: {err}"),
            );
        }

        if let Some(stats) = &self.scan.stats {
            ui.add_space(4.0);
            self.scan_summary(ui, stats.clone());
        }

        ui.add_space(8.0);
        ui.separator();
        ui.label(format!("Detections ({})", self.scan.hits.len()));
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if self.scan.hits.is_empty() && !self.scan.running && self.scan.stats.is_some() {
                    ui.add_space(8.0);
                    ui.colored_label(
                        egui::Color32::from_rgb(0x3f, 0xa0, 0x5a),
                        "✓  No threats found.",
                    );
                }
                for hit in &self.scan.hits {
                    ui.horizontal(|ui| {
                        let (badge, col) = match hit.confidence {
                            Confidence::Suspicious => {
                                ("SUSPECT", egui::Color32::from_rgb(0xd1, 0x8b, 0x1b))
                            }
                            _ => ("THREAT", egui::Color32::from_rgb(0xd9, 0x53, 0x4f)),
                        };
                        ui.colored_label(col, egui::RichText::new(badge).strong());
                        ui.label(egui::RichText::new(&hit.threat).strong());
                        ui.label(&hit.path);
                        if let Some(loc) = &hit.location {
                            ui.weak(format!("→ {loc}"));
                        }
                    });
                }
            });
    }

    fn scan_summary(&self, ui: &mut egui::Ui, stats: ScanStats) {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                if self.scan.cancelled {
                    ui.colored_label(egui::Color32::from_rgb(0xd1, 0x8b, 0x1b), "Scan cancelled.");
                } else {
                    ui.label(egui::RichText::new("Scan complete").strong());
                }
            });
            ui.horizontal(|ui| {
                ui.label(format!(
                    "Scanned {} files ({:.1} MiB)",
                    stats.scanned,
                    stats.bytes as f64 / (1024.0 * 1024.0)
                ));
                ui.separator();
                let col = if stats.infected > 0 {
                    egui::Color32::from_rgb(0xd9, 0x53, 0x4f)
                } else {
                    egui::Color32::from_rgb(0x3f, 0xa0, 0x5a)
                };
                ui.colored_label(col, format!("{} infected", stats.infected));
                if stats.suspicious > 0 {
                    ui.colored_label(
                        egui::Color32::from_rgb(0xd1, 0x8b, 0x1b),
                        format!("{} suspicious", stats.suspicious),
                    );
                }
                if stats.errors > 0 {
                    ui.weak(format!("{} errors", stats.errors));
                }
            });
            if !self.scan.actions.is_empty() {
                ui.separator();
                for (path, done) in &self.scan.actions {
                    let desc = match done {
                        Remediated::Quarantined { .. } => "quarantined".to_string(),
                        Remediated::Deleted => "deleted".to_string(),
                        Remediated::Reported => "reported".to_string(),
                        Remediated::Failed { error } => format!("FAILED: {error}"),
                    };
                    ui.weak(format!("{} — {desc}", path.display()));
                }
            }
        });
    }

    fn quarantine_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Quarantine");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Refresh").clicked() {
                    self.refresh_quarantine();
                }
                if !self.quarantine.is_empty() && ui.button("Clear all").clicked() {
                    if let Ok(mut q) = Quarantine::open(&paths::quarantine_dir()) {
                        match q.clear() {
                            Ok(n) => self.toast(format!("Removed {n} item(s)"), false),
                            Err(e) => self.toast(e.to_string(), true),
                        }
                    }
                    self.refresh_quarantine();
                }
            });
        });
        ui.add_space(4.0);

        if let Some(err) = &self.quarantine_error {
            ui.colored_label(egui::Color32::from_rgb(0xd9, 0x53, 0x4f), err);
            return;
        }
        if self.quarantine.is_empty() {
            ui.weak("Quarantine is empty.");
            return;
        }

        let mut restore: Option<String> = None;
        let mut delete: Option<String> = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for e in &self.quarantine {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(&e.threat)
                                    .strong()
                                    .color(egui::Color32::from_rgb(0xd9, 0x53, 0x4f)),
                            );
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.button("Delete").clicked() {
                                        delete = Some(e.id.clone());
                                    }
                                    if ui.button("Restore").clicked() {
                                        restore = Some(e.id.clone());
                                    }
                                },
                            );
                        });
                        ui.weak(e.original_path.display().to_string());
                        ui.weak(format!(
                            "{} · {} bytes · {}",
                            e.id, e.size, e.quarantined_at
                        ));
                    });
                }
            });

        if let Some(id) = restore {
            match Quarantine::open(&paths::quarantine_dir()).and_then(|mut q| q.restore(&id, None))
            {
                Ok(p) => self.toast(format!("Restored to {}", p.display()), false),
                Err(e) => self.toast(format!("Restore failed: {e}"), true),
            }
            self.refresh_quarantine();
        }
        if let Some(id) = delete {
            match Quarantine::open(&paths::quarantine_dir()).and_then(|mut q| q.remove(&id)) {
                Ok(()) => self.toast("Item deleted", false),
                Err(e) => self.toast(format!("Delete failed: {e}"), true),
            }
            self.refresh_quarantine();
        }
    }

    fn protection_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Real-time protection");
        ui.add_space(4.0);
        ui.label("Real-time protection runs as a background service so it keeps working after this window is closed.");
        ui.add_space(6.0);

        ui.checkbox(
            &mut self.config.realtime.enabled,
            "Enable real-time protection",
        );

        ui.horizontal(|ui| {
            ui.label("On detection:");
            let mut a = self.config.realtime.action;
            egui::ComboBox::from_id_salt("rt_action")
                .selected_text(format!("{a:?}"))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut a, DefaultAction::Quarantine, "Quarantine");
                    ui.selectable_value(&mut a, DefaultAction::Delete, "Delete");
                    ui.selectable_value(&mut a, DefaultAction::Report, "Report");
                });
            self.config.realtime.action = a;
        });

        ui.add_space(6.0);
        ui.label("Watched folders:");
        let mut remove: Option<usize> = None;
        for (i, p) in self.config.realtime.watch_paths.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.weak(p.display().to_string());
                if ui.small_button("✕").clicked() {
                    remove = Some(i);
                }
            });
        }
        if let Some(i) = remove {
            self.config.realtime.watch_paths.remove(i);
        }
        if ui.button("➕  Add folder…").clicked() {
            if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                if !self.config.realtime.watch_paths.contains(&dir) {
                    self.config.realtime.watch_paths.push(dir);
                }
            }
        }

        ui.add_space(8.0);
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("💾  Save settings").clicked() {
                self.save_config();
            }
            #[cfg(windows)]
            {
                if ui.button("Install service").clicked() {
                    self.run_service_cmd("install");
                }
                if ui.button("Start").clicked() {
                    self.run_service_cmd("start");
                }
                if ui.button("Stop").clicked() {
                    self.run_service_cmd("stop");
                }
            }
        });
        #[cfg(not(windows))]
        ui.weak("Service install/start/stop is available on Windows. On this platform, run `ello-service run` under your init system.");
    }

    fn status_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Status");
        ui.add_space(6.0);
        egui::Grid::new("status_grid")
            .num_columns(2)
            .spacing([24.0, 6.0])
            .show(ui, |ui| {
                ui.label("Signature version:");
                if self.status.signatures_present {
                    ui.label(format!("v{}", self.status.signature_version));
                } else {
                    ui.colored_label(egui::Color32::from_rgb(0xd1, 0x8b, 0x1b), "none installed");
                }
                ui.end_row();
                ui.label("Trusted update keys:");
                ui.label(self.status.trusted_keys.to_string());
                ui.end_row();
                ui.label("Quarantined items:");
                ui.label(self.status.quarantined.to_string());
                ui.end_row();
                ui.label("Data directory:");
                ui.label(paths::data_dir().display().to_string());
                ui.end_row();
            });

        ui.add_space(10.0);
        ui.separator();
        ui.label(egui::RichText::new("Signature updates").strong());
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui
                .button("Trust key…")
                .on_hover_text("Install a vendor public key (.pub)")
                .clicked()
            {
                self.trust_key_dialog();
            }
            if ui
                .button("Apply update…")
                .on_hover_text("Verify and install a signed .ellodb update")
                .clicked()
            {
                self.apply_update_dialog();
            }
            if ui.button("Refresh").clicked() {
                self.refresh_status();
            }
        });
    }

    fn save_config(&mut self) {
        match self.config.save(&paths::config_file()) {
            Ok(()) => self.toast("Settings saved", false),
            Err(e) => self.toast(format!("Save failed: {e}"), true),
        }
    }

    #[cfg(windows)]
    fn run_service_cmd(&mut self, action: &str) {
        let exe = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("ello-service.exe")))
            .unwrap_or_else(|| PathBuf::from("ello-service.exe"));
        match std::process::Command::new(&exe).arg(action).status() {
            Ok(s) if s.success() => self.toast(format!("Service {action} ok"), false),
            Ok(s) => self.toast(format!("Service {action} exited with {s}"), true),
            Err(e) => self.toast(format!("Could not run ello-service: {e}"), true),
        }
    }

    fn trust_key_dialog(&mut self) {
        let Some(file) = rfd::FileDialog::new()
            .add_filter("public key", &["pub"])
            .pick_file()
        else {
            return;
        };
        let result = (|| -> anyhow::Result<()> {
            let bytes = std::fs::read(&file)?;
            let trimmed: Vec<u8> = bytes
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect();
            let key = ello_engine::update::parse_public_key(&trimmed)?;
            paths::ensure_layout()?;
            let name = file
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("vendor");
            std::fs::write(
                paths::keys_dir().join(format!("{name}.pub")),
                hex::encode(key.to_bytes()),
            )?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.toast("Key trusted", false);
                self.refresh_status();
            }
            Err(e) => self.toast(format!("Trust failed: {e}"), true),
        }
    }

    fn apply_update_dialog(&mut self) {
        let Some(db) = rfd::FileDialog::new()
            .add_filter("signature db", &["ellodb"])
            .pick_file()
        else {
            return;
        };
        let Some(sig) = rfd::FileDialog::new()
            .add_filter("signature", &["sig"])
            .pick_file()
        else {
            return;
        };
        match apply_update(&db, &sig, &self.config) {
            Ok(v) => {
                self.toast(format!("Installed signatures v{v}"), false);
                self.refresh_status();
            }
            Err(e) => self.toast(format!("Update failed: {e}"), true),
        }
    }
}

fn apply_update(
    db: &std::path::Path,
    sig: &std::path::Path,
    config: &Config,
) -> anyhow::Result<u64> {
    let content = std::fs::read(db)?;
    let sig_raw = std::fs::read(sig)?;
    let signature = {
        let text: String = sig_raw
            .iter()
            .filter(|b| !b.is_ascii_whitespace())
            .map(|&b| b as char)
            .collect();
        if sig_raw.len() == 64 {
            sig_raw.clone()
        } else {
            hex::decode(&text)?
        }
    };
    let keys = load_trusted_keys();
    if keys.is_empty() {
        anyhow::bail!("no trusted keys installed; trust a vendor key first");
    }
    let sig_path = paths::signatures_dir().join("latest.ellodb");
    let current = ello_engine::scanner::load_engine(&sig_path, &config.scan)
        .map(|e| e.signature_version())
        .unwrap_or(0);
    let db_parsed = ello_engine::update::accept_update(&content, &signature, &keys, current)?;
    paths::ensure_layout()?;
    std::fs::write(&sig_path, &content)?;
    Ok(db_parsed.version())
}

fn load_trusted_keys() -> Vec<ello_engine::update::VerifyingKey> {
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
                    if let Ok(k) = ello_engine::update::parse_public_key(&trimmed) {
                        keys.push(k);
                    }
                }
            }
        }
    }
    keys
}

fn quick_scan_roots() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Config::load(&paths::config_file())
        .map(|c| c.realtime.watch_paths)
        .unwrap_or_default();
    #[cfg(not(windows))]
    if v.is_empty() {
        if let Some(d) = dirs_download() {
            v.push(d);
        }
    }
    v.retain(|p| p.exists());
    v
}

#[cfg(not(windows))]
fn dirs_download() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Downloads"))
}

fn action_label(a: Remediation) -> &'static str {
    match a {
        Remediation::Quarantine => "Quarantine",
        Remediation::Delete => "Delete",
        Remediation::ReportOnly => "Report only",
    }
}
