//! Windows Service Control Manager integration.
//!
//! The installed service runs `ello-service.exe service-main` under the SCM.
//! Installation registers the current executable; the SCM entry point reports
//! status, launches the protection loop, and shuts down cleanly on Stop.

use std::ffi::OsString;
use std::time::Duration;

use anyhow::{Context, Result};
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service::ServiceControl, service_dispatcher};

use crate::{SERVICE_DISPLAY, SERVICE_NAME};

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

fn manager() -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::ALL_ACCESS)
        .context("opening the Service Control Manager (run as Administrator)")
}

pub fn install() -> Result<()> {
    let exe = std::env::current_exe().context("resolving current executable")?;
    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec![OsString::from("service-main")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager()?
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("creating service")?;
    service
        .set_description("Monitors folders and scans files in real time for malware.")
        .ok();
    println!("Installed service '{SERVICE_NAME}'. Start it with: ello-service start");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let service = manager()?
        .open_service(SERVICE_NAME, ServiceAccess::DELETE | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)
        .context("opening service")?;
    let _ = service.stop();
    service.delete().context("deleting service")?;
    println!("Uninstalled service '{SERVICE_NAME}'.");
    Ok(())
}

pub fn start() -> Result<()> {
    let service = manager()?
        .open_service(SERVICE_NAME, ServiceAccess::START)
        .context("opening service")?;
    service.start::<&str>(&[]).context("starting service")?;
    println!("Started service '{SERVICE_NAME}'.");
    Ok(())
}

pub fn stop() -> Result<()> {
    let service = manager()?
        .open_service(SERVICE_NAME, ServiceAccess::STOP)
        .context("opening service")?;
    service.stop().context("stopping service")?;
    println!("Stopped service '{SERVICE_NAME}'.");
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

/// Entry point invoked by the SCM. Errors are logged; there is no console.
fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(error = %e, "service terminated with error");
    }
}

/// Dispatches to the SCM. Called from `main` when the binary is launched with
/// the hidden `service-main` argument.
pub fn dispatch() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).context("starting service dispatcher")
}

fn run_service() -> Result<()> {
    let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("registering control handler")?;

    let running = |state: ServiceState, controls_accepted| ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };

    use windows_service::service::ServiceControlAccept;
    status_handle.set_service_status(running(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN))?;

    let (config, watch, debounce) = crate::load_watch_config(Vec::new())?;
    let result = watcher_run(config, watch, debounce, shutdown_rx);

    status_handle.set_service_status(running(ServiceState::Stopped, ServiceControlAccept::empty()))?;
    result
}

fn watcher_run(
    config: ello_common::Config,
    watch: Vec<std::path::PathBuf>,
    debounce: Duration,
    shutdown: crossbeam_channel::Receiver<()>,
) -> Result<()> {
    let protection = crate::watcher::Protection::from_config(&config)?;
    crate::watcher::run(protection, &watch, debounce, shutdown)
}
