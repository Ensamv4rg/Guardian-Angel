use ga_engine::{Engine, EngineConfig, UserContext};
use ga_ipc::PIPE_NAME;
use ga_platform_win::{SERVICE_PIPE_SDDL, create_secure_pipe, pipe_client_sid};
use std::ffi::OsString;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::windows::named_pipe::NamedPipeServer;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const SERVICE_NAME: &str = "GuardianAngel";
const DISPLAY_NAME: &str = "Guardian Angel privacy engine";
const DESCRIPTION: &str = "Finds trackers, telemetry and spyware on this PC and blocks them when you choose.";
const PROXY_PORT: u16 = 8899;
const RESCAN_EVERY: Duration = Duration::from_secs(6 * 60 * 60);

/// Who a pipe connection may be answered for.
#[derive(Clone)]
enum Mode {
    /// Running as a normal user: only that user may connect.
    Console(Arc<UserContext>),
    /// Running as SYSTEM: each connecting user gets their own data.
    Service { data_root: PathBuf },
}

pub fn main() -> Result<(), BoxError> {
    match std::env::args().nth(1).as_deref() {
        None => Ok(service_dispatcher::start(SERVICE_NAME, ffi_service_main)?),
        Some("console") => run_console(),
        Some("install") => install(),
        Some("uninstall") => uninstall(),
        Some(other) => Err(format!("unknown command '{other}'; use console, install or uninstall").into()),
    }
}

fn run_console() -> Result<(), BoxError> {
    let local = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is not set")?;
    let data_root = PathBuf::from(local).join("GuardianAngel");
    let ctx = Arc::new(UserContext::current(&data_root));
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let engine = Engine::start(config(data_root)).await;
        println!("Guardian Angel engine running in console mode on {PIPE_NAME}. Press Ctrl+C to stop.");
        serve(engine, Mode::Console(ctx), async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    })
}

fn config(data_root: PathBuf) -> EngineConfig {
    EngineConfig {
        data_root,
        proxy_port: PROXY_PORT,
        network_monitor: true,
        app_scan: true,
    }
}

/// Accepts pipe connections until `shutdown` completes. A new pipe
/// instance is created before each connection is handed off, so clients
/// can always connect.
async fn serve(engine: Arc<Engine>, mode: Mode, shutdown: impl Future<Output = ()>) -> Result<(), BoxError> {
    let mut server = create_secure_pipe(PIPE_NAME, true, SERVICE_PIPE_SDDL)
        .map_err(|e| format!("could not open {PIPE_NAME} (is the service already running?): {e}"))?;
    let mut rescan = tokio::time::interval(RESCAN_EVERY);
    rescan.tick().await;
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            connected = server.connect() => {
                connected?;
                let client = std::mem::replace(&mut server, create_secure_pipe(PIPE_NAME, false, SERVICE_PIPE_SDDL)?);
                tokio::spawn(handle_client(engine.clone(), mode.clone(), client));
            }
            _ = rescan.tick() => engine.rescan_known_users(),
            () = &mut shutdown => return Ok(()),
        }
    }
}

async fn handle_client(engine: Arc<Engine>, mode: Mode, pipe: NamedPipeServer) {
    let sid = pipe_client_sid(&pipe);
    let ctx = match (&mode, sid) {
        // Console mode serves only the user who started it.
        (Mode::Console(own), Some(sid)) if own.sid.as_deref() == Some(sid.as_str()) => (**own).clone(),
        (Mode::Service { data_root }, Some(sid)) => match UserContext::for_sid(&sid, data_root) {
            Some(ctx) => ctx,
            None => return,
        },
        // Unknown or different user: close without answering.
        _ => return,
    };
    let slot = engine.slot(&ctx);
    let _ = ga_ipc::serve(pipe, |request| {
        let (engine, slot) = (engine.clone(), slot.clone());
        async move { engine.handle(slot, request).await }
    })
    .await;
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_args: Vec<OsString>) {
    let _ = run_service();
}

fn run_service() -> Result<(), BoxError> {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let stop_tx = std::sync::Mutex::new(Some(stop_tx));
    let status = service_control_handler::register(SERVICE_NAME, move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(tx) = stop_tx.lock().ok().and_then(|mut t| t.take()) {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let set = |state: ServiceState, accept: ServiceControlAccept| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
    };
    set(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN)?;

    let program_data = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
    let data_root = PathBuf::from(program_data).join("GuardianAngel");
    let result = tokio::runtime::Runtime::new().map_err(BoxError::from).and_then(|rt| {
        rt.block_on(async {
            let engine = Engine::start(config(data_root.clone())).await;
            serve(engine, Mode::Service { data_root }, async {
                let _ = stop_rx.await;
            })
            .await
        })
    });

    set(ServiceState::Stopped, ServiceControlAccept::empty())?;
    result
}

fn install() -> Result<(), BoxError> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    service.set_description(DESCRIPTION)?;
    service.start::<&str>(&[])?;
    println!("Installed and started the {SERVICE_NAME} service.");
    Ok(())
}

fn uninstall() -> Result<(), BoxError> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
    }
    service.delete()?;
    println!("Removed the {SERVICE_NAME} service.");
    Ok(())
}
