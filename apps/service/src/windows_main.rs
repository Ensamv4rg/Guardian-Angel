use ga_engine::{Engine, EngineConfig, UserContext};
use ga_ipc::PIPE_NAME;
use ga_platform_win::{SERVICE_PIPE_SDDL, create_secure_pipe, pipe_client_sid};
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
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
        // Console mode runs as the signed-in user, who cannot change the
        // network settings; blocking needs the installed service.
        let engine = Engine::start(EngineConfig {
            dns_blocking: false,
            ..config(data_root)
        })
        .await;
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
        dns_blocking: true,
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
            Some(ctx) => {
                grant_user_folder(&ctx.data_dir, &sid);
                ctx
            }
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

    let data_root = service_data_root();
    // Before the CA key is created or read: lock the folder down.
    secure_data_root(&data_root);
    let result =tokio::runtime::Runtime::new().map_err(BoxError::from).and_then(|rt| {
        rt.block_on(async {
            let engine = Engine::start(config(data_root.clone())).await;
            let served = serve(engine.clone(), Mode::Service { data_root }, async {
                let _ = stop_rx.await;
            })
            .await;
            // Put the network settings back before the process ends.
            engine.shutdown().await;
            served
        })
    });

    set(ServiceState::Stopped, ServiceControlAccept::empty())?;
    result
}

/// `C:\ProgramData\GuardianAngel`: the service's data, including the
/// inspection certificate's private key.
fn service_data_root() -> PathBuf {
    let program_data = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
    PathBuf::from(program_data).join("GuardianAngel")
}

/// Runs a system tool without a console window and reports whether it succeeded.
fn run_quiet(program: &str, args: &[&str]) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    std::process::Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Only SYSTEM and administrators may read the data folder (ProgramData is
/// readable by every user by default, and it holds the CA key).
///
/// The folder itself gets the two grants; everything inside is reset to
/// inherit them. (Applying the grants with `/T` instead strips every
/// permission from files, since folder inheritance flags do not apply to
/// files: an earlier version locked even SYSTEM out of its own CA key after
/// a restart. The reset also repairs those files.)
fn secure_data_root(root: &Path) {
    let _ = std::fs::create_dir_all(root);
    let inside = root.join("*");
    let root = root.to_string_lossy();
    run_quiet(
        "icacls",
        &[&root, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/Q"],
    );
    run_quiet("icacls", &[&inside.to_string_lossy(), "/reset", "/T", "/C", "/Q"]);
}

/// Lets one user read (not change) their own folder: their exported
/// certificate. Everything else in it is written by the service.
fn grant_user_folder(dir: &Path, sid: &str) {
    static DONE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = std::sync::OnceLock::new();
    let done = DONE.get_or_init(Default::default);
    if !done.lock().map(|mut d| d.insert(sid.to_owned())).unwrap_or(false) {
        return;
    }
    let _ = std::fs::create_dir_all(dir);
    run_quiet("icacls", &[&dir.to_string_lossy(), "/grant", &format!("*{sid}:(OI)(CI)RX"), "/Q"]);
}

fn wait_until_stopped(service: &windows_service::service::Service) {
    for _ in 0..40 {
        match service.query_status() {
            Ok(s) if s.current_state == ServiceState::Stopped => return,
            Err(_) => return,
            _ => std::thread::sleep(Duration::from_millis(250)),
        }
    }
}

/// Installs the service, or updates and restarts an existing install.
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
    let access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS;
    let service = match manager.open_service(SERVICE_NAME, access) {
        Ok(existing) => {
            // Upgrade or repair: stop the old copy, point it at this exe.
            let _ = existing.stop();
            wait_until_stopped(&existing);
            existing.change_config(&info)?;
            existing
        }
        Err(_) => manager.create_service(&info, access)?,
    };
    service.set_description(DESCRIPTION)?;
    // Restart after a crash, so blocking comes back (the original DNS server
    // stays second on each adapter, so the internet works in between).
    run_quiet(
        "sc.exe",
        &["failure", SERVICE_NAME, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/60000"],
    );
    secure_data_root(&service_data_root());
    service.start::<&str>(&[])?;
    println!("Installed and started the {SERVICE_NAME} service.");
    Ok(())
}

/// Removes the service. First puts back every Windows setting Guardian Angel
/// changed, for every user who used it (NFR-9: uninstall restores settings).
fn uninstall() -> Result<(), BoxError> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    );
    if let Ok(service) = &service {
        let _ = service.stop();
        wait_until_stopped(service);
    }
    // The service puts DNS back when it stops; this covers a crashed one.
    for name in ga_engine::blocking::restore_from_disk(&service_data_root()) {
        println!("Restored the DNS setting of {name}.");
    }

    let users = service_data_root().join("users");
    for entry in std::fs::read_dir(&users).into_iter().flatten().flatten() {
        let sid = entry.file_name().to_string_lossy().into_owned();
        let Ok(journal) = ga_blocker::settings::journal::Journal::open(&entry.path().join("changes")) else { continue };
        let mut store = ga_blocker::settings::store::WindowsStore::for_user(&sid);
        match ga_blocker::settings::undo_all(&mut store, &journal) {
            Ok(done) if !done.is_empty() => println!("Restored {} setting change(s) for {sid}.", done.len()),
            Ok(_) => {}
            // A user who is signed out has no loaded registry hive; their
            // changes stay recorded and are listed here.
            Err(e) => println!("Could not restore settings for {sid}: {e}"),
        }
    }

    if let Ok(service) = service {
        service.delete()?;
        println!("Removed the {SERVICE_NAME} service.");
    }
    Ok(())
}
