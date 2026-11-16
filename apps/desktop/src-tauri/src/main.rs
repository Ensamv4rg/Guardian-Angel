//! Guardian Angel desktop UI. It has no privileges of its own: every action
//! is a request to the service over its pipe, and the service decides what
//! this user may see and change.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use ga_ipc::{IpcError, RequestEnvelope};
use serde_json::{Value, json};
use tokio::sync::Mutex;

#[cfg(windows)]
type Pipe = tokio::net::windows::named_pipe::NamedPipeClient;

/// One connection to the service, opened on first use and reopened if the
/// service restarts.
#[derive(Default)]
struct Connection(Mutex<Option<ga_ipc::Client<Pipe>>>);

/// The single command the frontend uses: `invoke("ipc", { method, params })`.
#[tauri::command]
async fn ipc(state: tauri::State<'_, Connection>, method: String, params: Option<Value>) -> Result<Value, String> {
    let mut envelope = json!({ "id": 1, "method": method });
    if let Some(p) = params {
        envelope["params"] = p;
    }
    let request = serde_json::from_value::<RequestEnvelope>(envelope)
        .map_err(|_| "Unknown request.".to_owned())?
        .request;

    let mut conn = state.0.lock().await;
    for attempt in 0..2 {
        if conn.is_none() {
            let client = ga_ipc::connect()
                .await
                .map_err(|_| "The Guardian Angel service is not running.".to_owned())?;
            *conn = Some(client);
        }
        let Some(client) = conn.as_mut() else { continue };
        match client.call(request.clone()).await {
            Ok(v) => return Ok(v),
            Err(IpcError::Service(message)) => return Err(message),
            // The service restarted: reconnect once and retry.
            Err(_) if attempt == 0 => *conn = None,
            Err(e) => {
                *conn = None;
                return Err(e.to_string());
            }
        }
    }
    Err("Could not reach the Guardian Angel service.".to_owned())
}

/// Name of the inspection certificate, as the service creates it.
const CA_NAME: &str = "Guardian Angel Local Inspection CA";

/// Runs a program without flashing a console window.
fn run_hidden(program: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    std::process::Command::new(program).args(args).creation_flags(CREATE_NO_WINDOW).output()
}

/// Whether the inspection certificate is trusted for this Windows user.
#[tauri::command]
fn certificate_trusted() -> bool {
    run_hidden("certutil", &["-user", "-verifystore", "Root", CA_NAME]).is_ok_and(|o| o.status.success())
}

/// Trusts the certificate the service exported at `path` for this user.
/// Windows shows its own confirmation dialog; nothing happens without it.
#[tauri::command]
fn trust_certificate(path: String) -> Result<(), String> {
    if !path.to_lowercase().ends_with(".pem") || !std::path::Path::new(&path).is_file() {
        return Err("Certificate file not found.".into());
    }
    let out = run_hidden("certutil", &["-user", "-addstore", "Root", &path]).map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err("The certificate was not added (the Windows prompt may have been declined).".into())
    }
}

/// Removes the inspection certificate from this user's trusted roots.
#[tauri::command]
fn remove_certificate() -> Result<(), String> {
    let out = run_hidden("certutil", &["-user", "-delstore", "Root", CA_NAME]).map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err("The certificate could not be removed, or was not installed.".into())
    }
}

/// Starts an Electron or Chromium-based app with its traffic sent through
/// the inspection proxy. Only existing `.exe` files are accepted.
#[tauri::command]
fn launch_with_proxy(path: String, proxy: String) -> Result<(), String> {
    let exe = std::path::Path::new(&path);
    if !path.to_lowercase().ends_with(".exe") || !exe.is_file() {
        return Err("Program not found.".into());
    }
    if !proxy.starts_with("127.0.0.1:") {
        return Err("Only the local inspection proxy can be used.".into());
    }
    std::process::Command::new(exe)
        .arg(format!("--proxy-server={proxy}"))
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Process IDs with a visible window on this desktop, so the app list can
/// put open apps first. (The service cannot see windows; it runs in session 0.)
#[tauri::command]
fn windowed_pids() -> Vec<u32> {
    ga_platform_win::processes_with_windows().into_iter().collect()
}

/// Updates need the release signing key's public half in the config. Builds
/// made without it (development, local installers) cannot update themselves.
fn updates_configured(app: &tauri::AppHandle) -> bool {
    app.config()
        .plugins
        .0
        .get("updater")
        .and_then(|u| u.get("pubkey"))
        .and_then(Value::as_str)
        .is_some_and(|key| !key.trim().is_empty())
}

/// Asks the release server whether a newer version exists. Sends nothing
/// but the request for the release list.
#[tauri::command]
async fn check_update(app: tauri::AppHandle) -> Result<Value, String> {
    use tauri_plugin_updater::UpdaterExt;
    let current = app.package_info().version.to_string();
    if !updates_configured(&app) {
        return Ok(json!({ "configured": false, "current": current, "available": null }));
    }
    let update = app
        .updater()
        .map_err(|e| e.to_string())?
        .check()
        .await
        .map_err(|e| format!("Could not check for updates: {e}"))?;
    let available = update.map(|u| json!({ "version": u.version, "notes": u.body, "date": u.date.map(|d| d.to_string()) }));
    Ok(json!({ "configured": true, "current": current, "available": available }))
}

/// Downloads the newer installer, checks its signature and runs it. The
/// installer closes the app, updates the app and the service, and reopens it.
#[tauri::command]
async fn install_update(app: tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_updater::UpdaterExt;
    if !updates_configured(&app) {
        return Err("This copy of Guardian Angel was built without updates.".into());
    }
    let update = app
        .updater()
        .map_err(|e| e.to_string())?
        .check()
        .await
        .map_err(|e| format!("Could not check for updates: {e}"))?
        .ok_or("Guardian Angel is already up to date.")?;
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|e| format!("The update could not be installed: {e}"))?;
    app.restart();
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(Connection::default())
        .invoke_handler(tauri::generate_handler![
            ipc,
            certificate_trusted,
            trust_certificate,
            remove_certificate,
            launch_with_proxy,
            windowed_pids,
            check_update,
            install_update
        ])
        .run(tauri::generate_context!())
        .expect("error while running Guardian Angel");
}
