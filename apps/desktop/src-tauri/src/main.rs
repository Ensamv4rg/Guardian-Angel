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

// ---- Windows proxy setting (for inspecting apps that do not take a flag) ----

use ga_platform_win::inet_proxy::{self, PROXY_TYPE_AUTO_PROXY_URL, PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY, ProxySetting};

/// The proxy runs in the service on this port (see the service).
const INSPECTION_PROXY: &str = "127.0.0.1:8899";

fn pac_url() -> String {
    format!("http://{INSPECTION_PROXY}/proxy.pac")
}

/// Where the setting from before is kept, to put it back exactly.
fn proxy_backup_path() -> Option<std::path::PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| std::path::PathBuf::from(d).join("GuardianAngel").join("proxy-before.json"))
}

fn setting_to_json(s: &ProxySetting) -> Value {
    json!({ "flags": s.flags, "server": s.server, "bypass": s.bypass, "script_url": s.script_url })
}

fn setting_from_json(v: &Value) -> ProxySetting {
    let text = |k: &str| v[k].as_str().map(str::to_owned);
    ProxySetting {
        flags: v["flags"].as_u64().and_then(|f| u32::try_from(f).ok()).unwrap_or(PROXY_TYPE_DIRECT),
        server: text("server"),
        bypass: text("bypass"),
        script_url: text("script_url"),
    }
}

fn is_ours(s: &ProxySetting) -> bool {
    s.flags & PROXY_TYPE_AUTO_PROXY_URL != 0 && s.script_url.as_deref() == Some(pac_url().as_str())
}

/// Whether the service's proxy answers with its setup script.
fn proxy_answers() -> bool {
    use std::io::{Read, Write};
    let Ok(addr) = INSPECTION_PROXY.parse() else { return false };
    let Ok(mut tcp) = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2)) else { return false };
    let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(2)));
    let request = format!("GET /proxy.pac HTTP/1.1\r\nHost: {INSPECTION_PROXY}\r\nConnection: close\r\n\r\n");
    let mut reply = String::new();
    tcp.write_all(request.as_bytes()).is_ok() && tcp.read_to_string(&mut reply).is_ok() && reply.contains("FindProxyForURL")
}

/// Whether apps are being sent through Guardian Angel, and what was there before.
#[tauri::command]
fn system_proxy_status() -> Result<Value, String> {
    let current = inet_proxy::current_proxy().map_err(|e| e.to_string())?;
    let other = !is_ours(&current) && current.flags & (PROXY_TYPE_PROXY | PROXY_TYPE_AUTO_PROXY_URL) != 0;
    Ok(json!({ "on": is_ours(&current), "other_proxy": other, "proxy_running": proxy_answers() }))
}

/// Points the Windows proxy setting at Guardian Angel's setup script.
#[tauri::command]
fn system_proxy_on() -> Result<(), String> {
    let current = inet_proxy::current_proxy().map_err(|e| e.to_string())?;
    if is_ours(&current) {
        return Ok(());
    }
    if current.flags & (PROXY_TYPE_PROXY | PROXY_TYPE_AUTO_PROXY_URL) != 0 {
        return Err("This PC already uses a proxy (often set up by work or school). Guardian Angel will not replace it.".into());
    }
    if !proxy_answers() {
        return Err("The inspection proxy is not running, so nothing was changed. Check that the Guardian Angel service is running.".into());
    }
    let path = proxy_backup_path().ok_or("LOCALAPPDATA is not set")?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(&path, setting_to_json(&current).to_string()).map_err(|e| e.to_string())?;
    inet_proxy::set_proxy(&ProxySetting {
        flags: PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_PROXY_URL,
        script_url: Some(pac_url()),
        ..current
    })
    .map_err(|e| e.to_string())
}

/// Puts the Windows proxy setting back as it was. Also run by the
/// uninstaller (`guardian-angel.exe --restore-proxy`).
#[tauri::command]
fn system_proxy_off() -> Result<(), String> {
    let current = inet_proxy::current_proxy().map_err(|e| e.to_string())?;
    let path = proxy_backup_path();
    let before = path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .map(|v| setting_from_json(&v));
    if is_ours(&current) {
        let restored = before.unwrap_or(ProxySetting {
            flags: PROXY_TYPE_DIRECT,
            ..current
        });
        inet_proxy::set_proxy(&restored).map_err(|e| e.to_string())?;
    }
    if let Some(p) = path {
        let _ = std::fs::remove_file(p);
    }
    Ok(())
}

/// Opens a web page or a new email in the user's own browser or mail app
/// (data request forms and letters). Only `https:` and `mailto:` links.
#[tauri::command]
fn open_link(url: String) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("mailto:")) || url.len() > 8000 || url.contains(['\r', '\n', '"']) {
        return Err("Only web and email links can be opened.".into());
    }
    std::process::Command::new("rundll32.exe")
        .args(["url.dll,FileProtocolHandler", &url])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
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
    // Run by the uninstaller: put the proxy setting back, then exit.
    if std::env::args().any(|a| a == "--restore-proxy") {
        let _ = system_proxy_off();
        return;
    }
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
            install_update,
            system_proxy_status,
            system_proxy_on,
            system_proxy_off,
            open_link
        ])
        .run(tauri::generate_context!())
        .expect("error while running Guardian Angel");
}
