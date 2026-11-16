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

fn main() {
    tauri::Builder::default()
        .manage(Connection::default())
        .invoke_handler(tauri::generate_handler![ipc])
        .run(tauri::generate_context!())
        .expect("error while running Guardian Angel");
}
