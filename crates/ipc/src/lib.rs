//! Protocol between the Guardian Angel service and its clients.
//!
//! Newline-delimited JSON over a named pipe: each request is
//! `{"id":1,"method":"overview"}` (plus `"params"` when the method takes
//! any), each response `{"id":1,"result":...}` or `{"id":1,"error":"..."}`.
//! The server loop and client work over any byte stream, so they are tested
//! in memory.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::future::Future;
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};

/// The service's pipe. Only signed-in local users can connect.
pub const PIPE_NAME: &str = r"\\.\pipe\guardian-angel";
/// Requests are small; anything longer is refused.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Responses (a full overview) can be large.
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum Request {
    /// Service version, uptime and component health.
    Status,
    /// Everything known about the calling user: trackers, apps, extensions,
    /// settings, network.
    Overview,
    /// Start a fresh scan in the background.
    ScanNow,
    Alerts,
    MarkAlertsRead,
    /// Privacy settings that can be fixed, with what would change.
    Fixes,
    ApplyFix {
        setting_id: String,
    },
    /// Changes Guardian Angel made that are still in effect.
    Changes,
    Undo {
        id: String,
    },
    UndoAll,
    ProxyStatus,
    /// Apps (executable names) whose traffic the proxy may decrypt.
    ProxySetApps {
        apps: Vec<String>,
    },
    /// Recent decrypted requests with decoded tracker data.
    ProxyEvents,
    /// The inspection certificate (PEM) so the user can choose to trust it.
    ProxyExportCa,
    /// Programs running for the calling user, to pick for inspection.
    RunningApps,
    /// Read every file of one installed app (by name), without the size
    /// limits of the normal scan. Runs in the background like `ScanNow`.
    ScanAppFully {
        name: String,
    },
    /// Delete tracking cookies from closed browsers. Cookies of social
    /// networks and big platforms (which sign you out) only when asked;
    /// tracking cookies sites set under their own name (Google Analytics'
    /// `_ga`) unless `site_trackers` is false.
    DeleteTrackerCookies {
        include_social: bool,
        site_trackers: bool,
    },
    /// Machine-wide tracker blocking (DNS).
    BlockingStatus,
    /// The network adapters turning blocking on would change.
    BlockingPreview,
    /// `profile`: "relaxed", "balanced" or "strict".
    BlockingEnable {
        profile: String,
    },
    BlockingDisable,
    BlockingSetProfile {
        profile: String,
    },
    BlockingPause {
        minutes: u32,
    },
    BlockingResume,
    /// Never block this domain (`allow: true`) or take it off that list.
    BlockingAllow {
        domain: String,
        allow: bool,
    },
    /// What trackers received from this user's apps and browsers, by
    /// company and site, with choices and data requests.
    TrackerActivity,
    /// Decrypt connections from every app to known tracking companies (only
    /// those). Machine-wide; needs the certificate and proxy set up.
    SetWatchTrackers {
        on: bool,
    },
    /// The user said no to tracking on this site (`refused: false` forgets it).
    SetSiteChoice {
        site: String,
        refused: bool,
    },
    /// The user sent (`sent: true`) or withdrew a data request.
    SetDataRequest {
        company: String,
        kind: String,
        sent: bool,
    },
    /// Name, email and region for data request letters.
    SetRequester {
        name: String,
        email: String,
        region: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub id: u64,
    #[serde(flatten)]
    pub request: Request,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("connection to the Guardian Angel service failed: {0}")]
    Io(#[from] io::Error),
    #[error("the service sent an invalid response: {0}")]
    Protocol(String),
    #[error("{0}")]
    Service(String),
}

/// Serves one client connection until it closes. `handler` answers each
/// request; its error text is sent back to the client.
pub async fn serve<S, F, Fut>(stream: S, handler: F) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn(Request) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = BufReader::new(read);
    let mut line = String::new();
    loop {
        line.clear();
        let n = (&mut reader).take(MAX_REQUEST_BYTES as u64 + 1).read_line(&mut line).await?;
        if n == 0 {
            return Ok(());
        }
        if n > MAX_REQUEST_BYTES {
            send(&mut write, &error(0, "request too large")).await?;
            return Ok(());
        }
        let response = match serde_json::from_str::<RequestEnvelope>(line.trim()) {
            Ok(env) => match handler(env.request).await {
                Ok(result) => ResponseEnvelope {
                    id: env.id,
                    result: Some(result),
                    error: None,
                },
                Err(e) => error(env.id, &e),
            },
            Err(_) => error(id_of(&line), "unknown or malformed request"),
        };
        send(&mut write, &response).await?;
    }
}

fn error(id: u64, message: &str) -> ResponseEnvelope {
    ResponseEnvelope {
        id,
        result: None,
        error: Some(message.to_owned()),
    }
}

/// Best effort: echo the request ID even when the rest is invalid.
fn id_of(line: &str) -> u64 {
    serde_json::from_str::<Value>(line.trim())
        .ok()
        .and_then(|v| v.get("id")?.as_u64())
        .unwrap_or(0)
}

async fn send<W: AsyncWrite + Unpin>(w: &mut W, response: &ResponseEnvelope) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(response).map_err(io::Error::other)?;
    bytes.push(b'\n');
    w.write_all(&bytes).await?;
    w.flush().await
}

/// A connection to the service.
pub struct Client<S> {
    reader: BufReader<ReadHalf<S>>,
    writer: WriteHalf<S>,
    next_id: u64,
}

impl<S: AsyncRead + AsyncWrite> Client<S> {
    pub fn new(stream: S) -> Self {
        let (read, writer) = tokio::io::split(stream);
        Self {
            reader: BufReader::new(read),
            writer,
            next_id: 1,
        }
    }

    /// Sends one request and waits for its response.
    pub async fn call(&mut self, request: Request) -> Result<Value, IpcError> {
        let id = self.next_id;
        self.next_id += 1;
        let mut bytes = serde_json::to_vec(&RequestEnvelope { id, request }).map_err(io::Error::other)?;
        bytes.push(b'\n');
        self.writer.write_all(&bytes).await?;
        self.writer.flush().await?;

        let mut line = String::new();
        let n = (&mut self.reader).take(MAX_RESPONSE_BYTES as u64).read_line(&mut line).await?;
        if n == 0 {
            return Err(IpcError::Io(io::ErrorKind::UnexpectedEof.into()));
        }
        let response: ResponseEnvelope =
            serde_json::from_str(line.trim()).map_err(|e| IpcError::Protocol(e.to_string()))?;
        if response.id != id {
            return Err(IpcError::Protocol(format!("expected response {id}, got {}", response.id)));
        }
        // A `null` result reads back as `None`; only an error field is a failure.
        match response.error {
            Some(e) => Err(IpcError::Service(e)),
            None => Ok(response.result.unwrap_or(Value::Null)),
        }
    }
}

/// Connects to the service pipe, waiting briefly if every instance is busy.
#[cfg(windows)]
pub async fn connect() -> Result<Client<tokio::net::windows::named_pipe::NamedPipeClient>, IpcError> {
    use tokio::net::windows::named_pipe::ClientOptions;
    const ERROR_PIPE_BUSY: i32 = 231;
    for _ in 0..50 {
        match ClientOptions::new().open(PIPE_NAME) {
            Ok(pipe) => return Ok(Client::new(pipe)),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(IpcError::Io(io::Error::other("the service is busy")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn handler(req: Request) -> Result<Value, String> {
        match req {
            Request::Status => Ok(json!({"version": "test"})),
            Request::ApplyFix { setting_id } if setting_id == "advertising_id" => Ok(json!({"applied": setting_id})),
            Request::ApplyFix { .. } => Err("unknown setting".into()),
            _ => Ok(Value::Null),
        }
    }

    #[test]
    fn wire_format_is_stable() {
        let env = RequestEnvelope {
            id: 3,
            request: Request::ApplyFix {
                setting_id: "location".into(),
            },
        };
        assert_eq!(
            serde_json::to_string(&env).unwrap(),
            r#"{"id":3,"method":"apply_fix","params":{"setting_id":"location"}}"#
        );
        let plain: RequestEnvelope = serde_json::from_str(r#"{"id":1,"method":"overview"}"#).unwrap();
        assert_eq!(plain.request, Request::Overview);
    }

    #[tokio::test]
    async fn client_and_server_round_trip() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        tokio::spawn(serve(b, handler));
        let mut client = Client::new(a);

        assert_eq!(client.call(Request::Status).await.unwrap(), json!({"version": "test"}));
        let ok = client
            .call(Request::ApplyFix {
                setting_id: "advertising_id".into(),
            })
            .await
            .unwrap();
        assert_eq!(ok["applied"], "advertising_id");
        let err = client.call(Request::ApplyFix { setting_id: "nope".into() }).await.unwrap_err();
        assert_eq!(err.to_string(), "unknown setting");
        // The connection keeps working after an error.
        assert!(client.call(Request::Overview).await.is_ok());
    }

    #[tokio::test]
    async fn malformed_and_oversized_requests_are_refused() {
        let (mut a, b) = tokio::io::duplex(256 * 1024);
        tokio::spawn(serve(b, handler));
        let mut reader = BufReader::new(&mut a);

        reader.get_mut().write_all(b"{\"id\":9,\"method\":\"format_disk\"}\n").await.unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let r: ResponseEnvelope = serde_json::from_str(&line).unwrap();
        assert_eq!((r.id, r.error.as_deref()), (9, Some("unknown or malformed request")));

        let big = format!("{{\"id\":1,\"method\":\"status\",\"pad\":\"{}\"}}\n", "x".repeat(MAX_REQUEST_BYTES));
        reader.get_mut().write_all(big.as_bytes()).await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        assert!(line.contains("request too large"));
    }
}
