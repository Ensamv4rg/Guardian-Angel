//! The proxy: accepts `CONNECT host:port`, works out which app opened the
//! connection, and either tunnels it untouched or decrypts it, forwards each
//! request to the real server over a verified TLS connection, and decodes
//! tracker payloads on the way.

use crate::ca::CertAuthority;
use crate::rules::Rules;
use bytes::Bytes;
use ga_core::DecodedPayload;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{CONTENT_LENGTH, HOST, HeaderValue, UPGRADE};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::Serialize;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio_rustls::{TlsAcceptor, TlsConnector};

type Body = BoxBody<Bytes, hyper::Error>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Request head limit for the initial `CONNECT`.
const MAX_HEAD: usize = 16 * 1024;
/// Bodies up to this size are buffered and decoded; larger ones stream
/// through untouched.
const DEFAULT_MAX_CAPTURE: usize = 256 * 1024;
/// Bodies without a declared length are buffered up to this size.
const MAX_BUFFERED: usize = 8 * 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Path of the revocation list the proxy serves for its own certificates.
pub const CRL_PATH: &str = "/guardian-angel.crl";
/// Headers that apply to one hop only and must not be forwarded.
const HOP_BY_HOP: &[&str] = &["proxy-connection", "keep-alive", "proxy-authorization", "te", "trailer"];

/// Works out which program opened a connection: (client address, proxy address) -> exe name.
pub type AppResolver = Arc<dyn Fn(SocketAddr, SocketAddr) -> Option<String> + Send + Sync>;

/// How the proxy checks the certificates of real servers.
#[derive(Clone)]
pub enum UpstreamTrust {
    /// Windows' own certificate verification, including enterprise roots.
    Platform,
    /// A fixed set of roots (tests).
    Roots(Arc<RootCertStore>),
}

#[derive(Clone)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub upstream_trust: UpstreamTrust,
    /// Host -> address to connect to instead of resolving it (tests).
    pub connect_overrides: HashMap<String, SocketAddr>,
    pub max_capture: usize,
}

impl ProxyConfig {
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            upstream_trust: UpstreamTrust::Platform,
            connect_overrides: HashMap::new(),
            max_capture: DEFAULT_MAX_CAPTURE,
        }
    }
}

/// One decrypted request.
#[derive(Debug, Clone, Serialize)]
pub struct InspectedRequest {
    pub app: Option<String>,
    pub host: String,
    pub method: String,
    pub path: String,
    pub status: Option<u16>,
    pub request_bytes: usize,
    /// Decoded tracker data; empty when the request is not a known tracker format.
    pub payloads: Vec<DecodedPayload>,
}

#[derive(Debug, Clone, Serialize)]
pub enum ProxyEvent {
    Inspected(InspectedRequest),
    /// Passed through without decryption.
    Tunneled { app: Option<String>, host: String },
    /// The app refused our certificate; the host is now always tunnelled.
    AppRejectedInspection { app: Option<String>, host: String },
}

pub struct Proxy {
    listener: TcpListener,
    shared: Arc<Shared>,
}

struct Shared {
    ca: Arc<CertAuthority>,
    rules: Arc<RwLock<Rules>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    upstream_tls: Arc<ClientConfig>,
    server_configs: Mutex<HashMap<String, Arc<ServerConfig>>>,
    events: mpsc::Sender<ProxyEvent>,
    app_of: AppResolver,
    overrides: HashMap<String, SocketAddr>,
    max_capture: usize,
    /// Written into every leaf certificate.
    crl_url: String,
}

impl Proxy {
    pub async fn bind(
        config: ProxyConfig,
        ca: Arc<CertAuthority>,
        rules: Arc<RwLock<Rules>>,
        events: mpsc::Sender<ProxyEvent>,
        app_of: AppResolver,
    ) -> Result<Self, BoxError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()?;
        let mut upstream_tls = match config.upstream_trust {
            UpstreamTrust::Platform => {
                use rustls_platform_verifier::BuilderVerifierExt;
                builder.with_platform_verifier()?.with_no_client_auth()
            }
            UpstreamTrust::Roots(roots) => builder.with_root_certificates(roots).with_no_client_auth(),
        };
        upstream_tls.alpn_protocols = vec![b"http/1.1".to_vec()];

        let listener = TcpListener::bind(config.listen).await?;
        let crl_url = format!("http://{}{CRL_PATH}", listener.local_addr()?);
        Ok(Self {
            listener,
            shared: Arc::new(Shared {
                ca,
                rules,
                provider,
                upstream_tls: Arc::new(upstream_tls),
                server_configs: Mutex::new(HashMap::new()),
                events,
                app_of,
                overrides: config.connect_overrides,
                max_capture: config.max_capture,
                crl_url,
            }),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accepts connections until the future is dropped.
    pub async fn run(self) -> io::Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let shared = self.shared.clone();
            tokio::spawn(async move {
                let _ = shared.handle(stream, peer).await;
            });
        }
    }
}

impl Shared {
    fn emit(&self, event: ProxyEvent) {
        // Never block traffic on a slow consumer; drop events instead.
        let _ = self.events.try_send(event);
    }

    async fn handle(self: Arc<Self>, mut client: TcpStream, peer: SocketAddr) -> Result<(), BoxError> {
        let proxy_addr = client.local_addr()?;
        let (head, leftover) = read_head(&mut client).await?;
        let mut words = head.lines().next().unwrap_or("").split_whitespace();
        let (method, target) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
        // Windows fetches the revocation list for our certificates from here.
        if method.eq_ignore_ascii_case("GET") && target.ends_with(CRL_PATH) {
            let crl = self.ca.crl_der()?;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                crl.len()
            );
            client.write_all(head.as_bytes()).await?;
            client.write_all(&crl).await?;
            return Ok(());
        }
        if !method.eq_ignore_ascii_case("CONNECT") {
            client
                .write_all(b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
            return Ok(());
        }
        let Some((host, port)) = split_authority(target) else {
            client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await?;
            return Ok(());
        };

        let app = (self.app_of)(peer, proxy_addr);
        let inspect = port == 443 && read(&self.rules).should_inspect(app.as_deref(), &host);
        client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

        if inspect && leftover.is_empty() {
            self.intercept(client, app, host, port).await
        } else {
            self.emit(ProxyEvent::Tunneled { app, host: host.clone() });
            let mut upstream = self.connect(&host, port).await?;
            upstream.write_all(&leftover).await?;
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
            Ok(())
        }
    }

    async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        match self.overrides.get(host) {
            Some(addr) => TcpStream::connect(addr).await,
            None => TcpStream::connect((host, port)).await,
        }
    }

    fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, BoxError> {
        if let Some(c) = lock(&self.server_configs).get(host) {
            return Ok(c.clone());
        }
        let (chain, key) = self.ca.leaf_for(host, Some(&self.crl_url))?;
        let mut config = ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
        // HTTP/1.1 only: simpler and safer to parse; clients fall back to it.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        lock(&self.server_configs).insert(host.to_owned(), config.clone());
        Ok(config)
    }

    async fn intercept(self: Arc<Self>, client: TcpStream, app: Option<String>, host: String, port: u16) -> Result<(), BoxError> {
        let acceptor = TlsAcceptor::from(self.server_config(&host)?);
        let client_tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(client)).await {
            Ok(Ok(tls)) => tls,
            // The app does not trust our certificate (pinning or its own
            // trust list). Remember the host so its next attempt is tunnelled.
            _ => {
                write(&self.rules).learn_bypass(&host);
                self.emit(ProxyEvent::AppRejectedInspection { app, host });
                return Ok(());
            }
        };

        let upstream_tcp = self.connect(&host, port).await?;
        let name = ServerName::try_from(host.clone())?;
        let upstream_tls = TlsConnector::from(self.upstream_tls.clone()).connect(name, upstream_tcp).await?;
        let (sender, conn) = hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(upstream_tls)).await?;
        tokio::spawn(conn.with_upgrades());

        let ctx = Arc::new(ConnCtx {
            shared: self.clone(),
            sender: AsyncMutex::new(sender),
            app,
            host,
        });
        let service = hyper::service::service_fn(move |req| {
            let ctx = ctx.clone();
            async move { ctx.forward(req).await }
        });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(client_tls), service)
            .with_upgrades()
            .await?;
        Ok(())
    }
}

/// One decrypted client connection and its matching upstream connection.
struct ConnCtx {
    shared: Arc<Shared>,
    sender: AsyncMutex<hyper::client::conn::http1::SendRequest<Body>>,
    app: Option<String>,
    host: String,
}

impl ConnCtx {
    async fn forward(&self, mut req: Request<Incoming>) -> Result<Response<Body>, hyper::Error> {
        let method = req.method().to_string();
        let path = req.uri().path_and_query().map_or_else(|| "/".to_owned(), |p| p.to_string());
        let upgrade = req.headers().contains_key(UPGRADE);
        let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));

        let (mut parts, body) = req.into_parts();
        for h in HOP_BY_HOP {
            parts.headers.remove(*h);
        }
        if !upgrade {
            parts.headers.remove("connection");
        }
        if !parts.headers.contains_key(HOST)
            && let Ok(v) = HeaderValue::from_str(&self.host)
        {
            parts.headers.insert(HOST, v);
        }

        // Buffer small bodies so they can be decoded; stream large ones.
        let declared: Option<u64> = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let small = declared.is_none_or(|n| n <= self.shared.max_capture as u64);
        let (body, captured) = if small && !upgrade {
            match Limited::new(body, MAX_BUFFERED).collect().await {
                Ok(collected) => {
                    let bytes = collected.to_bytes();
                    (full(bytes.clone()), Some(bytes))
                }
                Err(_) => return Ok(simple(StatusCode::PAYLOAD_TOO_LARGE)),
            }
        } else {
            (body.boxed(), None)
        };
        let request_bytes = captured.as_ref().map_or(0, Bytes::len);

        let result = self.sender.lock().await.send_request(Request::from_parts(parts, body)).await;
        let mut response = match result {
            Ok(r) => r,
            Err(_) => return Ok(simple(StatusCode::BAD_GATEWAY)),
        };

        let text = captured.as_ref().map(|b| String::from_utf8_lossy(b).into_owned());
        let url = format!("https://{}{}", self.host, path);
        let payloads = ga_decoders::decode(&ga_decoders::Request {
            method: &method,
            url: &url,
            body: text.as_deref(),
        });
        self.shared.emit(ProxyEvent::Inspected(InspectedRequest {
            app: self.app.clone(),
            host: self.host.clone(),
            method,
            path,
            status: Some(response.status().as_u16()),
            request_bytes,
            payloads,
        }));

        // WebSocket and other upgrades: splice the two raw connections.
        if response.status() == StatusCode::SWITCHING_PROTOCOLS
            && let Some(client_upgrade) = client_upgrade
        {
            let upstream_upgrade = hyper::upgrade::on(&mut response);
            tokio::spawn(async move {
                if let (Ok(c), Ok(u)) = tokio::join!(client_upgrade, upstream_upgrade) {
                    let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(c), &mut TokioIo::new(u)).await;
                }
            });
        }

        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(parts, body.boxed()))
    }
}

fn full(bytes: Bytes) -> Body {
    Full::new(bytes).map_err(|never| match never {}).boxed()
}

fn simple(status: StatusCode) -> Response<Body> {
    let mut r = Response::new(full(Bytes::new()));
    *r.status_mut() = status;
    r
}

/// Reads the request head up to the blank line. Returns the head and any
/// bytes the client already sent after it.
async fn read_head(stream: &mut TcpStream) -> Result<(String, Vec<u8>), BoxError> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read(&mut chunk)).await??;
        if n == 0 {
            return Err("connection closed before request".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            return Ok((head, buf[end + 4..].to_vec()));
        }
        if buf.len() > MAX_HEAD {
            return Err("request head too large".into());
        }
    }
}

/// `host:443`, `[::1]:443` -> (host, port).
fn split_authority(target: &str) -> Option<(String, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty()).then(|| Some((host.to_ascii_lowercase(), port.parse().ok()?)))?
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn read<T>(m: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(|p| p.into_inner())
}

fn write<T>(m: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    m.write().unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
mod unit {
    use super::split_authority;

    #[test]
    fn parses_connect_targets() {
        assert_eq!(split_authority("Example.com:443"), Some(("example.com".into(), 443)));
        assert_eq!(split_authority("[::1]:8443"), Some(("::1".into(), 8443)));
        assert_eq!(split_authority("nohost"), None);
        assert_eq!(split_authority(":443"), None);
        assert_eq!(split_authority("x.com:notaport"), None);
    }
}
