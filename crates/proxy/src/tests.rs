//! End-to-end tests: a fake HTTPS server, the real proxy and a test client,
//! all in-process. Nothing touches the system's certificates or proxy.

use super::*;
use bytes::Bytes;
use ga_core::DataKind;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const HOST: &str = "region1.google-analytics.com";

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A stand-in for the real internet: its own CA and a server for `HOST`
/// that records requests, answers "upstream-ok" and echoes WebSocket bytes.
struct FakeUpstream {
    addr: SocketAddr,
    root: CertificateDer<'static>,
    seen: Arc<Mutex<Vec<String>>>,
}

async fn fake_upstream() -> FakeUpstream {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![HOST.to_owned()]).unwrap().signed_by(&leaf_key, &issuer).unwrap();

    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let seen = seen2.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
                    let seen = seen.clone();
                    async move {
                        if req.uri().path() == "/ws" {
                            let up = hyper::upgrade::on(&mut req);
                            tokio::spawn(async move {
                                let mut io = TokioIo::new(up.await.unwrap());
                                let mut buf = [0u8; 4];
                                io.read_exact(&mut buf).await.unwrap();
                                io.write_all(&buf).await.unwrap();
                            });
                            let mut r = Response::new(Full::new(Bytes::new()));
                            *r.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                            r.headers_mut().insert("connection", "upgrade".parse().unwrap());
                            r.headers_mut().insert("upgrade", "websocket".parse().unwrap());
                            return Ok::<_, hyper::Error>(r);
                        }
                        let line = format!("{} {}", req.method(), req.uri());
                        let body = req.into_body().collect().await?.to_bytes();
                        seen.lock().unwrap().push(format!("{line} {}", String::from_utf8_lossy(&body)));
                        Ok(Response::new(Full::new(Bytes::from_static(b"upstream-ok"))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .with_upgrades()
                    .await;
            });
        }
    });
    FakeUpstream {
        addr,
        root: ca_cert.der().clone(),
        seen,
    }
}

struct Running {
    addr: SocketAddr,
    events: mpsc::Receiver<ProxyEvent>,
    ca: Arc<CertAuthority>,
    rules: Arc<RwLock<Rules>>,
}

async fn start_proxy(up: &FakeUpstream, rules: Rules, app: &'static str) -> Running {
    let tmp = tempfile::tempdir().unwrap();
    // Created, then reloaded from disk: the reloaded CA must issue
    // certificates that chain to the saved one.
    CertAuthority::load_or_create(tmp.path()).unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(tmp.path()).unwrap());

    let mut roots = RootCertStore::empty();
    roots.add(up.root.clone()).unwrap();
    let config = ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream_trust: UpstreamTrust::Roots(Arc::new(roots)),
        connect_overrides: HashMap::from([(HOST.to_owned(), up.addr)]),
        max_capture: 256 * 1024,
    };
    let rules = Arc::new(RwLock::new(rules));
    let (tx, events) = mpsc::channel(64);
    let proxy = Proxy::bind(config, ca.clone(), rules.clone(), tx, Arc::new(move |_, _| Some(app.to_owned())))
        .await
        .unwrap();
    let addr = proxy.local_addr().unwrap();
    tokio::spawn(proxy.run());
    Running { addr, events, ca, rules }
}

/// Connects through the proxy like an app would: CONNECT, then TLS trusting `root`.
async fn connect(proxy: SocketAddr, root: &CertificateDer<'static>) -> Result<tokio_rustls::client::TlsStream<TcpStream>, std::io::Error> {
    let mut tcp = TcpStream::connect(proxy).await?;
    tcp.write_all(format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n").as_bytes()).await?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tcp.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));

    let mut roots = RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(HOST).unwrap(), tcp)
        .await
}

async fn send(
    tls: tokio_rustls::client::TlsStream<TcpStream>,
    req: Request<Full<Bytes>>,
) -> (StatusCode, String) {
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
    tokio::spawn(conn);
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn next_event(rx: &mut mpsc::Receiver<ProxyEvent>) -> ProxyEvent {
    tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("event in time").expect("channel open")
}

fn ga4_request() -> Request<Full<Bytes>> {
    Request::post("/g/collect?v=2&tid=G-TEST&cid=1234.5678&dl=https%3A%2F%2Fapp.example%2Fsettings")
        .header("host", HOST)
        .body(Full::new(Bytes::from_static(b"en=page_view")))
        .unwrap()
}

#[tokio::test]
async fn decrypts_forwards_and_decodes_opted_in_apps() {
    let up = fake_upstream().await;
    let mut p = start_proxy(&up, Rules::for_apps(["Chatty.exe"]), "chatty.exe").await;

    let tls = connect(p.addr, p.ca.cert_der()).await.expect("app trusts our CA");
    let (status, body) = send(tls, ga4_request()).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "upstream-ok"));

    // The real server got the request, body intact.
    let seen = up.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].starts_with("POST /g/collect?v=2"), "{seen:?}");
    assert!(seen[0].ends_with("en=page_view"));

    let ProxyEvent::Inspected(r) = next_event(&mut p.events).await else { panic!("expected inspection") };
    assert_eq!(r.app.as_deref(), Some("chatty.exe"));
    assert_eq!(r.host, HOST);
    assert_eq!(r.status, Some(200));
    assert_eq!(r.payloads.len(), 1);
    assert_eq!(r.payloads[0].product, "Google Analytics 4");
    assert!(r.payloads[0].kinds().contains(&DataKind::PersistentId));
}

#[tokio::test]
async fn tunnels_apps_that_are_not_opted_in() {
    let up = fake_upstream().await;
    let mut p = start_proxy(&up, Rules::for_apps(["other.exe"]), "chatty.exe").await;

    // Tunnelled untouched: the client sees the real server's certificate.
    let tls = connect(p.addr, &up.root).await.expect("real certificate passes through");
    let (status, _) = send(tls, ga4_request()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(matches!(next_event(&mut p.events).await, ProxyEvent::Tunneled { .. }));
}

#[tokio::test]
async fn learns_to_bypass_apps_that_reject_inspection() {
    let up = fake_upstream().await;
    let mut p = start_proxy(&up, Rules::everything(), "pinned.exe").await;

    // An app that only trusts the real certificate (pinning) fails once...
    assert!(connect(p.addr, &up.root).await.is_err());
    let ProxyEvent::AppRejectedInspection { app, host } = next_event(&mut p.events).await else {
        panic!("expected rejection")
    };
    assert_eq!((app.as_deref(), host.as_str()), (Some("pinned.exe"), HOST));
    assert_eq!(p.rules.read().unwrap().bypassed_hosts().collect::<Vec<_>>(), [HOST]);

    // ...and works on the retry, because the host is now tunnelled.
    let tls = connect(p.addr, &up.root).await.expect("retry is tunnelled");
    let (status, _) = send(tls, ga4_request()).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn websocket_upgrades_pass_through_inspection() {
    let up = fake_upstream().await;
    let p = start_proxy(&up, Rules::everything(), "chatty.exe").await;
    let tls = connect(p.addr, p.ca.cert_der()).await.unwrap();

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
    tokio::spawn(conn.with_upgrades());
    let req = Request::get("/ws")
        .header("host", HOST)
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);

    let mut io = TokioIo::new(hyper::upgrade::on(resp).await.unwrap());
    io.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn plain_requests_are_refused() {
    let up = fake_upstream().await;
    let p = start_proxy(&up, Rules::everything(), "x.exe").await;
    let mut tcp = TcpStream::connect(p.addr).await.unwrap();
    tcp.write_all(b"GET http://example.org/ HTTP/1.1\r\nHost: example.org\r\n\r\n").await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = tcp.read(&mut buf).await.unwrap();
    assert!(buf[..n].starts_with(b"HTTP/1.1 501"));
}

#[tokio::test]
async fn serves_a_signed_revocation_list_for_its_certificates() {
    let up = fake_upstream().await;
    let p = start_proxy(&up, Rules::everything(), "x.exe").await;
    let mut tcp = TcpStream::connect(p.addr).await.unwrap();
    let request = format!("GET http://{0}/guardian-angel.crl HTTP/1.1\r\nHost: {0}\r\n\r\n", p.addr);
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.contains("application/pkix-crl"));
    let body = &buf[buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..];
    // A DER-encoded revocation list starts with a SEQUENCE tag.
    assert_eq!(body[0], 0x30);
}

#[test]
fn ca_is_saved_and_reloaded() {
    let tmp = tempfile::tempdir().unwrap();
    let first = CertAuthority::load_or_create(tmp.path()).unwrap();
    let second = CertAuthority::load_or_create(tmp.path()).unwrap();
    assert_eq!(first.cert_der(), second.cert_der());
    let fresh = CertAuthority::load_or_create(tempfile::tempdir().unwrap().path()).unwrap();
    assert_ne!(first.cert_der(), fresh.cert_der(), "every install gets its own CA");
}
