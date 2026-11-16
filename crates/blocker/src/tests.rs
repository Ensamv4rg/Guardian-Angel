//! End-to-end tests: the real resolver on a local port, talking to a fake
//! upstream DNS server, so no traffic leaves the machine.

use super::*;
use ga_knowledge::TrackerDb;
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;

const UPSTREAM_ANSWER: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

/// A fake upstream that answers every A query with `UPSTREAM_ANSWER`, or
/// never answers when `silent`.
async fn fake_upstream(silent: bool) -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((len, peer)) = sock.recv_from(&mut buf).await else { continue };
            if silent {
                continue;
            }
            let q = Message::from_vec(&buf[..len]).unwrap();
            let mut r = Message::response(q.metadata.id, q.metadata.op_code);
            r.add_queries(q.queries.iter().cloned());
            r.add_answer(Record::from_rdata(q.queries[0].name().clone(), 300, RData::A(A(UPSTREAM_ANSWER))));
            sock.send_to(&r.to_vec().unwrap(), peer).await.unwrap();
        }
    });
    addr
}

/// Starts the resolver and returns its address and stats.
async fn start(profile: Profile, upstream: SocketAddr) -> (SocketAddr, Arc<std::sync::Mutex<BlockStats>>) {
    let blocker = DnsBlocker::bind(
        ResolverConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstreams: vec![upstream],
            upstream_timeout: Duration::from_millis(300),
        },
        Arc::new(TrackerDb::bundled().unwrap()),
        Arc::new(RwLock::new(Policy::new(profile))),
    )
    .await
    .unwrap();
    let addr = blocker.local_addr().unwrap();
    let stats = blocker.stats();
    tokio::spawn(blocker.run());
    (addr, stats)
}

/// Sends one query and waits up to a second for the reply.
async fn ask(server: SocketAddr, name: &str, rtype: RecordType, id: u16) -> Option<Message> {
    let mut q = Message::query();
    q.metadata.id = id;
    q.metadata.recursion_desired = true;
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    ask_raw(server, &q.to_vec().unwrap()).await
}

async fn ask_raw(server: SocketAddr, packet: &[u8]) -> Option<Message> {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(packet, server).await.unwrap();
    let mut buf = [0u8; 4096];
    let len = tokio::time::timeout(Duration::from_secs(1), sock.recv(&mut buf)).await.ok()?.ok()?;
    Some(Message::from_vec(&buf[..len]).unwrap())
}

fn first_ip(m: &Message) -> Option<String> {
    m.answers.first().map(|r| match &r.data {
        RData::A(a) => a.0.to_string(),
        RData::AAAA(a) => a.0.to_string(),
        other => format!("{other:?}"),
    })
}

#[tokio::test]
async fn blocks_trackers_with_null_answers() {
    let (server, stats) = start(Profile::Balanced, fake_upstream(false).await).await;

    let a = ask(server, "stats.g.doubleclick.net.", RecordType::A, 7).await.unwrap();
    assert_eq!(a.metadata.id, 7);
    assert_eq!(a.metadata.message_type, MessageType::Response);
    assert_eq!(a.metadata.response_code, ResponseCode::NoError);
    assert_eq!(first_ip(&a).as_deref(), Some("0.0.0.0"));

    let aaaa = ask(server, "www.google-analytics.com.", RecordType::AAAA, 8).await.unwrap();
    assert_eq!(first_ip(&aaaa).as_deref(), Some("::"));

    // Other record types for a blocked name: empty answer, not an error.
    let txt = ask(server, "doubleclick.net.", RecordType::TXT, 9).await.unwrap();
    assert_eq!(txt.metadata.response_code, ResponseCode::NoError);
    assert!(txt.answers.is_empty());

    let s = stats.lock().unwrap().clone();
    assert_eq!((s.queries, s.blocked), (3, 3));
    assert_eq!(s.blocked_by_company.get("Google"), Some(&3));
}

#[tokio::test]
async fn forwards_everything_else_unchanged() {
    let (server, stats) = start(Profile::Balanced, fake_upstream(false).await).await;

    let r = ask(server, "example.org.", RecordType::A, 4242).await.unwrap();
    assert_eq!(r.metadata.id, 4242);
    assert_eq!(first_ip(&r).as_deref(), Some("93.184.216.34"));

    // A tracker outside the profile is forwarded too (social in Balanced).
    let social = ask(server, "connect.facebook.com.", RecordType::A, 5).await.unwrap();
    assert_eq!(first_ip(&social).as_deref(), Some("93.184.216.34"));

    // Protected domains always resolve.
    let wu = ask(server, "ctldl.windowsupdate.com.", RecordType::A, 6).await.unwrap();
    assert_eq!(first_ip(&wu).as_deref(), Some("93.184.216.34"));

    assert_eq!(stats.lock().unwrap().blocked, 0);
}

#[tokio::test]
async fn unreachable_upstream_returns_servfail() {
    let (server, stats) = start(Profile::Balanced, fake_upstream(true).await).await;
    let r = ask(server, "example.org.", RecordType::A, 11).await.unwrap();
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(r.metadata.id, 11);
    assert_eq!(stats.lock().unwrap().upstream_failures, 1);
}

#[tokio::test]
async fn malformed_packets_get_no_reply_and_do_not_stop_the_server() {
    let (server, _) = start(Profile::Balanced, fake_upstream(false).await).await;
    assert!(ask_raw(server, b"\x00\x01garbage").await.is_none());
    assert!(ask_raw(server, b"").await.is_none());
    // Still serving afterwards.
    assert!(ask(server, "example.org.", RecordType::A, 1).await.is_some());
}

#[tokio::test]
async fn policy_changes_apply_without_restart() {
    let policy = Arc::new(RwLock::new(Policy::new(Profile::Balanced)));
    let blocker = DnsBlocker::bind(
        ResolverConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            upstreams: vec![fake_upstream(false).await],
            upstream_timeout: Duration::from_millis(300),
        },
        Arc::new(TrackerDb::bundled().unwrap()),
        policy.clone(),
    )
    .await
    .unwrap();
    let server = blocker.local_addr().unwrap();
    tokio::spawn(blocker.run());

    let before = ask(server, "doubleclick.net.", RecordType::A, 1).await.unwrap();
    assert_eq!(first_ip(&before).as_deref(), Some("0.0.0.0"));

    policy.write().unwrap().allow("doubleclick.net");
    let after = ask(server, "doubleclick.net.", RecordType::A, 2).await.unwrap();
    assert_eq!(first_ip(&after).as_deref(), Some("93.184.216.34"));
}
