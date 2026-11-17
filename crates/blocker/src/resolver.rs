//! A small forwarding DNS resolver that answers blocked names itself.
//!
//! Blocked A/AAAA queries get `0.0.0.0` / `::` (the "null route" used by
//! Pi-hole and AdGuard: the request fails fast instead of timing out); other
//! record types for blocked names get an empty answer. Everything else is
//! forwarded unchanged to the upstream servers Windows already uses, and the
//! upstream reply is relayed back byte for byte.

use crate::policy::{Decision, Policy};
use ga_knowledge::TrackerDb;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use std::collections::BTreeMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

/// TTL on blocked answers, so a newly allowed domain works within a minute.
const BLOCKED_TTL: u32 = 60;
/// Queries handled at once. Beyond this, packets are dropped and the client
/// retries, which keeps memory bounded under a flood.
const MAX_IN_FLIGHT: usize = 256;
/// Largest DNS message over UDP with EDNS.
const MAX_PACKET: usize = 4096;

#[derive(Debug, Clone)]
pub struct ResolverConfig {
    pub listen: SocketAddr,
    /// Tried in order until one answers.
    pub upstreams: Vec<SocketAddr>,
    pub upstream_timeout: Duration,
}

/// Running totals since the resolver started.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockStats {
    pub queries: u64,
    pub blocked: u64,
    pub blocked_by_company: BTreeMap<String, u64>,
    /// Allowed queries no upstream answered in time.
    pub upstream_failures: u64,
}

pub struct DnsBlocker {
    sockets: Vec<Arc<UdpSocket>>,
    shared: Arc<Shared>,
}

struct Shared {
    db: Arc<TrackerDb>,
    policy: Arc<RwLock<Policy>>,
    stats: Arc<Mutex<BlockStats>>,
    upstreams: RwLock<Vec<SocketAddr>>,
    /// The resolver's own addresses, never used as upstreams.
    own: Mutex<Vec<SocketAddr>>,
    timeout: Duration,
}

/// Changes a running resolver: where it forwards, and its statistics.
#[derive(Clone)]
pub struct ResolverControl(Arc<Shared>);

impl ResolverControl {
    /// Replaces the upstream servers, e.g. after joining another network.
    pub fn set_upstreams(&self, upstreams: Vec<SocketAddr>) {
        let own = lock(&self.0.own).clone();
        *self.0.upstreams.write().unwrap_or_else(|p| p.into_inner()) =
            upstreams.into_iter().filter(|u| !own.contains(u)).collect();
    }

    pub fn upstreams(&self) -> Vec<SocketAddr> {
        read(&self.0.upstreams).clone()
    }

    pub fn stats(&self) -> BlockStats {
        lock(&self.0.stats).clone()
    }
}

impl DnsBlocker {
    pub async fn bind(config: ResolverConfig, db: Arc<TrackerDb>, policy: Arc<RwLock<Policy>>) -> io::Result<Self> {
        let socket = UdpSocket::bind(config.listen).await?;
        let local = socket.local_addr()?;
        let shared = Arc::new(Shared {
            db,
            policy,
            stats: Arc::default(),
            upstreams: RwLock::default(),
            own: Mutex::new(vec![local]),
            timeout: config.upstream_timeout,
        });
        // Never forward to ourselves (that would loop forever).
        ResolverControl(shared.clone()).set_upstreams(config.upstreams);
        Ok(Self {
            sockets: vec![Arc::new(socket)],
            shared,
        })
    }

    /// Answers on one more address as well (for example `[::1]:53` next to
    /// `127.0.0.1:53`), with the same policy and statistics.
    pub async fn also_listen(&mut self, addr: SocketAddr) -> io::Result<SocketAddr> {
        let socket = UdpSocket::bind(addr).await?;
        let local = socket.local_addr()?;
        lock(&self.shared.own).push(local);
        self.sockets.push(Arc::new(socket));
        Ok(local)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sockets[0].local_addr()
    }

    /// Live statistics; readable while `run` is going.
    pub fn stats(&self) -> Arc<Mutex<BlockStats>> {
        self.shared.stats.clone()
    }

    pub fn control(&self) -> ResolverControl {
        ResolverControl(self.shared.clone())
    }

    /// Serves queries until the future is dropped or a socket fails.
    pub async fn run(self) -> io::Result<()> {
        let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
        let mut loops = tokio::task::JoinSet::new();
        for socket in self.sockets {
            loops.spawn(serve(socket, self.shared.clone(), permits.clone()));
        }
        // The first loop to end (with an error) ends the resolver; dropping
        // the set stops the others.
        match loops.join_next().await {
            Some(Ok(result)) => result,
            Some(Err(e)) => Err(io::Error::other(e)),
            None => Ok(()),
        }
    }
}

async fn serve(socket: Arc<UdpSocket>, shared: Arc<Shared>, permits: Arc<Semaphore>) -> io::Result<()> {
    let mut buf = vec![0u8; MAX_PACKET];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            // Windows reports ICMP "port unreachable" from an earlier send
            // as an error on the next receive; it is not fatal.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
            Err(e) => return Err(e),
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
        let packet = buf[..len].to_vec();
        let socket = socket.clone();
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Some(reply) = shared.handle(&packet).await {
                let _ = socket.send_to(&reply, peer).await;
            }
            drop(permit);
        });
    }
}

/// Asks `server` for the A record of `name` and reports whether it gave a
/// normal answer in time. Used to check that blocking has not broken DNS.
pub async fn probe(server: SocketAddr, name: &str, timeout: Duration) -> bool {
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    let Ok(name) = Name::from_ascii(name) else { return false };
    let mut query = Message::query();
    query.metadata.id = rand_id();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(name, RecordType::A));
    let Ok(packet) = query.to_vec() else { return false };
    let bind: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let attempt = async {
        let sock = UdpSocket::bind(bind).await.ok()?;
        sock.connect(server).await.ok()?;
        sock.send(&packet).await.ok()?;
        let mut buf = vec![0u8; MAX_PACKET];
        loop {
            let len = sock.recv(&mut buf).await.ok()?;
            if let Ok(reply) = Message::from_vec(&buf[..len])
                && reply.metadata.id == query.metadata.id
            {
                return Some(reply.metadata.response_code == ResponseCode::NoError);
            }
        }
    };
    matches!(tokio::time::timeout(timeout, attempt).await, Ok(Some(true)))
}

fn rand_id() -> u16 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
    h.finish() as u16
}

impl Shared {
    /// The reply to send, or `None` to stay silent (malformed input).
    async fn handle(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let query = Message::from_vec(packet).ok()?;
        if query.metadata.message_type != MessageType::Query {
            return None;
        }
        lock(&self.stats).queries += 1;

        // Only plain single-question queries are inspected; anything unusual
        // is passed through untouched.
        if let [question] = query.queries.as_slice() {
            let name = question.name().to_ascii();
            let decision = read(&self.policy).decide(&self.db, &name, unix_now());
            if let Decision::Block { company, .. } = decision {
                let mut stats = lock(&self.stats);
                stats.blocked += 1;
                *stats.blocked_by_company.entry(company).or_default() += 1;
                drop(stats);
                return blocked_reply(&query);
            }
        }

        match self.forward(packet).await {
            Some(reply) => Some(reply),
            None => {
                lock(&self.stats).upstream_failures += 1;
                error_reply(&query, ResponseCode::ServFail)
            }
        }
    }

    /// Sends the query to each upstream in turn and returns the first reply
    /// whose transaction ID matches.
    async fn forward(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let id = packet.get(..2)?;
        let upstreams = read(&self.upstreams).clone();
        for upstream in &upstreams {
            let bind: SocketAddr = if upstream.is_ipv4() {
                (Ipv4Addr::UNSPECIFIED, 0).into()
            } else {
                (Ipv6Addr::UNSPECIFIED, 0).into()
            };
            let Ok(sock) = UdpSocket::bind(bind).await else { continue };
            if sock.connect(upstream).await.is_err() || sock.send(packet).await.is_err() {
                continue;
            }
            let mut buf = vec![0u8; MAX_PACKET];
            let deadline = tokio::time::Instant::now() + self.timeout;
            // Ignore stray packets with the wrong ID until the deadline.
            while let Ok(Ok(len)) = tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
                if buf.get(..2) == Some(id) {
                    buf.truncate(len);
                    return Some(buf);
                }
            }
        }
        None
    }
}

fn blocked_reply(query: &Message) -> Option<Vec<u8>> {
    let question = query.queries.first()?;
    let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.metadata.recursion_available = true;
    reply.add_query(question.clone());
    let rdata = match question.query_type() {
        RecordType::A => Some(RData::A(A(Ipv4Addr::UNSPECIFIED))),
        RecordType::AAAA => Some(RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))),
        // HTTPS, TXT, etc.: an empty answer ("no data").
        _ => None,
    };
    if let Some(rdata) = rdata {
        reply.add_answer(Record::from_rdata(question.name().clone(), BLOCKED_TTL, rdata));
    }
    reply.to_vec().ok()
}

fn error_reply(query: &Message, code: ResponseCode) -> Option<Vec<u8>> {
    let mut reply = Message::error_msg(query.metadata.id, query.metadata.op_code, code);
    reply.metadata.recursion_desired = query.metadata.recursion_desired;
    reply.metadata.recursion_available = true;
    reply.add_queries(query.queries.iter().cloned());
    reply.to_vec().ok()
}

/// A panic elsewhere must not stop DNS for the whole machine.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

fn read<T>(m: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(|p| p.into_inner())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
