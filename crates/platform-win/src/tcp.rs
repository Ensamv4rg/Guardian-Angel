use std::mem::{offset_of, size_of};
use std::net::{Ipv4Addr, SocketAddrV4};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_CONNECTIONS,
};
use windows::Win32::Networking::WinSock::AF_INET;

const NO_ERROR: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// Process ID that owns the IPv4 TCP connection from `local` to `remote`.
///
/// Used to tell which program opened a connection to the local proxy: from
/// the proxy's side, `local` is the client's address and `remote` is the
/// proxy's own listening address.
pub fn tcp_connection_owner(local: SocketAddrV4, remote: SocketAddrV4) -> Option<u32> {
    tcp_table()?
        .iter()
        .find(|r| endpoint(r.dwLocalAddr, r.dwLocalPort) == local && endpoint(r.dwRemoteAddr, r.dwRemotePort) == remote)
        .map(|r| r.dwOwningPid)
}

/// Addresses are stored in network byte order in memory; ports in the low
/// 16 bits, also network byte order.
fn endpoint(addr: u32, port: u32) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::from(addr.to_ne_bytes()), u16::from_be(port as u16))
}

/// All IPv4 TCP connections with their owning process IDs.
fn tcp_table() -> Option<Vec<MIB_TCPROW_OWNER_PID>> {
    let mut size: u32 = 16 * 1024;
    // The table can grow between the size query and the read; retry a few times.
    for _ in 0..4 {
        // u64 storage gives 8-byte alignment, more than the table needs.
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let mut len = (buf.len() * 8) as u32;
        // SAFETY: `buf` is writable for `len` bytes and outlives the call;
        // `len` points to a live u32 the API updates with the needed size.
        let rc = unsafe {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr().cast()),
                &mut len,
                false,
                u32::from(AF_INET.0),
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        if rc == ERROR_INSUFFICIENT_BUFFER {
            size = len + 4 * 1024;
            continue;
        }
        if rc != NO_ERROR {
            return None;
        }

        let table = buf.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
        // SAFETY: on success the buffer starts with a MIB_TCPTABLE_OWNER_PID
        // header; reading its first field stays within the buffer.
        let count = unsafe { (*table).dwNumEntries } as usize;
        let rows_offset = offset_of!(MIB_TCPTABLE_OWNER_PID, table);
        let needed = rows_offset.checked_add(count.checked_mul(size_of::<MIB_TCPROW_OWNER_PID>())?)?;
        if needed > buf.len() * 8 {
            return None;
        }
        // SAFETY: the check above shows `count` rows fit inside `buf` after
        // the header; rows are plain integers, valid for any bit pattern, and
        // correctly aligned within the 8-byte-aligned buffer.
        let rows = unsafe {
            let first = table.cast::<u8>().add(rows_offset).cast::<MIB_TCPROW_OWNER_PID>();
            std::slice::from_raw_parts(first, count).to_vec()
        };
        return Some(rows);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::tcp_connection_owner;
    use std::net::{SocketAddr, TcpListener, TcpStream};

    #[test]
    fn finds_owner_of_own_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let server = listener.local_addr().unwrap();
        let client = TcpStream::connect(server).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        let (SocketAddr::V4(local), SocketAddr::V4(remote)) = (client.local_addr().unwrap(), server) else {
            panic!("expected IPv4");
        };
        assert_eq!(tcp_connection_owner(local, remote), Some(std::process::id()));
        // Reversed direction is a different connection row (also ours, the
        // accepted side), but an unrelated port is not found.
        let mut other = remote;
        other.set_port(1);
        assert_eq!(tcp_connection_owner(local, other), None);
    }
}
