//! Native macOS socket inspection.
//!
//! `eslogger` has no TCP/IP `connect` event, so sogar asks the kernel
//! directly which IPv4/IPv6 sockets a process holds: `proc_pidinfo` with
//! `PROC_PIDLISTFDS` enumerates file descriptors, and `proc_pidfdinfo` with
//! `PROC_PIDFDSOCKETINFO` describes each `PROX_FDTYPE_SOCKET` descriptor
//! (see `<sys/proc_info.h>`). Snapshots are taken when a network-capable
//! binary is executed or a critical file is touched.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::Serialize;

use crate::lineage::basename;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        }
    }
}

/// One IPv4/IPv6 socket held by a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SocketConnection {
    pub protocol: Transport,
    pub fd: i32,
    /// `addr:port` (IPv6 as `[addr]:port`).
    pub local: String,
    /// Peer `addr:port`; absent for listening or unconnected sockets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    /// TCP state (`ESTABLISHED`, `SYN_SENT`, `LISTEN`, ...); absent for UDP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<&'static str>,
}

impl SocketConnection {
    fn same_socket(&self, other: &Self) -> bool {
        self.protocol == other.protocol && self.local == other.local && self.remote == other.remote
    }
}

/// Executables that commonly open network connections on an agent's behalf.
pub fn is_network_binary(path: &str) -> bool {
    let name = basename(path);
    matches!(
        name,
        "curl" | "wget" | "nc" | "ncat" | "ssh" | "scp" | "sftp" | "node" | "deno" | "bun"
            | "ruby" | "php" | "git" | "gh"
    ) || name.starts_with("python")
}

/// Adds sockets from a later snapshot, updating the state of ones already seen.
pub fn merge(into: &mut Vec<SocketConnection>, later: Vec<SocketConnection>) {
    for conn in later {
        match into.iter_mut().find(|c| c.same_socket(&conn)) {
            Some(existing) => existing.state = conn.state,
            None => into.push(conn),
        }
    }
}

fn tcp_state_name(state: i32) -> &'static str {
    const NAMES: [&str; 12] = [
        "CLOSED",
        "LISTEN",
        "SYN_SENT",
        "SYN_RECEIVED",
        "ESTABLISHED",
        "CLOSE_WAIT",
        "FIN_WAIT_1",
        "CLOSING",
        "LAST_ACK",
        "FIN_WAIT_2",
        "TIME_WAIT",
        "RESERVED",
    ];
    usize::try_from(state)
        .ok()
        .and_then(|i| NAMES.get(i).copied())
        .unwrap_or("UNKNOWN")
}

/// Decodes an `in4in6_addr`/`in6_addr` union plus a network-order port.
fn socket_addr(vflag: u8, raw: &[u32; 4], port: i32) -> Option<SocketAddr> {
    const INI_IPV4: u8 = 0x1;
    const INI_IPV6: u8 = 0x2;
    let mut bytes = [0u8; 16];
    for (i, word) in raw.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
    }
    // A dual-stack IPv6 socket talking IPv4 reports INI_IPV4.
    let ip = if vflag & INI_IPV4 != 0 {
        IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
    } else if vflag & INI_IPV6 != 0 {
        IpAddr::V6(Ipv6Addr::from(bytes))
    } else {
        return None;
    };
    // The kernel stores ports in network byte order in an `int`.
    Some(SocketAddr::new(ip, u16::from_be(port as u16)))
}

/// All IPv4/IPv6 TCP and UDP sockets currently held by `pid`. Returns an
/// empty list when the process is gone or cannot be inspected.
pub fn inspect_pid(pid: u32) -> Vec<SocketConnection> {
    sys::inspect_pid(pid)
}

#[cfg(target_os = "macos")]
mod sys {
    //! `#[repr(C)]` mirrors of `<sys/proc_info.h>`; sizes and offsets are
    //! checked at compile time against the macOS SDK's layout.
    #![allow(dead_code)] // fields exist to reproduce the C layout

    use std::mem::{offset_of, size_of};

    use super::{socket_addr, tcp_state_name, SocketConnection, Transport};

    const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
    const SOCKINFO_IN: i32 = 1;
    const SOCKINFO_TCP: i32 = 2;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcFileInfo {
        fi_openflags: u32,
        fi_status: u32,
        fi_offset: i64,
        fi_type: i32,
        fi_guardflags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct VinfoStat {
        vst_dev: u32,
        vst_mode: u16,
        vst_nlink: u16,
        vst_ino: u64,
        vst_uid: u32,
        vst_gid: u32,
        vst_times: [i64; 8],
        vst_size: i64,
        vst_blocks: i64,
        vst_blksize: i32,
        vst_flags: u32,
        vst_gen: u32,
        vst_rdev: u32,
        vst_qspare: [i64; 2],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockbufInfo {
        sbi_cc: u32,
        sbi_hiwat: u32,
        sbi_mbcnt: u32,
        sbi_mbmax: u32,
        sbi_lowat: u32,
        sbi_flags: i16,
        sbi_timeo: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct InSockV6 {
        in6_hlim: u8,
        in6_cksum: i32,
        in6_ifindex: u16,
        in6_hops: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct InSockinfo {
        pub(super) insi_fport: i32,
        pub(super) insi_lport: i32,
        insi_gencnt: u64,
        insi_flags: u32,
        insi_flow: u32,
        pub(super) insi_vflag: u8,
        insi_ip_ttl: u8,
        rfu_1: u32,
        /// `in4in6_addr` / `in6_addr` union (16 bytes, 4-byte aligned).
        pub(super) insi_faddr: [u32; 4],
        pub(super) insi_laddr: [u32; 4],
        insi_v4_tos: u8,
        insi_v6: InSockV6,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct TcpSockinfo {
        pub(super) tcpsi_ini: InSockinfo,
        pub(super) tcpsi_state: i32,
        tcpsi_timer: [i32; 4],
        tcpsi_mss: i32,
        tcpsi_flags: u32,
        rfu_1: u32,
        tcpsi_tp: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) union SocketProto {
        pub(super) pri_in: InSockinfo,
        pub(super) pri_tcp: TcpSockinfo,
        /// Largest member is `un_sockinfo` (526 bytes, padded to 528).
        _size: [u64; 66],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct SocketInfo {
        soi_stat: VinfoStat,
        soi_so: u64,
        soi_pcb: u64,
        pub(super) soi_type: i32,
        soi_protocol: i32,
        pub(super) soi_family: i32,
        soi_options: i16,
        soi_linger: i16,
        soi_state: i16,
        soi_qlen: i16,
        soi_incqlen: i16,
        soi_qlimit: i16,
        soi_timeo: i16,
        soi_error: u16,
        soi_oobmark: u32,
        soi_rcv: SockbufInfo,
        soi_snd: SockbufInfo,
        pub(super) soi_kind: i32,
        rfu_1: u32,
        pub(super) soi_proto: SocketProto,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SocketFdInfo {
        pfi: ProcFileInfo,
        psi: SocketInfo,
    }

    // Values measured from the macOS SDK with a C probe (sizeof / offsetof).
    const _: () = assert!(size_of::<ProcFileInfo>() == 24);
    const _: () = assert!(size_of::<VinfoStat>() == 136);
    const _: () = assert!(size_of::<InSockinfo>() == 80);
    const _: () = assert!(offset_of!(InSockinfo, insi_vflag) == 24);
    const _: () = assert!(offset_of!(InSockinfo, insi_faddr) == 32);
    const _: () = assert!(offset_of!(InSockinfo, insi_laddr) == 48);
    const _: () = assert!(size_of::<TcpSockinfo>() == 120);
    const _: () = assert!(offset_of!(TcpSockinfo, tcpsi_state) == 80);
    const _: () = assert!(offset_of!(SocketInfo, soi_family) == 160);
    const _: () = assert!(offset_of!(SocketInfo, soi_kind) == 232);
    const _: () = assert!(offset_of!(SocketInfo, soi_proto) == 240);
    const _: () = assert!(size_of::<SocketInfo>() == 768);
    const _: () = assert!(offset_of!(SocketFdInfo, psi) == 24);
    const _: () = assert!(size_of::<SocketFdInfo>() == 792);

    pub(super) fn decode(psi: &SocketInfo, fd: i32) -> Option<SocketConnection> {
        if psi.soi_family != libc::AF_INET && psi.soi_family != libc::AF_INET6 {
            return None;
        }
        // SAFETY: `soi_kind` selects the active union member, as in lsof/netstat.
        let (ini, protocol, state) = match psi.soi_kind {
            SOCKINFO_TCP => {
                let tcp = unsafe { psi.soi_proto.pri_tcp };
                (tcp.tcpsi_ini, Transport::Tcp, Some(tcp_state_name(tcp.tcpsi_state)))
            }
            SOCKINFO_IN if psi.soi_type == libc::SOCK_DGRAM => {
                (unsafe { psi.soi_proto.pri_in }, Transport::Udp, None)
            }
            _ => return None,
        };
        let local = socket_addr(ini.insi_vflag, &ini.insi_laddr, ini.insi_lport)?;
        let remote = socket_addr(ini.insi_vflag, &ini.insi_faddr, ini.insi_fport)
            .filter(|addr| !(addr.ip().is_unspecified() && addr.port() == 0));
        Some(SocketConnection {
            protocol,
            fd,
            local: local.to_string(),
            remote: remote.map(|a| a.to_string()),
            state,
        })
    }

    fn socket_fds(pid: libc::c_int) -> Vec<i32> {
        let entry = size_of::<libc::proc_fdinfo>();
        // SAFETY: a null buffer asks the kernel for the required size.
        let needed = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
        };
        let Ok(needed) = usize::try_from(needed) else {
            return Vec::new();
        };
        if needed == 0 {
            return Vec::new();
        }
        // Headroom for descriptors opened between the two calls.
        let capacity = needed / entry + 32;
        let empty = libc::proc_fdinfo { proc_fd: 0, proc_fdtype: 0 };
        let mut fds = vec![empty; capacity];
        let Ok(buffer_size) = libc::c_int::try_from(capacity * entry) else {
            return Vec::new();
        };
        // SAFETY: `fds` is valid for `buffer_size` bytes.
        let written = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), buffer_size)
        };
        let Ok(written) = usize::try_from(written) else {
            return Vec::new();
        };
        fds.truncate((written / entry).min(capacity));
        fds.into_iter()
            .filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32)
            .map(|f| f.proc_fd)
            .collect()
    }

    pub(super) fn inspect_pid(pid: u32) -> Vec<SocketConnection> {
        let Ok(pid) = libc::c_int::try_from(pid) else {
            return Vec::new();
        };
        if pid <= 0 {
            return Vec::new();
        }
        let size = size_of::<SocketFdInfo>() as libc::c_int;
        socket_fds(pid)
            .into_iter()
            .filter_map(|fd| {
                // SAFETY: SocketFdInfo is plain old data matching the C layout.
                let mut info: SocketFdInfo = unsafe { std::mem::zeroed() };
                let ret = unsafe {
                    libc::proc_pidfdinfo(
                        pid,
                        fd,
                        PROC_PIDFDSOCKETINFO,
                        (&mut info as *mut SocketFdInfo).cast(),
                        size,
                    )
                };
                if ret == size {
                    decode(&info.psi, fd)
                } else {
                    None
                }
            })
            .collect()
    }

    #[cfg(test)]
    pub(super) fn zeroed_socket_info() -> SocketInfo {
        // SAFETY: all-zero is a valid value for this plain-old-data struct.
        unsafe { std::mem::zeroed() }
    }
}

#[cfg(not(target_os = "macos"))]
mod sys {
    pub(super) fn inspect_pid(_pid: u32) -> Vec<super::SocketConnection> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_network_binaries() {
        for path in [
            "/usr/bin/curl",
            "/opt/homebrew/bin/wget",
            "/usr/bin/nc",
            "/usr/bin/ssh",
            "/usr/bin/scp",
            "/usr/bin/python3",
            "/opt/homebrew/bin/python3.12",
            "/opt/homebrew/bin/node",
            "/opt/homebrew/bin/bun",
            "/usr/bin/git",
            "/opt/homebrew/bin/gh",
        ] {
            assert!(is_network_binary(path), "{path}");
        }
        for path in ["/bin/cat", "/bin/ls", "/usr/bin/sshd-keygen-wrapper", "/usr/bin/github-ish"] {
            assert!(!is_network_binary(path), "{path}");
        }
    }

    #[test]
    fn decodes_addresses_in_network_byte_order() {
        let v4 = |a: [u8; 4]| [0, 0, 0, u32::from_ne_bytes(a)];
        let port = |p: u16| i32::from(p.to_be());
        let addr = socket_addr(0x1, &v4([93, 184, 216, 34]), port(443)).expect("v4");
        assert_eq!(addr.to_string(), "93.184.216.34:443");

        let mut raw = [0u32; 4];
        raw[3] = u32::from_ne_bytes([0, 0, 0, 1]);
        let addr = socket_addr(0x2, &raw, port(8080)).expect("v6");
        assert_eq!(addr.to_string(), "[::1]:8080");

        assert!(socket_addr(0, &raw, 0).is_none());
        assert_eq!(tcp_state_name(4), "ESTABLISHED");
        assert_eq!(tcp_state_name(99), "UNKNOWN");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn decodes_kernel_socket_records() {
        let mut psi = sys::zeroed_socket_info();
        psi.soi_family = libc::AF_INET;
        psi.soi_type = libc::SOCK_STREAM;
        psi.soi_kind = 2; // SOCKINFO_TCP
        let mut tcp = unsafe { psi.soi_proto.pri_tcp };
        tcp.tcpsi_state = 2; // SYN_SENT
        tcp.tcpsi_ini.insi_vflag = 0x1;
        tcp.tcpsi_ini.insi_laddr[3] = u32::from_ne_bytes([192, 168, 1, 20]);
        tcp.tcpsi_ini.insi_lport = i32::from(51000u16.to_be());
        tcp.tcpsi_ini.insi_faddr[3] = u32::from_ne_bytes([1, 2, 3, 4]);
        tcp.tcpsi_ini.insi_fport = i32::from(443u16.to_be());
        psi.soi_proto.pri_tcp = tcp;
        assert_eq!(
            sys::decode(&psi, 7),
            Some(SocketConnection {
                protocol: Transport::Tcp,
                fd: 7,
                local: "192.168.1.20:51000".into(),
                remote: Some("1.2.3.4:443".into()),
                state: Some("SYN_SENT"),
            })
        );

        // Unix-domain sockets are not network connections.
        psi.soi_family = libc::AF_UNIX;
        assert_eq!(sys::decode(&psi, 7), None);
    }

    #[test]
    fn inspects_this_process_live_sockets() {
        use std::net::{TcpListener, TcpStream, UdpSocket};

        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let server_addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(server_addr).expect("connect");
        let client_addr = client.local_addr().expect("addr");
        let _accepted = listener.accept().expect("accept");
        let udp = UdpSocket::bind("127.0.0.1:0").expect("udp");
        udp.connect("127.0.0.1:9").expect("udp connect");

        let conns = inspect_pid(std::process::id());
        if !cfg!(target_os = "macos") {
            assert!(conns.is_empty());
            return;
        }
        assert!(
            conns.iter().any(|c| c.protocol == Transport::Tcp
                && c.local == client_addr.to_string()
                && c.remote.as_deref() == Some(server_addr.to_string().as_str())
                && c.state == Some("ESTABLISHED")),
            "{conns:#?}"
        );
        assert!(
            conns.iter().any(|c| c.protocol == Transport::Tcp
                && c.local == server_addr.to_string()
                && c.remote.is_none()
                && c.state == Some("LISTEN")),
            "{conns:#?}"
        );
        assert!(
            conns.iter().any(|c| c.protocol == Transport::Udp
                && c.remote.as_deref() == Some("127.0.0.1:9")),
            "{conns:#?}"
        );
        assert!(inspect_pid(0).is_empty());
    }

    #[test]
    fn merge_updates_state_and_appends_new_sockets() {
        let conn = |remote: &str, state| SocketConnection {
            protocol: Transport::Tcp,
            fd: 3,
            local: "10.0.0.2:50000".into(),
            remote: Some(remote.into()),
            state: Some(state),
        };
        let mut seen = vec![conn("1.1.1.1:443", "SYN_SENT")];
        merge(&mut seen, vec![conn("1.1.1.1:443", "ESTABLISHED"), conn("8.8.8.8:53", "ESTABLISHED")]);
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].state, Some("ESTABLISHED"));
    }
}
