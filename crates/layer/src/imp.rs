use std::collections::HashMap;
use std::ffi::CStr;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::io::IntoRawFd;
use std::sync::{Mutex, OnceLock};

use libc::{
    c_char, c_int, c_void, sockaddr, sockaddr_in, socklen_t, AF_INET, IPPROTO_TCP, SOCK_STREAM,
    SOL_SOCKET, SO_TYPE,
};

// ── Fake-IP table ──────────────────────────────────────────────────────────────
// 198.18.0.0/15 (RFC 5737 benchmarking range — not internet routable)
const FAKE_BASE: u32 = (198 << 24) | (18 << 16);
const FAKE_MASK: u32 = 0xFFFE_0000; // /15

struct FakeIpTable {
    next: u32,
    ip_to_host: HashMap<u32, String>,
}

impl FakeIpTable {
    fn new() -> Self {
        Self {
            next: 1,
            ip_to_host: HashMap::new(),
        }
    }

    fn assign(&mut self, host: &str) -> u32 {
        for (&ip, h) in &self.ip_to_host {
            if h == host {
                return ip;
            }
        }
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        let ip = FAKE_BASE | (id & 0x0001_FFFF);
        self.ip_to_host.insert(ip, host.to_string());
        ip
    }

    fn lookup(&self, ip: u32) -> Option<String> {
        if ip & FAKE_MASK == FAKE_BASE {
            self.ip_to_host.get(&ip).cloned()
        } else {
            None
        }
    }
}

static TABLE: OnceLock<Mutex<FakeIpTable>> = OnceLock::new();

fn table() -> &'static Mutex<FakeIpTable> {
    TABLE.get_or_init(|| Mutex::new(FakeIpTable::new()))
}

// ── Real function pointers (resolved once via dlsym RTLD_NEXT) ────────────────

type ConnectFn = unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int;
type GetaddrinfoFn = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const libc::addrinfo,
    *mut *mut libc::addrinfo,
) -> c_int;

static REAL_CONNECT: OnceLock<ConnectFn> = OnceLock::new();
static REAL_GETADDRINFO: OnceLock<GetaddrinfoFn> = OnceLock::new();

fn real_connect() -> ConnectFn {
    *REAL_CONNECT.get_or_init(|| unsafe {
        let ptr = libc::dlsym(libc::RTLD_NEXT, c"connect".as_ptr());
        assert!(!ptr.is_null(), "dlsym(RTLD_NEXT, connect) failed");
        std::mem::transmute(ptr)
    })
}

fn real_getaddrinfo() -> GetaddrinfoFn {
    *REAL_GETADDRINFO.get_or_init(|| unsafe {
        let ptr = libc::dlsym(libc::RTLD_NEXT, c"getaddrinfo".as_ptr());
        assert!(!ptr.is_null(), "dlsym(RTLD_NEXT, getaddrinfo) failed");
        std::mem::transmute(ptr)
    })
}

// ── getaddrinfo hook ──────────────────────────────────────────────────────────
//
// Two cases:
//   1. Real resolution succeeds → replace returned IPv4 addresses with fake IPs
//      so that the subsequent connect() can map fake IP back to hostname for SOCKS5h.
//   2. Real resolution fails (NXDOMAIN, private cloud DNS) → synthesize a fake
//      addrinfo result so the app can proceed to connect() via SOCKS5h.

#[no_mangle]
pub unsafe extern "C" fn getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> c_int {
    if node.is_null() || res.is_null() {
        return real_getaddrinfo()(node, service, hints, res);
    }

    let hostname = match CStr::from_ptr(node).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return real_getaddrinfo()(node, service, hints, res),
    };

    // Skip: loopback, empty, or already an IP address
    if hostname.is_empty()
        || hostname == "localhost"
        || hostname.starts_with("127.")
        || hostname == "::1"
        || hostname.parse::<std::net::IpAddr>().is_ok()
    {
        return real_getaddrinfo()(node, service, hints, res);
    }

    // Skip if caller only wants IPv6
    if !hints.is_null() {
        let ai_family = (*hints).ai_family;
        if ai_family != 0 && ai_family != AF_INET {
            return real_getaddrinfo()(node, service, hints, res);
        }
    }

    let real_ret = real_getaddrinfo()(node, service, hints, res);

    let fake_ip = {
        let mut tbl = table().lock().unwrap_or_else(|e| e.into_inner());
        tbl.assign(&hostname)
    };
    let fake_ip_be = fake_ip.to_be();

    if real_ret == 0 {
        // Replace all returned IPv4 addresses with our fake IP
        let mut cur = *res;
        while !cur.is_null() {
            let ai = &mut *cur;
            if ai.ai_family == AF_INET && !ai.ai_addr.is_null() {
                let sin = &mut *(ai.ai_addr as *mut sockaddr_in);
                sin.sin_addr.s_addr = fake_ip_be;
            }
            cur = ai.ai_next;
        }
        0
    } else {
        // DNS failed — synthesize a fake IPv4 result so the app reaches connect()
        // which will route it through SOCKS5h to the broker.
        let fake_ai = make_fake_addrinfo(fake_ip_be);
        if fake_ai.is_null() {
            return real_ret; // allocation failed, propagate original error
        }
        *res = fake_ai;
        0
    }
}

// Allocates an addrinfo + sockaddr_in via calloc so freeaddrinfo can free them.
unsafe fn make_fake_addrinfo(fake_ip_be: u32) -> *mut libc::addrinfo {
    let sin = libc::calloc(1, std::mem::size_of::<sockaddr_in>()) as *mut sockaddr_in;
    if sin.is_null() {
        return std::ptr::null_mut();
    }
    (*sin).sin_family = AF_INET as _;
    (*sin).sin_addr.s_addr = fake_ip_be;

    let ai = libc::calloc(1, std::mem::size_of::<libc::addrinfo>()) as *mut libc::addrinfo;
    if ai.is_null() {
        libc::free(sin as *mut c_void);
        return std::ptr::null_mut();
    }
    (*ai).ai_family = AF_INET;
    (*ai).ai_socktype = SOCK_STREAM;
    (*ai).ai_protocol = IPPROTO_TCP;
    (*ai).ai_addrlen = std::mem::size_of::<sockaddr_in>() as _;
    (*ai).ai_addr = sin as *mut sockaddr;
    ai
}

// ── connect hook ───────────────────────────────────────────────────────────────
//
// Intercepts non-loopback IPv4 TCP connect() calls:
//   - Fake IP (198.18.x.x): look up original hostname, SOCKS5h CONNECT
//   - Any other non-loopback: SOCKS5 CONNECT with the real IP

#[no_mangle]
pub unsafe extern "C" fn connect(
    sockfd: c_int,
    addr: *const sockaddr,
    addrlen: socklen_t,
) -> c_int {
    if addr.is_null() {
        return real_connect()(sockfd, addr, addrlen);
    }

    // Only intercept IPv4
    if (*addr).sa_family as c_int != AF_INET {
        return real_connect()(sockfd, addr, addrlen);
    }

    // Only intercept TCP sockets
    let mut sock_type: c_int = 0;
    let mut optlen: socklen_t = std::mem::size_of::<c_int>() as socklen_t;
    let ok = libc::getsockopt(
        sockfd,
        SOL_SOCKET,
        SO_TYPE,
        &mut sock_type as *mut c_int as *mut c_void,
        &mut optlen,
    );
    if ok != 0 || sock_type != SOCK_STREAM {
        return real_connect()(sockfd, addr, addrlen);
    }

    let sin = &*(addr as *const sockaddr_in);
    let ip = u32::from_be(sin.sin_addr.s_addr);
    let port = u16::from_be(sin.sin_port);

    // Skip loopback and wildcard
    let octet0 = (ip >> 24) & 0xFF;
    let octet1 = (ip >> 16) & 0xFF;
    if octet0 == 127 || ip == 0 || (octet0 == 169 && octet1 == 254) {
        return real_connect()(sockfd, addr, addrlen);
    }

    // Determine SOCKS5 target: hostname (for fake IPs) or dotted IP
    let target: String = match table().lock().unwrap_or_else(|e| e.into_inner()).lookup(ip) {
        Some(host) => host,
        None => format!("{}.{}.{}.{}", octet0, octet1, (ip >> 8) & 0xFF, ip & 0xFF),
    };

    // Save original socket flags so we can restore them after dup2
    let orig_flags = libc::fcntl(sockfd, libc::F_GETFL, 0);

    match socks5_connect(&target, port) {
        Ok(proxy_fd) => {
            let result = libc::dup2(proxy_fd, sockfd);
            libc::close(proxy_fd);
            if result == -1 {
                return -1;
            }
            // Restore original non-blocking flag if it was set
            if orig_flags >= 0 && orig_flags & libc::O_NONBLOCK != 0 {
                libc::fcntl(sockfd, libc::F_SETFL, orig_flags);
            }
            0
        }
        Err(_) => {
            set_errno(libc::ECONNREFUSED);
            -1
        }
    }
}

fn socks5_connect(host: &str, port: u16) -> std::io::Result<c_int> {
    let socks_port: u16 = std::env::var("DETOUR_SOCKS5_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1081);

    let mut proxy = TcpStream::connect(format!("127.0.0.1:{}", socks_port))?;

    // Greeting (no-auth)
    proxy.write_all(&[0x05, 0x01, 0x00])?;
    let mut resp = [0u8; 2];
    proxy.read_exact(&mut resp)?;
    if resp != [0x05, 0x00] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "SOCKS5 auth rejected",
        ));
    }

    // CONNECT request (ATYP=hostname)
    let hb = host.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, hb.len() as u8];
    req.extend_from_slice(hb);
    req.extend_from_slice(&port.to_be_bytes());
    proxy.write_all(&req)?;

    // Reply header (4 bytes) + BND.ADDR/PORT (depends on ATYP)
    let mut reply_hdr = [0u8; 4];
    proxy.read_exact(&mut reply_hdr)?;
    if reply_hdr[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "SOCKS5 CONNECT failed",
        ));
    }
    // Consume BND.ADDR + BND.PORT based on ATYP
    match reply_hdr[3] {
        0x01 => {
            let mut b = [0u8; 6];
            proxy.read_exact(&mut b)?;
        } // IPv4 + port
        0x03 => {
            let mut l = [0u8; 1];
            proxy.read_exact(&mut l)?;
            let mut b = vec![0u8; l[0] as usize + 2];
            proxy.read_exact(&mut b)?;
        }
        0x04 => {
            let mut b = [0u8; 18];
            proxy.read_exact(&mut b)?;
        } // IPv6 + port
        _ => {}
    }

    Ok(proxy.into_raw_fd())
}

unsafe fn set_errno(e: c_int) {
    #[cfg(target_os = "linux")]
    {
        *libc::__errno_location() = e;
    }
    #[cfg(target_os = "macos")]
    {
        *libc::__error() = e;
    }
}
