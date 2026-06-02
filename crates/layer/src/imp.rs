use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::{Ipv6Addr, TcpStream};
use std::os::unix::io::IntoRawFd;
use std::sync::{Mutex, OnceLock};

use libc::{
    c_char, c_int, c_void, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_un, socklen_t, AF_INET,
    AF_INET6, AF_UNIX, IPPROTO_TCP, SOCK_STREAM, SOL_SOCKET, SO_TYPE,
};

fn bypassed_host(host: &str) -> bool {
    std::env::var("DETOUR_BYPASS_HOSTS")
        .ok()
        .into_iter()
        .flat_map(|v| {
            v.split(',')
                .map(str::trim)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .any(|pattern| {
            !pattern.is_empty()
                && if let Some(suffix) = pattern.strip_prefix("*.") {
                    host == suffix || host.ends_with(&format!(".{}", suffix))
                } else {
                    host == pattern
                }
        })
}

fn bypassed_port(port: u16) -> bool {
    std::env::var("DETOUR_BYPASS_PORTS")
        .ok()
        .into_iter()
        .flat_map(|v| {
            v.split(',')
                .map(str::trim)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter_map(|port| port.parse::<u16>().ok())
        .any(|bypass| bypass == port)
}

fn should_passthrough_hostname(hostname: &str) -> bool {
    hostname.is_empty()
        || hostname == "localhost"
        || hostname.starts_with("127.")
        || hostname == "::1"
        || bypassed_host(hostname)
        || hostname.parse::<std::net::IpAddr>().is_ok()
}

fn parse_target_host_port(value: &str) -> Option<(String, u16)> {
    if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':')?.parse().ok()?;
        return Some((host.to_string(), port));
    }

    let colon = value.rfind(':')?;
    let host = value[..colon].trim();
    let port = value[colon + 1..].trim().parse().ok()?;
    if host.is_empty() {
        None
    } else {
        Some((host.to_string(), port))
    }
}

fn unix_socket_target(path: &str) -> Option<(String, u16)> {
    std::env::var("DETOUR_UNIX_SOCKET_MAPS")
        .ok()
        .into_iter()
        .flat_map(|v| {
            v.split(';')
                .map(str::trim)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .filter_map(|entry| {
            let equals = entry.find('=')?;
            let prefix = entry[..equals].trim().to_string();
            let target = parse_target_host_port(entry[equals + 1..].trim())?;
            Some((prefix, target))
        })
        .find_map(|(prefix, target)| {
            if prefix.is_empty() {
                return None;
            }

            if path == prefix
                || path
                    .strip_prefix(&prefix)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
            {
                Some(target)
            } else {
                None
            }
        })
}

unsafe fn unix_socket_path(addr: *const sockaddr, addrlen: socklen_t) -> Option<String> {
    if addr.is_null() || (*addr).sa_family as c_int != AF_UNIX {
        return None;
    }

    let addrlen = usize::try_from(addrlen).ok()?;
    let base = std::mem::size_of_val(&(*(addr as *const sockaddr_un)).sun_family);
    if addrlen <= base {
        return None;
    }

    let sun = &*(addr as *const sockaddr_un);
    let path_bytes = std::slice::from_raw_parts(
        sun.sun_path.as_ptr() as *const u8,
        std::mem::size_of_val(&sun.sun_path),
    );
    if path_bytes.first().copied() == Some(0) {
        return None;
    }

    let len = path_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(path_bytes.len());
    std::str::from_utf8(&path_bytes[..len])
        .ok()
        .map(str::to_string)
}

// ── Fake-IP table ──────────────────────────────────────────────────────────────
// 198.18.0.0/15 and 2001:db8::/96 are documentation/benchmarking ranges that
// should never be internet-routable. We map hostnames into both families so a
// client that prefers IPv6 still reaches the outbound tunnel.
const FAKE_V4_BASE: u32 = (198 << 24) | (18 << 16);
const FAKE_V4_MASK: u32 = 0xFFFE_0000; // /15
const FAKE_V6_PREFIX: [u8; 12] = [0x20, 0x01, 0x0d, 0xb8, 0xde, 0x70, 0, 0, 0, 0, 0, 0];

struct FakeIpTable {
    next: u32,
    host_to_id: HashMap<String, u32>,
    id_to_host: HashMap<u32, String>,
}

impl FakeIpTable {
    fn new() -> Self {
        Self {
            next: 1,
            host_to_id: HashMap::new(),
            id_to_host: HashMap::new(),
        }
    }

    fn assign(&mut self, host: &str) -> u32 {
        if let Some(&id) = self.host_to_id.get(host) {
            return id;
        }

        let id = self.next;
        self.next = self.next.wrapping_add(1);
        self.host_to_id.insert(host.to_string(), id);
        self.id_to_host.insert(id, host.to_string());
        id
    }

    fn lookup_v4(&self, ip: u32) -> Option<String> {
        if ip & FAKE_V4_MASK == FAKE_V4_BASE {
            let id = ip & 0x0001_FFFF;
            self.id_to_host.get(&id).cloned()
        } else {
            None
        }
    }

    fn lookup_v6(&self, ip: [u8; 16]) -> Option<String> {
        if ip[..12] == FAKE_V6_PREFIX {
            let id = u32::from_be_bytes(ip[12..16].try_into().ok()?);
            self.id_to_host.get(&id).cloned()
        } else {
            None
        }
    }
}

static TABLE: OnceLock<Mutex<FakeIpTable>> = OnceLock::new();

fn table() -> &'static Mutex<FakeIpTable> {
    TABLE.get_or_init(|| Mutex::new(FakeIpTable::new()))
}

struct FakeHostentState {
    hostent: libc::hostent,
    name: CString,
    aliases: [*mut c_char; 1],
    addr_list: [*mut c_char; 2],
    addr_v4: [u8; 4],
    addr_v6: [u8; 16],
}

impl FakeHostentState {
    fn new() -> Self {
        Self {
            hostent: libc::hostent {
                h_name: std::ptr::null_mut(),
                h_aliases: std::ptr::null_mut(),
                h_addrtype: AF_INET,
                h_length: 0,
                h_addr_list: std::ptr::null_mut(),
            },
            name: CString::new("detour.invalid").expect("static CString"),
            aliases: [std::ptr::null_mut()],
            addr_list: [std::ptr::null_mut(), std::ptr::null_mut()],
            addr_v4: [0; 4],
            addr_v6: [0; 16],
        }
    }

    fn populate(
        &mut self,
        hostname: &str,
        family: c_int,
        fake_id: u32,
    ) -> Option<*mut libc::hostent> {
        self.name = CString::new(hostname).ok()?;
        self.hostent.h_name = self.name.as_ptr() as *mut c_char;
        self.hostent.h_aliases = self.aliases.as_mut_ptr();
        self.addr_list[1] = std::ptr::null_mut();

        match family {
            AF_INET => {
                self.addr_v4 = fake_ipv4(fake_id).to_be_bytes();
                self.addr_list[0] = self.addr_v4.as_mut_ptr() as *mut c_char;
                self.hostent.h_addrtype = AF_INET;
                self.hostent.h_length = self.addr_v4.len() as c_int;
            }
            AF_INET6 => {
                self.addr_v6 = fake_ipv6(fake_id);
                self.addr_list[0] = self.addr_v6.as_mut_ptr() as *mut c_char;
                self.hostent.h_addrtype = AF_INET6;
                self.hostent.h_length = self.addr_v6.len() as c_int;
            }
            _ => return None,
        }

        self.hostent.h_addr_list = self.addr_list.as_mut_ptr();
        Some(&mut self.hostent)
    }
}

thread_local! {
    static HOSTENT_STATE: RefCell<FakeHostentState> = RefCell::new(FakeHostentState::new());
}

fn fake_ipv4(id: u32) -> u32 {
    FAKE_V4_BASE | (id & 0x0001_FFFF)
}

fn fake_ipv6(id: u32) -> [u8; 16] {
    let mut ip = [0u8; 16];
    ip[..12].copy_from_slice(&FAKE_V6_PREFIX);
    ip[12..16].copy_from_slice(&id.to_be_bytes());
    ip
}

unsafe fn hinted_socktype(hints: *const libc::addrinfo) -> c_int {
    if !hints.is_null() && (*hints).ai_socktype != 0 {
        (*hints).ai_socktype
    } else {
        SOCK_STREAM
    }
}

unsafe fn hinted_protocol(hints: *const libc::addrinfo) -> c_int {
    if !hints.is_null() && (*hints).ai_protocol != 0 {
        (*hints).ai_protocol
    } else {
        IPPROTO_TCP
    }
}

unsafe fn requested_family(hints: *const libc::addrinfo) -> c_int {
    if hints.is_null() {
        0
    } else {
        (*hints).ai_family
    }
}

unsafe fn service_port(service: *const c_char) -> u16 {
    if service.is_null() {
        return 0;
    }

    let Some(service_str) = CStr::from_ptr(service).to_str().ok() else {
        return 0;
    };

    if let Ok(port) = service_str.parse::<u16>() {
        return port;
    }

    let ent = libc::getservbyname(service, c"tcp".as_ptr());
    if ent.is_null() {
        0
    } else {
        u16::from_be((*ent).s_port as u16)
    }
}

// ── Real function pointers (resolved once via dlsym RTLD_NEXT) ────────────────

type ConnectFn = unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int;
type GetaddrinfoFn = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const libc::addrinfo,
    *mut *mut libc::addrinfo,
) -> c_int;
type GetHostByNameFn = unsafe extern "C" fn(*const c_char) -> *mut libc::hostent;
type GetHostByName2Fn = unsafe extern "C" fn(*const c_char, c_int) -> *mut libc::hostent;
#[cfg(target_os = "linux")]
type GetHostByNameRFn = unsafe extern "C" fn(
    *const c_char,
    *mut libc::hostent,
    *mut c_char,
    libc::size_t,
    *mut *mut libc::hostent,
    *mut c_int,
) -> c_int;
#[cfg(target_os = "linux")]
type GetHostByName2RFn = unsafe extern "C" fn(
    *const c_char,
    c_int,
    *mut libc::hostent,
    *mut c_char,
    libc::size_t,
    *mut *mut libc::hostent,
    *mut c_int,
) -> c_int;
#[cfg(target_os = "macos")]
type ConnectxFn = unsafe extern "C" fn(
    c_int,
    *const libc::sa_endpoints_t,
    libc::sae_associd_t,
    libc::c_uint,
    *const libc::iovec,
    libc::c_uint,
    *mut libc::size_t,
    *mut libc::sae_connid_t,
) -> c_int;

static REAL_CONNECT: OnceLock<ConnectFn> = OnceLock::new();
static REAL_GETADDRINFO: OnceLock<GetaddrinfoFn> = OnceLock::new();
static REAL_GETHOSTBYNAME: OnceLock<GetHostByNameFn> = OnceLock::new();
static REAL_GETHOSTBYNAME2: OnceLock<GetHostByName2Fn> = OnceLock::new();
#[cfg(target_os = "linux")]
static REAL_GETHOSTBYNAME_R: OnceLock<GetHostByNameRFn> = OnceLock::new();
#[cfg(target_os = "linux")]
static REAL_GETHOSTBYNAME2_R: OnceLock<GetHostByName2RFn> = OnceLock::new();
#[cfg(target_os = "macos")]
static REAL_CONNECTX: OnceLock<ConnectxFn> = OnceLock::new();

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

fn real_gethostbyname() -> GetHostByNameFn {
    *REAL_GETHOSTBYNAME.get_or_init(|| unsafe {
        let ptr = libc::dlsym(libc::RTLD_NEXT, c"gethostbyname".as_ptr());
        assert!(!ptr.is_null(), "dlsym(RTLD_NEXT, gethostbyname) failed");
        std::mem::transmute(ptr)
    })
}

fn real_gethostbyname2() -> GetHostByName2Fn {
    *REAL_GETHOSTBYNAME2.get_or_init(|| unsafe {
        let ptr = libc::dlsym(libc::RTLD_NEXT, c"gethostbyname2".as_ptr());
        assert!(!ptr.is_null(), "dlsym(RTLD_NEXT, gethostbyname2) failed");
        std::mem::transmute(ptr)
    })
}

#[cfg(target_os = "linux")]
fn real_gethostbyname_r() -> GetHostByNameRFn {
    *REAL_GETHOSTBYNAME_R.get_or_init(|| unsafe {
        let ptr = libc::dlsym(libc::RTLD_NEXT, c"gethostbyname_r".as_ptr());
        assert!(!ptr.is_null(), "dlsym(RTLD_NEXT, gethostbyname_r) failed");
        std::mem::transmute(ptr)
    })
}

#[cfg(target_os = "linux")]
fn real_gethostbyname2_r() -> GetHostByName2RFn {
    *REAL_GETHOSTBYNAME2_R.get_or_init(|| unsafe {
        let ptr = libc::dlsym(libc::RTLD_NEXT, c"gethostbyname2_r".as_ptr());
        assert!(!ptr.is_null(), "dlsym(RTLD_NEXT, gethostbyname2_r) failed");
        std::mem::transmute(ptr)
    })
}

#[cfg(target_os = "macos")]
fn real_connectx() -> ConnectxFn {
    *REAL_CONNECTX.get_or_init(|| unsafe {
        let ptr = libc::dlsym(libc::RTLD_NEXT, c"connectx".as_ptr());
        assert!(!ptr.is_null(), "dlsym(RTLD_NEXT, connectx) failed");
        std::mem::transmute(ptr)
    })
}

unsafe fn fake_hostent_for(hostname: &str, family: c_int) -> *mut libc::hostent {
    let fake_id = {
        let mut tbl = table().lock().unwrap_or_else(|e| e.into_inner());
        tbl.assign(hostname)
    };

    HOSTENT_STATE.with(|state| {
        state
            .borrow_mut()
            .populate(hostname, family, fake_id)
            .unwrap_or(std::ptr::null_mut())
    })
}

#[cfg(target_os = "linux")]
unsafe fn write_buffer_value<T: Copy>(
    buf: *mut c_char,
    buflen: usize,
    offset: &mut usize,
    value: T,
) -> Option<*mut T> {
    let align = std::mem::align_of::<T>();
    let size = std::mem::size_of::<T>();
    let start = (*offset + align - 1) & !(align - 1);
    let end = start.checked_add(size)?;
    if end > buflen {
        return None;
    }

    let ptr = buf.add(start) as *mut T;
    ptr.write(value);
    *offset = end;
    Some(ptr)
}

#[cfg(target_os = "linux")]
unsafe fn write_buffer_slice<T: Copy>(
    buf: *mut c_char,
    buflen: usize,
    offset: &mut usize,
    values: &[T],
) -> Option<*mut T> {
    let align = std::mem::align_of::<T>();
    let size = std::mem::size_of::<T>().checked_mul(values.len())?;
    let start = (*offset + align - 1) & !(align - 1);
    let end = start.checked_add(size)?;
    if end > buflen {
        return None;
    }

    let ptr = buf.add(start) as *mut T;
    std::ptr::copy_nonoverlapping(values.as_ptr(), ptr, values.len());
    *offset = end;
    Some(ptr)
}

// POSIX h_errno values from netdb.h. The libc crate does not expose these on
// every target, so define them with their standard values.
#[cfg(target_os = "linux")]
const H_TRY_AGAIN: c_int = 2;
#[cfg(target_os = "linux")]
const H_NO_RECOVERY: c_int = 3;

#[cfg(target_os = "linux")]
unsafe fn fill_fake_hostent_result(
    hostname: &str,
    family: c_int,
    ret: *mut libc::hostent,
    buf: *mut c_char,
    buflen: usize,
    result: *mut *mut libc::hostent,
    h_errnop: *mut c_int,
) -> c_int {
    if ret.is_null() || buf.is_null() {
        if !result.is_null() {
            *result = std::ptr::null_mut();
        }
        if !h_errnop.is_null() {
            *h_errnop = H_NO_RECOVERY;
        }
        return libc::EINVAL;
    }

    let fake_id = {
        let mut tbl = table().lock().unwrap_or_else(|e| e.into_inner());
        tbl.assign(hostname)
    };

    let addr_storage_v4;
    let addr_storage_v6;
    let addr_bytes: &[u8] = match family {
        AF_INET => {
            addr_storage_v4 = fake_ipv4(fake_id).to_be_bytes();
            &addr_storage_v4
        }
        AF_INET6 => {
            addr_storage_v6 = fake_ipv6(fake_id);
            &addr_storage_v6
        }
        _ => {
            if !result.is_null() {
                *result = std::ptr::null_mut();
            }
            if !h_errnop.is_null() {
                *h_errnop = H_NO_RECOVERY;
            }
            return libc::EINVAL;
        }
    };

    let mut offset = 0usize;
    let name_ptr = match write_buffer_slice(buf, buflen, &mut offset, hostname.as_bytes()) {
        Some(ptr) => ptr,
        None => {
            if !result.is_null() {
                *result = std::ptr::null_mut();
            }
            if !h_errnop.is_null() {
                *h_errnop = H_TRY_AGAIN;
            }
            return libc::ERANGE;
        }
    };
    if write_buffer_value(buf, buflen, &mut offset, 0u8).is_none() {
        if !result.is_null() {
            *result = std::ptr::null_mut();
        }
        if !h_errnop.is_null() {
            *h_errnop = H_TRY_AGAIN;
        }
        return libc::ERANGE;
    }

    let addr_ptr = match write_buffer_slice(buf, buflen, &mut offset, addr_bytes) {
        Some(ptr) => ptr,
        None => {
            if !result.is_null() {
                *result = std::ptr::null_mut();
            }
            if !h_errnop.is_null() {
                *h_errnop = H_TRY_AGAIN;
            }
            return libc::ERANGE;
        }
    };

    let aliases = [std::ptr::null_mut::<c_char>()];
    let aliases_ptr = match write_buffer_slice(buf, buflen, &mut offset, &aliases) {
        Some(ptr) => ptr,
        None => {
            if !result.is_null() {
                *result = std::ptr::null_mut();
            }
            if !h_errnop.is_null() {
                *h_errnop = H_TRY_AGAIN;
            }
            return libc::ERANGE;
        }
    };

    let addr_list = [addr_ptr as *mut c_char, std::ptr::null_mut()];
    let addr_list_ptr = match write_buffer_slice(buf, buflen, &mut offset, &addr_list) {
        Some(ptr) => ptr,
        None => {
            if !result.is_null() {
                *result = std::ptr::null_mut();
            }
            if !h_errnop.is_null() {
                *h_errnop = H_TRY_AGAIN;
            }
            return libc::ERANGE;
        }
    };

    *ret = libc::hostent {
        h_name: name_ptr as *mut c_char,
        h_aliases: aliases_ptr,
        h_addrtype: family,
        h_length: addr_bytes.len() as c_int,
        h_addr_list: addr_list_ptr,
    };

    if !result.is_null() {
        *result = ret;
    }
    if !h_errnop.is_null() {
        *h_errnop = 0;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn gethostbyname(name: *const c_char) -> *mut libc::hostent {
    if name.is_null() {
        return real_gethostbyname()(name);
    }

    let hostname = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return real_gethostbyname()(name),
    };

    if should_passthrough_hostname(hostname) {
        return real_gethostbyname()(name);
    }

    let _ = real_gethostbyname()(name);
    fake_hostent_for(hostname, AF_INET)
}

#[no_mangle]
pub unsafe extern "C" fn gethostbyname2(name: *const c_char, af: c_int) -> *mut libc::hostent {
    if name.is_null() {
        return real_gethostbyname2()(name, af);
    }

    if af != AF_INET && af != AF_INET6 {
        return real_gethostbyname2()(name, af);
    }

    let hostname = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return real_gethostbyname2()(name, af),
    };

    if should_passthrough_hostname(hostname) {
        return real_gethostbyname2()(name, af);
    }

    let _ = real_gethostbyname2()(name, af);
    fake_hostent_for(hostname, af)
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn gethostbyname_r(
    name: *const c_char,
    ret: *mut libc::hostent,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::hostent,
    h_errnop: *mut c_int,
) -> c_int {
    if name.is_null() {
        return real_gethostbyname_r()(name, ret, buf, buflen, result, h_errnop);
    }

    let hostname = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return real_gethostbyname_r()(name, ret, buf, buflen, result, h_errnop),
    };

    if should_passthrough_hostname(hostname) {
        return real_gethostbyname_r()(name, ret, buf, buflen, result, h_errnop);
    }

    let _ = real_gethostbyname_r()(name, ret, buf, buflen, result, h_errnop);
    fill_fake_hostent_result(hostname, AF_INET, ret, buf, buflen, result, h_errnop)
}

#[cfg(target_os = "linux")]
#[no_mangle]
pub unsafe extern "C" fn gethostbyname2_r(
    name: *const c_char,
    af: c_int,
    ret: *mut libc::hostent,
    buf: *mut c_char,
    buflen: libc::size_t,
    result: *mut *mut libc::hostent,
    h_errnop: *mut c_int,
) -> c_int {
    if name.is_null() {
        return real_gethostbyname2_r()(name, af, ret, buf, buflen, result, h_errnop);
    }

    if af != AF_INET && af != AF_INET6 {
        return real_gethostbyname2_r()(name, af, ret, buf, buflen, result, h_errnop);
    }

    let hostname = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return real_gethostbyname2_r()(name, af, ret, buf, buflen, result, h_errnop),
    };

    if should_passthrough_hostname(hostname) {
        return real_gethostbyname2_r()(name, af, ret, buf, buflen, result, h_errnop);
    }

    let _ = real_gethostbyname2_r()(name, af, ret, buf, buflen, result, h_errnop);
    fill_fake_hostent_result(hostname, af, ret, buf, buflen, result, h_errnop)
}

#[cfg(target_os = "macos")]
#[no_mangle]
pub unsafe extern "C" fn connectx(
    socket: c_int,
    endpoints: *const libc::sa_endpoints_t,
    associd: libc::sae_associd_t,
    flags: libc::c_uint,
    iov: *const libc::iovec,
    iovcnt: libc::c_uint,
    len: *mut libc::size_t,
    connid: *mut libc::sae_connid_t,
) -> c_int {
    if endpoints.is_null() {
        return real_connectx()(socket, endpoints, associd, flags, iov, iovcnt, len, connid);
    }

    let endpoints_ref = &*endpoints;
    let simple_connect = associd == 0
        && flags == 0
        && endpoints_ref.sae_srcif == 0
        && endpoints_ref.sae_srcaddr.is_null()
        && !endpoints_ref.sae_dstaddr.is_null()
        && endpoints_ref.sae_dstaddrlen > 0
        && (iov.is_null() || iovcnt == 0);

    if !simple_connect {
        return real_connectx()(socket, endpoints, associd, flags, iov, iovcnt, len, connid);
    }

    let rc = connect(
        socket,
        endpoints_ref.sae_dstaddr,
        endpoints_ref.sae_dstaddrlen,
    );
    if rc == 0 {
        if !len.is_null() {
            *len = 0;
        }
        if !connid.is_null() {
            *connid = 0;
        }
    }
    rc
}

// ── getaddrinfo hook ──────────────────────────────────────────────────────────
//
// Two cases:
//   1. Real resolution succeeds → replace returned IPs with fake IPs so that the
//      subsequent connect() can map them back to the original hostname.
//   2. Real resolution fails (NXDOMAIN, private cloud DNS) → synthesize fake
//      addrinfo results so the app can still proceed to connect() via SOCKS5h.

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

    if should_passthrough_hostname(&hostname) {
        return real_getaddrinfo()(node, service, hints, res);
    }

    let ai_family = requested_family(hints);
    if ai_family != 0 && ai_family != AF_INET && ai_family != AF_INET6 {
        return real_getaddrinfo()(node, service, hints, res);
    }

    let real_ret = real_getaddrinfo()(node, service, hints, res);

    let fake_id = {
        let mut tbl = table().lock().unwrap_or_else(|e| e.into_inner());
        tbl.assign(&hostname)
    };
    let fake_v4_be = fake_ipv4(fake_id).to_be();
    let fake_v6 = fake_ipv6(fake_id);

    if real_ret == 0 {
        // Replace all returned IPs with fake addresses that carry the hostname.
        let mut cur = *res;
        while !cur.is_null() {
            let ai = &mut *cur;
            if ai.ai_family == AF_INET && !ai.ai_addr.is_null() {
                let sin = &mut *(ai.ai_addr as *mut sockaddr_in);
                sin.sin_addr.s_addr = fake_v4_be;
            } else if ai.ai_family == AF_INET6 && !ai.ai_addr.is_null() {
                let sin6 = &mut *(ai.ai_addr as *mut sockaddr_in6);
                sin6.sin6_addr.s6_addr = fake_v6;
            }
            cur = ai.ai_next;
        }
        0
    } else {
        let fake_ai =
            make_fake_addrinfo_list(hints, ai_family, service_port(service), fake_v4_be, fake_v6);
        if fake_ai.is_null() {
            return real_ret; // allocation failed, propagate original error
        }
        *res = fake_ai;
        0
    }
}

// Allocates addrinfo nodes via calloc so freeaddrinfo can free them.
unsafe fn make_fake_addrinfo_list(
    hints: *const libc::addrinfo,
    ai_family: c_int,
    port: u16,
    fake_v4_be: u32,
    fake_v6: [u8; 16],
) -> *mut libc::addrinfo {
    match ai_family {
        AF_INET => make_fake_addrinfo_v4(hints, port, fake_v4_be),
        AF_INET6 => make_fake_addrinfo_v6(hints, port, fake_v6),
        _ => {
            let v6 = make_fake_addrinfo_v6(hints, port, fake_v6);
            if v6.is_null() {
                return std::ptr::null_mut();
            }

            let v4 = make_fake_addrinfo_v4(hints, port, fake_v4_be);
            if v4.is_null() {
                libc::free((*v6).ai_addr as *mut c_void);
                libc::free(v6 as *mut c_void);
                return std::ptr::null_mut();
            }

            (*v6).ai_next = v4;
            v6
        }
    }
}

unsafe fn make_fake_addrinfo_v4(
    hints: *const libc::addrinfo,
    port: u16,
    fake_ip_be: u32,
) -> *mut libc::addrinfo {
    let sin = libc::calloc(1, std::mem::size_of::<sockaddr_in>()) as *mut sockaddr_in;
    if sin.is_null() {
        return std::ptr::null_mut();
    }
    (*sin).sin_family = AF_INET as _;
    (*sin).sin_addr.s_addr = fake_ip_be;
    (*sin).sin_port = port.to_be();

    let ai = libc::calloc(1, std::mem::size_of::<libc::addrinfo>()) as *mut libc::addrinfo;
    if ai.is_null() {
        libc::free(sin as *mut c_void);
        return std::ptr::null_mut();
    }
    (*ai).ai_family = AF_INET;
    (*ai).ai_socktype = hinted_socktype(hints);
    (*ai).ai_protocol = hinted_protocol(hints);
    (*ai).ai_addrlen = std::mem::size_of::<sockaddr_in>() as _;
    (*ai).ai_addr = sin as *mut sockaddr;
    ai
}

unsafe fn make_fake_addrinfo_v6(
    hints: *const libc::addrinfo,
    port: u16,
    fake_ip: [u8; 16],
) -> *mut libc::addrinfo {
    let sin6 = libc::calloc(1, std::mem::size_of::<sockaddr_in6>()) as *mut sockaddr_in6;
    if sin6.is_null() {
        return std::ptr::null_mut();
    }
    (*sin6).sin6_family = AF_INET6 as _;
    (*sin6).sin6_port = port.to_be();
    (*sin6).sin6_addr.s6_addr = fake_ip;

    let ai = libc::calloc(1, std::mem::size_of::<libc::addrinfo>()) as *mut libc::addrinfo;
    if ai.is_null() {
        libc::free(sin6 as *mut c_void);
        return std::ptr::null_mut();
    }
    (*ai).ai_family = AF_INET6;
    (*ai).ai_socktype = hinted_socktype(hints);
    (*ai).ai_protocol = hinted_protocol(hints);
    (*ai).ai_addrlen = std::mem::size_of::<sockaddr_in6>() as _;
    (*ai).ai_addr = sin6 as *mut sockaddr;
    ai
}

// ── connect hook ───────────────────────────────────────────────────────────────
//
// Intercepts non-loopback TCP connect() calls:
//   - Fake IPs: look up original hostname, then SOCKS5h CONNECT
//   - Real IPs: SOCKS5 CONNECT with the literal IP

#[no_mangle]
pub unsafe extern "C" fn connect(
    sockfd: c_int,
    addr: *const sockaddr,
    addrlen: socklen_t,
) -> c_int {
    if addr.is_null() {
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

    let (target, port) = match (*addr).sa_family as c_int {
        AF_INET => {
            let sin = &*(addr as *const sockaddr_in);
            let ip = u32::from_be(sin.sin_addr.s_addr);
            let port = u16::from_be(sin.sin_port);

            let octet0 = (ip >> 24) & 0xFF;
            let octet1 = (ip >> 16) & 0xFF;
            if octet0 == 127 || ip == 0 || (octet0 == 169 && octet1 == 254) {
                return real_connect()(sockfd, addr, addrlen);
            }

            let target = match table()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .lookup_v4(ip)
            {
                Some(host) => host,
                None => format!("{}.{}.{}.{}", octet0, octet1, (ip >> 8) & 0xFF, ip & 0xFF),
            };

            (target, port)
        }
        AF_INET6 => {
            let sin6 = &*(addr as *const sockaddr_in6);
            let ip = sin6.sin6_addr.s6_addr;
            let port = u16::from_be(sin6.sin6_port);
            let ipv6 = Ipv6Addr::from(ip);

            if ipv6.is_loopback() || ipv6.is_unspecified() || ipv6.is_unicast_link_local() {
                return real_connect()(sockfd, addr, addrlen);
            }

            let target = match table()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .lookup_v6(ip)
            {
                Some(host) => host,
                None => ipv6.to_string(),
            };

            (target, port)
        }
        AF_UNIX => {
            let Some(path) = unix_socket_path(addr, addrlen) else {
                return real_connect()(sockfd, addr, addrlen);
            };

            let Some((target, port)) = unix_socket_target(&path) else {
                return real_connect()(sockfd, addr, addrlen);
            };

            (target, port)
        }
        _ => return real_connect()(sockfd, addr, addrlen),
    };

    if bypassed_port(port) || bypassed_host(&target) {
        return real_connect()(sockfd, addr, addrlen);
    }

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
            // Mark the fd for outbound X-Route-To injection (US-007).
            track_routed_fd(sockfd);
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

    let mut req = vec![0x05, 0x01, 0x00];
    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
        req.push(0x04);
        req.extend_from_slice(&ipv6.octets());
    } else {
        let hb = host.as_bytes();
        req.push(0x03);
        req.push(hb.len() as u8);
        req.extend_from_slice(hb);
    }
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

// ── outbound X-Route-To injection (US-007) ──────────────────────────────────
//
// For chained service-to-service detours, the local interception layer auto-
// injects the X-Route-To header on outbound HTTP/1.x requests when a route is
// configured via DETOUR_ROUTE_TO. The connect() hook records each fd it tunnels;
// the send()/write() hooks rewrite the first request head on those fds. Requests
// with no configured route — or already carrying the header — are untouched.

const ROUTE_ENV: &str = "DETOUR_ROUTE_TO";

/// The configured outbound route (session id), if any. None disables injection.
fn configured_route() -> Option<String> {
    std::env::var(ROUTE_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
}

/// fd → whether its head has already been handled (injected or skipped). Only
/// fds the connect() hook tunneled are present; everything else passes through.
fn routed_fds() -> &'static Mutex<HashMap<c_int, bool>> {
    static FDS: OnceLock<Mutex<HashMap<c_int, bool>>> = OnceLock::new();
    FDS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record a tunneled fd as a candidate for outbound header injection.
fn track_routed_fd(fd: c_int) {
    routed_fds()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(fd, false);
}

/// If `fd` is routed and its head hasn't been handled yet, mark it handled and
/// return the configured route. Returns None for untracked/already-handled fds.
fn take_route_for_fd(fd: c_int) -> Option<String> {
    let route = configured_route()?;
    let mut map = routed_fds().lock().unwrap_or_else(|e| e.into_inner());
    match map.get_mut(&fd) {
        Some(handled @ false) => {
            *handled = true;
            Some(route)
        }
        _ => None,
    }
}

fn untrack_fd(fd: c_int) {
    routed_fds()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&fd);
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Insert `X-Route-To: <route>` into an HTTP/1.x request head.
///
/// Returns `Some(rewritten)` only when `buf` begins with a complete HTTP/1.x
/// request head (request line + CRLFCRLF) that does not already carry the
/// header. Returns `None` (leave unmodified) for non-HTTP bytes, an incomplete
/// head, or a request that already has X-Route-To.
fn inject_route_header(buf: &[u8], route: &str) -> Option<Vec<u8>> {
    let head_end = find_subsequence(buf, b"\r\n\r\n")?;
    let head = &buf[..head_end];

    let line_end = find_subsequence(head, b"\r\n").unwrap_or(head.len());
    let request_line = &head[..line_end];
    if !is_http_request_line(request_line) {
        return None;
    }

    if head_has_route_header(head) {
        return None;
    }

    let insert_at = line_end + 2; // just past the request line's CRLF
    let mut out = Vec::with_capacity(buf.len() + route.len() + 16);
    out.extend_from_slice(&buf[..insert_at]);
    out.extend_from_slice(b"X-Route-To: ");
    out.extend_from_slice(route.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&buf[insert_at..]);
    Some(out)
}

/// A request line is `METHOD SP REQUEST-TARGET SP HTTP/1.x`.
fn is_http_request_line(line: &[u8]) -> bool {
    line.ends_with(b" HTTP/1.1") || line.ends_with(b" HTTP/1.0")
}

/// Case-insensitive scan of the header lines for an existing X-Route-To.
fn head_has_route_header(head: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(head) else {
        return false;
    };
    text.split("\r\n").skip(1).any(|line| {
        line.split_once(':')
            .map(|(name, _)| name.trim().eq_ignore_ascii_case("x-route-to"))
            .unwrap_or(false)
    })
}

type SendFn = unsafe extern "C" fn(c_int, *const c_void, libc::size_t, c_int) -> libc::ssize_t;
type WriteFn = unsafe extern "C" fn(c_int, *const c_void, libc::size_t) -> libc::ssize_t;
type CloseFn = unsafe extern "C" fn(c_int) -> c_int;

fn real_send() -> SendFn {
    unsafe {
        let ptr = libc::dlsym(libc::RTLD_NEXT, c"send".as_ptr());
        assert!(!ptr.is_null(), "dlsym(RTLD_NEXT, send) failed");
        std::mem::transmute::<*mut c_void, SendFn>(ptr)
    }
}

fn real_write() -> WriteFn {
    unsafe {
        let ptr = libc::dlsym(libc::RTLD_NEXT, c"write".as_ptr());
        assert!(!ptr.is_null(), "dlsym(RTLD_NEXT, write) failed");
        std::mem::transmute::<*mut c_void, WriteFn>(ptr)
    }
}

fn real_close() -> CloseFn {
    unsafe {
        let ptr = libc::dlsym(libc::RTLD_NEXT, c"close".as_ptr());
        assert!(!ptr.is_null(), "dlsym(RTLD_NEXT, close) failed");
        std::mem::transmute::<*mut c_void, CloseFn>(ptr)
    }
}

/// Write the whole injected buffer to the real send(), looping over partial
/// writes. Returns true if all bytes were accepted. Best-effort: a hard error or
/// EAGAIN on a non-blocking socket aborts and the caller falls back.
unsafe fn send_all(fd: c_int, data: &[u8], flags: c_int) -> bool {
    let mut off = 0usize;
    while off < data.len() {
        let n = real_send()(
            fd,
            data[off..].as_ptr() as *const c_void,
            data.len() - off,
            flags,
        );
        if n <= 0 {
            return false;
        }
        off += n as usize;
    }
    true
}

#[no_mangle]
pub unsafe extern "C" fn send(
    fd: c_int,
    buf: *const c_void,
    len: libc::size_t,
    flags: c_int,
) -> libc::ssize_t {
    if !buf.is_null() && len > 0 {
        if let Some(route) = take_route_for_fd(fd) {
            let slice = std::slice::from_raw_parts(buf as *const u8, len);
            if let Some(rewritten) = inject_route_header(slice, &route) {
                if send_all(fd, &rewritten, flags) {
                    // The app's original bytes were all delivered (plus our
                    // header); report the count it expected.
                    return len as libc::ssize_t;
                }
            }
        }
    }
    real_send()(fd, buf, len, flags)
}

#[no_mangle]
pub unsafe extern "C" fn write(
    fd: c_int,
    buf: *const c_void,
    count: libc::size_t,
) -> libc::ssize_t {
    if !buf.is_null() && count > 0 {
        if let Some(route) = take_route_for_fd(fd) {
            let slice = std::slice::from_raw_parts(buf as *const u8, count);
            if let Some(rewritten) = inject_route_header(slice, &route) {
                if send_all(fd, &rewritten, 0) {
                    return count as libc::ssize_t;
                }
            }
        }
    }
    real_write()(fd, buf, count)
}

#[no_mangle]
pub unsafe extern "C" fn close(fd: c_int) -> c_int {
    untrack_fd(fd);
    real_close()(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_ip_table_round_trips_ipv4_and_ipv6() {
        let mut table = FakeIpTable::new();
        let id = table.assign("db.internal");

        assert_eq!(
            table.lookup_v4(fake_ipv4(id)),
            Some("db.internal".to_string())
        );
        assert_eq!(
            table.lookup_v6(fake_ipv6(id)),
            Some("db.internal".to_string())
        );
    }

    #[test]
    fn passthrough_detects_local_and_literal_hosts() {
        assert!(should_passthrough_hostname("localhost"));
        assert!(should_passthrough_hostname("127.0.0.1"));
        assert!(should_passthrough_hostname("::1"));
        assert!(should_passthrough_hostname("10.0.0.5"));
        assert!(!should_passthrough_hostname("redis.internal"));
    }

    #[test]
    fn service_port_parses_numeric_ports() {
        let service = std::ffi::CString::new("5432").unwrap();
        let port = unsafe { service_port(service.as_ptr()) };
        assert_eq!(port, 5432);
    }

    #[test]
    fn service_port_resolves_named_tcp_services() {
        let service = std::ffi::CString::new("https").unwrap();
        let port = unsafe { service_port(service.as_ptr()) };
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_target_host_port_supports_ipv4_and_ipv6() {
        assert_eq!(
            parse_target_host_port("db.internal:5432"),
            Some(("db.internal".to_string(), 5432))
        );
        assert_eq!(
            parse_target_host_port("[2001:db8::1]:6379"),
            Some(("2001:db8::1".to_string(), 6379))
        );
    }

    #[test]
    fn inject_route_header_adds_header_after_request_line() {
        let req = b"GET /api HTTP/1.1\r\nHost: svc\r\nAccept: */*\r\n\r\n";
        let out = inject_route_header(req, "sess-1").expect("should inject");
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "GET /api HTTP/1.1\r\nX-Route-To: sess-1\r\nHost: svc\r\nAccept: */*\r\n\r\n"
        );
        // Header lands before the existing headers and the body delimiter stays.
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn inject_route_header_preserves_body() {
        let req = b"POST /x HTTP/1.1\r\nHost: svc\r\nContent-Length: 5\r\n\r\nhello";
        let out = inject_route_header(req, "s2").unwrap();
        assert!(out.ends_with(b"\r\n\r\nhello"));
        assert!(find_subsequence(&out, b"X-Route-To: s2\r\n").is_some());
    }

    #[test]
    fn inject_route_header_skips_when_already_present() {
        // Case-insensitive: an existing x-route-to must not be duplicated.
        let req = b"GET / HTTP/1.1\r\nHost: svc\r\nx-route-to: existing\r\n\r\n";
        assert!(inject_route_header(req, "sess-1").is_none());
    }

    #[test]
    fn inject_route_header_ignores_non_http_and_partial_heads() {
        // Not an HTTP request line.
        assert!(inject_route_header(b"\x16\x03\x01 TLS handshake\r\n\r\n", "s").is_none());
        // HTTP/2 preface is not HTTP/1.x.
        assert!(inject_route_header(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "s").is_none());
        // Incomplete head (no CRLFCRLF yet) — leave it for a later write.
        assert!(inject_route_header(b"GET / HTTP/1.1\r\nHost: svc\r\n", "s").is_none());
    }

    #[test]
    fn configured_route_requires_non_empty_env() {
        unsafe { std::env::set_var(ROUTE_ENV, "  ") };
        assert!(configured_route().is_none());
        unsafe { std::env::set_var(ROUTE_ENV, "sess-xyz") };
        assert_eq!(configured_route().as_deref(), Some("sess-xyz"));
        unsafe { std::env::remove_var(ROUTE_ENV) };
    }

    #[test]
    fn take_route_for_fd_only_fires_once_per_tracked_fd() {
        unsafe { std::env::set_var(ROUTE_ENV, "sess-once") };
        let fd = 4242;
        // Untracked fd never routes.
        assert!(take_route_for_fd(fd).is_none());

        track_routed_fd(fd);
        assert_eq!(take_route_for_fd(fd).as_deref(), Some("sess-once"));
        // Head already handled — second call is a no-op so later writes pass through.
        assert!(take_route_for_fd(fd).is_none());

        untrack_fd(fd);
        unsafe { std::env::remove_var(ROUTE_ENV) };
    }

    #[test]
    fn unix_socket_target_matches_prefix_mappings() {
        unsafe {
            std::env::set_var(
                "DETOUR_UNIX_SOCKET_MAPS",
                "/cloudsql/project:region:instance=db.internal:5432;/var/run/redis=redis.internal:6379",
            );
        }

        assert_eq!(
            unix_socket_target("/cloudsql/project:region:instance/.s.PGSQL.5432"),
            Some(("db.internal".to_string(), 5432))
        );
        assert_eq!(
            unix_socket_target("/var/run/redis/redis.sock"),
            Some(("redis.internal".to_string(), 6379))
        );
        assert_eq!(unix_socket_target("/tmp/other.sock"), None);

        unsafe {
            std::env::remove_var("DETOUR_UNIX_SOCKET_MAPS");
        }
    }
}
