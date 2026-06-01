// detour-layer: LD_PRELOAD / DYLD_INSERT_LIBRARIES shared library.
//
// Hooks connect() and getaddrinfo() to transparently route outbound TCP
// connections through the detour agent's SOCKS5 proxy (default port 1081).
//
// Usage (Linux):
//   LD_PRELOAD=/path/to/libdetour_layer.so DETOUR_SOCKS5_PORT=1081 node server.js
//
// Usage (macOS):
//   DYLD_INSERT_LIBRARIES=/path/to/libdetour_layer.dylib DETOUR_SOCKS5_PORT=1081 node server.js
//
// Optional bypass controls:
//   DETOUR_BYPASS_HOSTS=localhost,metadata.google.internal,*.svc.cluster.local
//   DETOUR_BYPASS_PORTS=25,2525
//
// Optional Unix socket remapping:
//   DETOUR_UNIX_SOCKET_MAPS=/cloudsql/project:region:instance=db.internal:5432
//
// How it works:
//   getaddrinfo(), gethostbyname*(), and Linux gethostbyname*_r() — rewrite
//     resolved IPv4/IPv6 answers to fake addresses and, on lookup misses (for
//     example private cloud DNS), synthesize fake results so the app can still
//     proceed to connect().
//
//   connect() — intercepts non-loopback IPv4/IPv6 TCP connections:
//     - Fake IPs → SOCKS5 CONNECT with original hostname (SOCKS5h)
//     - Any other non-loopback IP → SOCKS5 CONNECT with the literal IP directly
//     - Configured Unix socket paths → SOCKS5 CONNECT with the mapped TCP target
//
//   On macOS, connectx() simple TCP connects are also routed through the same
//   outbound tunnel path.

#[cfg(unix)]
mod imp;
