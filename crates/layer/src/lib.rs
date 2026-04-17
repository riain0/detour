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
// How it works:
//   getaddrinfo() — for hostnames that fail resolution (private cloud DNS),
//     returns a fake IP in 198.18.0.0/15 and records hostname→fakeIP so that
//     the subsequent connect() call can look up the original hostname for SOCKS5h.
//
//   connect() — intercepts all non-loopback IPv4 TCP connections:
//     - Fake IP (198.18.x.x) → SOCKS5 CONNECT with original hostname (SOCKS5h)
//     - Any other non-loopback IP → SOCKS5 CONNECT with the IP directly

#[cfg(unix)]
mod imp;
