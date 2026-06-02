//! Raw byte-stream data plane for the sidecar (US-004/US-005).
//!
//! Instead of reshaping requests into `RelayRequest`/`RelayResponse`, the sidecar
//! sniffs only the HTTP request head (just enough to extract the `X-Route-To`
//! routing header), then splices the connection as raw bytes. Routed connections
//! are relayed over the broker `RelayConnection` RPC keyed by a fresh
//! connection_id; everything else is spliced verbatim to the local app.
//!
//! Because the body is never buffered or HTTP-parsed, WebSocket and other
//! protocol upgrades flow through unchanged (US-005), and gRPC/streaming bodies
//! keep their framing and trailers end to end (US-006).

use std::io;

use bytes::BytesMut;
use http::HeaderMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tracing::warn;

use detour_proto::detour::{detour_client::DetourClient, RawConnFrame};

/// Upper bound on bytes read while sniffing the request head. Guards against a
/// peer that never sends the head terminator (or speaks a non-HTTP/1.x protocol).
const MAX_HEAD: usize = 64 * 1024;
const HEAD_END: &[u8] = b"\r\n\r\n";
const RAW_BUF: usize = 16384;

/// The HTTP/2 client connection preface. A connection beginning with these bytes
/// speaks HTTP/2 (h2c) — gRPC's transport — and must be sniffed at the frame
/// level rather than as a text head.
pub const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The sniffed start of an HTTP/1.x connection. `raw` is the verbatim head bytes
/// (request line + headers + terminating CRLFCRLF) so they can be replayed
/// downstream without loss.
pub struct Head {
    pub raw: Vec<u8>,
    pub method: String,
    pub path: String,
    pub headers: HeaderMap,
}

/// Outcome of sniffing the start of a connection. Every variant carries the
/// bytes already consumed so the caller can replay them verbatim downstream.
pub enum Sniff {
    /// An HTTP/1.x request whose head was parsed; `rest` is any pipelined body.
    Http1 { head: Head, rest: Vec<u8> },
    /// An HTTP/2 (h2c) connection. `buffered` holds the preface (and possibly
    /// more) read so far — gRPC routing reads further frames (US-006).
    Http2 { buffered: Vec<u8> },
    /// Not recognizably HTTP/1.x or /2; splice the buffered bytes verbatim.
    Raw { buffered: Vec<u8> },
}

/// Sniff the start of a connection: detect the HTTP/2 preface, otherwise read up
/// to the end of an HTTP/1.x request head (CRLFCRLF). Falls back to [`Sniff::Raw`]
/// on early EOF, an over-long head, or an unparseable head.
pub async fn sniff_head<R: AsyncRead + Unpin>(io: &mut R) -> io::Result<Sniff> {
    let mut buf = BytesMut::with_capacity(8192);
    let mut tmp = [0u8; 8192];

    loop {
        // HTTP/2 preface detection takes priority: "PRI * HTTP/2.0\r\n\r\n..."
        // contains a CRLFCRLF, so we must rule it in/out before the head search.
        if buf.starts_with(H2_PREFACE) {
            return Ok(Sniff::Http2 {
                buffered: buf.to_vec(),
            });
        }
        if buf.len() < H2_PREFACE.len() && !buf.is_empty() && H2_PREFACE.starts_with(&buf) {
            // Still a possible preface prefix — read more before deciding.
            let n = io.read(&mut tmp).await?;
            if n == 0 {
                return Ok(Sniff::Raw {
                    buffered: buf.to_vec(),
                });
            }
            buf.extend_from_slice(&tmp[..n]);
            continue;
        }

        if let Some(pos) = find_subsequence(&buf, HEAD_END) {
            let head_end = pos + HEAD_END.len();
            let raw = buf[..head_end].to_vec();
            let rest = buf[head_end..].to_vec();
            return Ok(match parse_head(&raw) {
                Some(head) => Sniff::Http1 { head, rest },
                None => Sniff::Raw {
                    buffered: buf.to_vec(),
                },
            });
        }

        if buf.len() >= MAX_HEAD {
            return Ok(Sniff::Raw {
                buffered: buf.to_vec(),
            });
        }

        let n = io.read(&mut tmp).await?;
        if n == 0 {
            return Ok(Sniff::Raw {
                buffered: buf.to_vec(),
            });
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn parse_head(raw: &[u8]) -> Option<Head> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut lines = text.split("\r\n");

    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();

    let mut headers = HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if let (Ok(n), Ok(v)) = (
                http::header::HeaderName::from_bytes(name.trim().as_bytes()),
                http::header::HeaderValue::from_str(value.trim()),
            ) {
                headers.append(n, v);
            }
        }
    }

    Some(Head {
        raw: raw.to_vec(),
        method,
        path,
        headers,
    })
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// True if the request head asks to upgrade the protocol (WebSocket or any other
/// `Connection: Upgrade` handshake). Such connections must flow over the raw data
/// plane untouched — after the handshake the bytes are an opaque, non-HTTP stream
/// (US-005).
pub fn is_upgrade(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);

    connection_upgrade && headers.contains_key(http::header::UPGRADE)
}

/// Upper bound on bytes read while looking for the first HTTP/2 HEADERS frame.
const MAX_H2_SNIFF: usize = 32 * 1024;

/// Read further HTTP/2 frames from `io` (starting from `buffered`, which already
/// holds the preface) until the first HEADERS frame is found, then extract the
/// `x-route-to` header from its HPACK block (US-006).
///
/// Returns `(route, buffered)` where `route` is the header value if found and
/// `buffered` is every byte consumed, so the caller can replay the whole prefix
/// verbatim whether it routes or splices. The HPACK decoder is minimal: it does
/// not implement Huffman string decoding, so a Huffman-coded value yields `None`
/// and the connection is spliced rather than misrouted.
pub async fn read_h2_route<R: AsyncRead + Unpin>(
    io: &mut R,
    mut buffered: Vec<u8>,
) -> io::Result<(Option<String>, Vec<u8>)> {
    let mut tmp = [0u8; 8192];
    loop {
        if let Some(block) = first_headers_block(&buffered[H2_PREFACE.len()..]) {
            return Ok((hpack_find(block, "x-route-to"), buffered));
        }
        if buffered.len() >= MAX_H2_SNIFF {
            return Ok((None, buffered));
        }
        let n = io.read(&mut tmp).await?;
        if n == 0 {
            return Ok((None, buffered));
        }
        buffered.extend_from_slice(&tmp[..n]);
    }
}

/// Walk HTTP/2 frames and return the header block fragment of the first HEADERS
/// frame (type 0x1), with PADDED/PRIORITY adjustments applied. Returns None if no
/// complete HEADERS frame is present yet.
fn first_headers_block(buf: &[u8]) -> Option<&[u8]> {
    let mut i = 0;
    while i + 9 <= buf.len() {
        let len = ((buf[i] as usize) << 16) | ((buf[i + 1] as usize) << 8) | buf[i + 2] as usize;
        let ftype = buf[i + 3];
        let flags = buf[i + 4];
        let start = i + 9;
        let end = start.checked_add(len)?;
        if end > buf.len() {
            return None; // frame not fully read yet
        }
        if ftype == 0x1 {
            let mut p = &buf[start..end];
            if flags & 0x8 != 0 {
                // PADDED: first byte is pad length, trailing pad stripped.
                if p.is_empty() {
                    return None;
                }
                let pad = p[0] as usize;
                p = &p[1..];
                p = p.get(..p.len().checked_sub(pad)?)?;
            }
            if flags & 0x20 != 0 {
                // PRIORITY: 5 bytes (stream dependency + weight).
                p = p.get(5..)?;
            }
            return Some(p);
        }
        i = end;
    }
    None
}

/// Minimal HPACK scan for a literal header field named `target`. Handles the
/// three literal representations (incremental indexing / without indexing /
/// never indexed), skips indexed fields and dynamic-table-size updates, and
/// returns the decoded value — or None if absent or Huffman-coded. Header names
/// referenced by static-table index (name_idx != 0) are not resolved, so
/// `x-route-to` must be sent as a literal name (it is not in the static table,
/// so a compliant encoder always emits it literally).
fn hpack_find(block: &[u8], target: &str) -> Option<String> {
    let mut i = 0;
    while i < block.len() {
        let b = block[i];
        let prefix = if b & 0x80 != 0 {
            // Indexed header field — integer only, no literal payload.
            i = decode_int(block, i, 7)?.1;
            continue;
        } else if b & 0x40 != 0 {
            6 // literal, incremental indexing
        } else if b & 0x20 != 0 {
            // Dynamic table size update — integer only.
            i = decode_int(block, i, 5)?.1;
            continue;
        } else {
            4 // literal without indexing / never indexed
        };

        let (name_idx, after_idx) = decode_int(block, i, prefix)?;
        let (name, after_name) = if name_idx == 0 {
            let (s, j) = decode_str(block, after_idx)?;
            (Some(s), j)
        } else {
            (None, after_idx)
        };
        let (value, after_value) = decode_str(block, after_name)?;
        if name.as_deref() == Some(target) {
            return Some(value);
        }
        i = after_value;
    }
    None
}

/// Decode an HPACK variable-length integer with an `prefix`-bit prefix at `pos`.
/// Returns `(value, next_index)`.
fn decode_int(buf: &[u8], pos: usize, prefix: u32) -> Option<(usize, usize)> {
    if pos >= buf.len() {
        return None;
    }
    let mask = (1u32 << prefix) - 1;
    let mut i = pos;
    let mut value = (buf[i] as u32) & mask;
    i += 1;
    if value < mask {
        return Some((value as usize, i));
    }
    let mut shift = 0;
    loop {
        if i >= buf.len() {
            return None;
        }
        let b = buf[i];
        i += 1;
        value = value.checked_add(((b & 0x7f) as u32).checked_shl(shift)?)?;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if shift > 28 {
            return None;
        }
    }
    Some((value as usize, i))
}

/// Decode an HPACK string literal at `pos`. Returns None for Huffman-coded
/// strings (unsupported in this minimal decoder).
fn decode_str(buf: &[u8], pos: usize) -> Option<(String, usize)> {
    if pos >= buf.len() {
        return None;
    }
    let huffman = buf[pos] & 0x80 != 0;
    let (len, i) = decode_int(buf, pos, 7)?;
    let end = i.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    if huffman {
        return None;
    }
    Some((String::from_utf8(buf[i..end].to_vec()).ok()?, end))
}

/// Relay a routed connection over the broker `RelayConnection` RPC as raw
/// per-connection byte frames (US-004). `initial` is the already-sniffed head
/// (plus any pipelined body bytes) and rides the opening frame so the agent
/// replays it to the local app verbatim. is_eof closes the matching half.
pub async fn relay_raw<S>(
    mut client: DetourClient<Channel>,
    session_id: String,
    connection_id: String,
    service_name: String,
    initial: Vec<u8>,
    io: S,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut rd, mut wr) = tokio::io::split(io);
    let (tx, rx) = mpsc::channel::<RawConnFrame>(16);

    // Opening frame carries routing (session_id/connection_id/service_name) and
    // the bytes already read off the socket.
    let opening = RawConnFrame {
        session_id,
        connection_id: connection_id.clone(),
        payload: initial,
        is_eof: false,
        service_name,
    };
    if tx.send(opening).await.is_err() {
        return Ok(());
    }

    // client → broker
    let cid = connection_id.clone();
    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; RAW_BUF];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = tx.send(raw_frame(&cid, Vec::new(), true)).await;
                    break;
                }
                Ok(n) => {
                    if tx
                        .send(raw_frame(&cid, buf[..n].to_vec(), false))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    // broker → client
    let resp = client
        .relay_connection(ReceiverStream::new(rx))
        .await?
        .into_inner();
    let mut inbound = resp;
    loop {
        match inbound.message().await {
            Ok(Some(frame)) => {
                if !frame.payload.is_empty() && wr.write_all(&frame.payload).await.is_err() {
                    break;
                }
                if frame.is_eof {
                    let _ = wr.shutdown().await;
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                warn!(error = %e, "raw relay response stream error");
                break;
            }
        }
    }

    up.abort();
    Ok(())
}

/// Splice a non-routed connection straight to the local app as a raw TCP proxy.
/// `initial` is the bytes already read while sniffing and is written upstream
/// first so nothing is lost.
pub async fn splice_upstream<S>(io: S, upstream: &str, initial: Vec<u8>) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut up = TcpStream::connect(normalize_upstream(upstream)).await?;
    if !initial.is_empty() {
        up.write_all(&initial).await?;
    }

    let (mut client_rd, mut client_wr) = tokio::io::split(io);
    let (mut up_rd, mut up_wr) = up.split();

    let c2u = async {
        let _ = tokio::io::copy(&mut client_rd, &mut up_wr).await;
        let _ = up_wr.shutdown().await;
    };
    let u2c = async {
        let _ = tokio::io::copy(&mut up_rd, &mut client_wr).await;
        let _ = client_wr.shutdown().await;
    };
    tokio::join!(c2u, u2c);
    Ok(())
}

/// Strip a scheme prefix so `http://host:port` and `host:port` both resolve.
fn normalize_upstream(upstream: &str) -> String {
    upstream
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .to_string()
}

fn raw_frame(connection_id: &str, payload: Vec<u8>, is_eof: bool) -> RawConnFrame {
    RawConnFrame {
        session_id: String::new(),
        connection_id: connection_id.to_string(),
        payload,
        is_eof,
        service_name: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn sniff_head_parses_request_line_headers_and_leftover() {
        let (mut a, mut b) = duplex(4096);
        a.write_all(b"GET /foo?x=1 HTTP/1.1\r\nHost: svc\r\nX-Route-To: abc-123\r\n\r\nBODYBYTES")
            .await
            .unwrap();
        a.shutdown().await.unwrap();

        let Sniff::Http1 { head, rest } = sniff_head(&mut b).await.unwrap() else {
            panic!("expected a parsed HTTP/1 head");
        };
        assert_eq!(head.method, "GET");
        assert_eq!(head.path, "/foo?x=1");
        assert_eq!(head.headers.get("x-route-to").unwrap(), "abc-123");
        assert_eq!(head.headers.get("host").unwrap(), "svc");
        assert_eq!(rest, b"BODYBYTES");
        // The raw head is preserved verbatim for downstream replay.
        assert!(head.raw.ends_with(b"\r\n\r\n"));
        assert!(head.raw.starts_with(b"GET /foo?x=1 HTTP/1.1"));
    }

    #[tokio::test]
    async fn sniff_head_non_http_returns_raw_bytes() {
        // No CRLFCRLF terminator before EOF — caller gets the bytes back to splice.
        let (mut a, mut b) = duplex(4096);
        a.write_all(b"not http, no head terminator").await.unwrap();
        a.shutdown().await.unwrap();

        let Sniff::Raw { buffered } = sniff_head(&mut b).await.unwrap() else {
            panic!("expected the raw fallback");
        };
        assert_eq!(buffered, b"not http, no head terminator");
    }

    // Upgrade requests carry their handshake in the head, then the connection
    // becomes an opaque byte stream — sniff_head returns the head and the caller
    // splices the rest, so nothing past the handshake is HTTP-parsed (US-005).
    #[tokio::test]
    async fn sniff_head_websocket_upgrade_is_parsed_then_left_raw() {
        let (mut a, mut b) = duplex(4096);
        a.write_all(
            b"GET /ws HTTP/1.1\r\nHost: svc\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x81\x05hello",
        )
        .await
        .unwrap();
        a.shutdown().await.unwrap();

        let Sniff::Http1 { head, rest } = sniff_head(&mut b).await.unwrap() else {
            panic!("expected a parsed HTTP/1 head");
        };
        assert_eq!(head.headers.get("upgrade").unwrap(), "websocket");
        // The post-handshake WebSocket frame bytes are returned unparsed.
        assert_eq!(rest, b"\x81\x05hello");
    }

    /// Build a single h2 HEADERS frame whose HPACK block carries one literal,
    /// non-Huffman header (END_HEADERS|END_STREAM, stream 1, no padding/priority).
    fn h2_headers_frame(name: &str, value: &str) -> Vec<u8> {
        let mut block = vec![0x00u8]; // literal without indexing, new name (idx 0)
        block.push(name.len() as u8); // string len, huffman bit clear
        block.extend_from_slice(name.as_bytes());
        block.push(value.len() as u8);
        block.extend_from_slice(value.as_bytes());

        let len = block.len();
        let mut frame = vec![
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
            0x01, // type HEADERS
            0x05, // flags END_HEADERS | END_STREAM
            0x00,
            0x00,
            0x00,
            0x01, // stream id 1
        ];
        frame.extend_from_slice(&block);
        frame
    }

    fn h2_settings_frame() -> Vec<u8> {
        // Empty SETTINGS frame (length 0, type 0x4, stream 0) — what a client
        // sends right after the preface, before HEADERS.
        vec![0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]
    }

    #[tokio::test]
    async fn sniff_head_detects_http2_preface() {
        let (mut a, mut b) = duplex(4096);
        let mut bytes = H2_PREFACE.to_vec();
        bytes.extend_from_slice(&h2_settings_frame());
        a.write_all(&bytes).await.unwrap();
        a.shutdown().await.unwrap();

        let Sniff::Http2 { buffered } = sniff_head(&mut b).await.unwrap() else {
            panic!("expected HTTP/2");
        };
        assert!(buffered.starts_with(H2_PREFACE));
    }

    #[test]
    fn hpack_find_extracts_literal_header() {
        let frame = h2_headers_frame("x-route-to", "sess-uuid");
        let block = first_headers_block(&frame).expect("headers block");
        assert_eq!(hpack_find(block, "x-route-to").as_deref(), Some("sess-uuid"));
        assert_eq!(hpack_find(block, "missing"), None);
    }

    // End to end over a socket: preface + SETTINGS + HEADERS(x-route-to). The
    // route is extracted and every consumed byte is returned for verbatim replay.
    #[tokio::test]
    async fn read_h2_route_extracts_route_from_first_headers_frame() {
        let (mut a, mut b) = duplex(8192);
        let mut bytes = H2_PREFACE.to_vec();
        bytes.extend_from_slice(&h2_settings_frame());
        bytes.extend_from_slice(&h2_headers_frame("x-route-to", "the-session"));
        a.write_all(&bytes).await.unwrap();
        a.shutdown().await.unwrap();

        let Sniff::Http2 { buffered } = sniff_head(&mut b).await.unwrap() else {
            panic!("expected HTTP/2");
        };
        let (route, consumed) = read_h2_route(&mut b, buffered).await.unwrap();
        assert_eq!(route.as_deref(), Some("the-session"));
        assert!(consumed.starts_with(H2_PREFACE));
    }

    #[test]
    fn hpack_find_returns_none_for_huffman_value() {
        // Same literal header but with the Huffman bit set on the value string.
        let mut block = vec![0x00u8, "x-route-to".len() as u8];
        block.extend_from_slice(b"x-route-to");
        block.push(0x80 | 3); // huffman flag + len 3
        block.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        assert_eq!(hpack_find(&block, "x-route-to"), None);
    }

    #[test]
    fn is_upgrade_detects_websocket_and_ignores_plain_requests() {
        let mut ws = HeaderMap::new();
        ws.insert(http::header::CONNECTION, "Upgrade".parse().unwrap());
        ws.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        assert!(is_upgrade(&ws));

        // Connection header may carry a comma-separated token list.
        let mut ws2 = HeaderMap::new();
        ws2.insert(http::header::CONNECTION, "keep-alive, Upgrade".parse().unwrap());
        ws2.insert(http::header::UPGRADE, "h2c".parse().unwrap());
        assert!(is_upgrade(&ws2));

        // Connection: Upgrade without an Upgrade header is not an upgrade.
        let mut partial = HeaderMap::new();
        partial.insert(http::header::CONNECTION, "Upgrade".parse().unwrap());
        assert!(!is_upgrade(&partial));

        let mut plain = HeaderMap::new();
        plain.insert(http::header::CONNECTION, "keep-alive".parse().unwrap());
        assert!(!is_upgrade(&plain));
    }

    #[tokio::test]
    async fn splice_upstream_proxies_bytes_both_ways() {
        // Upstream echo server.
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });

        // A front connection the sidecar would accept.
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let splice = tokio::spawn(async move {
            let (sock, _) = front.accept().await.unwrap();
            splice_upstream(sock, &upstream_addr.to_string(), b"HEAD".to_vec())
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(front_addr).await.unwrap();
        client.write_all(b"TAIL").await.unwrap();
        client.shutdown().await.unwrap();

        let mut got = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut client, &mut got)
            .await
            .unwrap();
        // "HEAD" (initial, written upstream first) + "TAIL" echoed back.
        assert_eq!(got, b"HEADTAIL");

        splice.await.unwrap();
    }
}
