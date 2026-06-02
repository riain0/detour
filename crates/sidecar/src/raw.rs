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

/// The sniffed start of an HTTP/1.x connection. `raw` is the verbatim head bytes
/// (request line + headers + terminating CRLFCRLF) so they can be replayed
/// downstream without loss.
pub struct Head {
    pub raw: Vec<u8>,
    pub method: String,
    pub path: String,
    pub headers: HeaderMap,
}

/// Read from `io` until the end of the HTTP request head (CRLFCRLF).
///
/// On success returns `Ok((Head, rest))` where `rest` is any bytes already read
/// past the head (pipelined body bytes). If the stream closes early, exceeds
/// [`MAX_HEAD`], or the head is not parseable HTTP/1.x (e.g. an HTTP/2 preface),
/// returns `Err(raw)` with all bytes consumed so the caller can splice them
/// verbatim.
pub async fn sniff_head<R: AsyncRead + Unpin>(
    io: &mut R,
) -> io::Result<Result<(Head, Vec<u8>), Vec<u8>>> {
    let mut buf = BytesMut::with_capacity(8192);
    let mut tmp = [0u8; 8192];

    loop {
        if let Some(pos) = find_subsequence(&buf, HEAD_END) {
            let head_end = pos + HEAD_END.len();
            let raw = buf[..head_end].to_vec();
            let rest = buf[head_end..].to_vec();
            return Ok(match parse_head(&raw) {
                Some(head) => Ok((head, rest)),
                None => Err(buf.to_vec()),
            });
        }

        if buf.len() >= MAX_HEAD {
            return Ok(Err(buf.to_vec()));
        }

        let n = io.read(&mut tmp).await?;
        if n == 0 {
            return Ok(Err(buf.to_vec()));
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

        let Ok((head, rest)) = sniff_head(&mut b).await.unwrap() else {
            panic!("expected a parsed head");
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

        let Err(raw) = sniff_head(&mut b).await.unwrap() else {
            panic!("expected the raw fallback");
        };
        assert_eq!(raw, b"not http, no head terminator");
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

        let Ok((head, rest)) = sniff_head(&mut b).await.unwrap() else {
            panic!("expected a parsed head");
        };
        assert_eq!(head.headers.get("upgrade").unwrap(), "websocket");
        // The post-handshake WebSocket frame bytes are returned unparsed.
        assert_eq!(rest, b"\x81\x05hello");
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
