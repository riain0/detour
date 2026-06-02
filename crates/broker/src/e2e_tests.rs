//! End-to-end interception tests (US-013).
//!
//! These wire a real in-process broker (`RelayService` behind a tonic server)
//! to a simulated agent (over the real `OpenTunnel` bidi stream) and drive it
//! with a simulated sidecar (the real `RelayConnection` / `OutboundTunnel`
//! client RPCs). They exercise the broker's raw data-plane routing, auth, and
//! outbound tunnel end to end over the wire.
//!
//! ## Cloud Run deployment assumptions
//!
//! - In production the sidecar runs as a Cloud Run sidecar container in front of
//!   the app container; here the test plays the sidecar's client role directly.
//! - The agent runs on the developer's machine and dials its local app; here a
//!   simulated agent echoes / generates bytes in place of `forward_connection`
//!   (which dials a real socket and is covered by detour-agent's own tests).
//! - `OutboundTunnel` targets (e.g. private Cloud DNS like `db.internal`) are
//!   resolved INSIDE the cloud network by the broker via `lookup_host`; the test
//!   uses `localhost` to exercise the same name-resolution path offline.
//! - gcp-oidc validation needs Google's live JWKS (network, non-deterministic),
//!   so the auth success/failure E2E uses signed-token mode, which flows through
//!   the identical `AuthService::validate` seam (gcp-oidc is unit-tested in
//!   `auth`).

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Server};
use tonic::{Code, Request};

use detour_core::AuthMode;
use detour_proto::detour::{
    agent_message, broker_message, detour_client::DetourClient, detour_server::DetourServer,
    outbound_client_msg, outbound_server_msg, AgentMessage, OutboundClientMsg, OutboundConnect,
    RawConnFrame, RegisterSession, RouteEntry,
};

use crate::auth::AuthService;
use crate::connections::{ConnectionMap, PendingRequests, RawConnections};
use crate::registry::MemoryRegistry;
use crate::relay::RelayService;

const SESSION: &str = "11111111-1111-4111-8111-111111111111";
const SERVICE: &str = "svc";

/// Start a broker on an ephemeral port and return its URL.
async fn start_broker(auth: AuthService) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let service = RelayService {
        registry: Arc::new(MemoryRegistry::new(3600)),
        connections: ConnectionMap::default(),
        pending_requests: PendingRequests::default(),
        raw_connections: RawConnections::default(),
        auth: Arc::new(auth),
        broker_id: "test-broker".into(),
        ttl_secs: 3600,
    };

    tokio::spawn(async move {
        Server::builder()
            .add_service(DetourServer::new(service))
            .serve(addr)
            .await
            .unwrap();
    });

    format!("http://{addr}")
}

/// Connect a client, retrying until the broker's listener is up.
async fn connect(url: &str) -> DetourClient<Channel> {
    for _ in 0..100 {
        if let Ok(client) = DetourClient::connect(url.to_string()).await {
            return client;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("broker never came up at {url}");
}

fn register_msg(session_id: &str) -> AgentMessage {
    AgentMessage {
        payload: Some(agent_message::Payload::Register(RegisterSession {
            session_id: session_id.to_string(),
            auth_mode: "session-id".into(),
            routes: vec![RouteEntry {
                service_name: SERVICE.into(),
                local_port: 0,
            }],
        })),
    }
}

fn agent_raw(connection_id: &str, payload: Vec<u8>, is_eof: bool) -> AgentMessage {
    AgentMessage {
        payload: Some(agent_message::Payload::Raw(RawConnFrame {
            session_id: String::new(),
            connection_id: connection_id.to_string(),
            payload,
            is_eof,
            service_name: String::new(),
        })),
    }
}

fn sidecar_raw(connection_id: &str, payload: &[u8], is_eof: bool) -> RawConnFrame {
    RawConnFrame {
        session_id: SESSION.into(),
        connection_id: connection_id.to_string(),
        payload: payload.to_vec(),
        is_eof,
        service_name: SERVICE.into(),
    }
}

/// What the simulated agent app does with each routed connection.
#[derive(Clone, Copy)]
enum App {
    /// Echo every received byte back; mirror is_eof.
    Echo,
    /// On the opening frame, stream three SSE events then close.
    Sse,
}

/// Register a session over OpenTunnel with an optional bearer token, wait for the
/// ack, then run `app` against the broker's raw frames. Returns once registered.
async fn spawn_agent(url: &str, token: Option<String>, app: App) {
    let mut client = connect(url).await;
    let (tx, rx) = mpsc::channel::<AgentMessage>(64);
    tx.send(register_msg(SESSION)).await.unwrap();

    let mut request = Request::new(ReceiverStream::new(rx));
    if let Some(token) = token {
        request
            .metadata_mut()
            .insert("authorization", token.parse().unwrap());
    }

    let mut inbound = client.open_tunnel(request).await.unwrap().into_inner();
    let ack = inbound.next().await.expect("ack").expect("ack ok");
    assert!(
        matches!(ack.payload, Some(broker_message::Payload::Ack(_))),
        "expected SessionAck, got {:?}",
        ack.payload
    );

    tokio::spawn(async move {
        let _client = client; // keep the channel alive
        while let Some(Ok(msg)) = inbound.next().await {
            let Some(broker_message::Payload::Raw(frame)) = msg.payload else {
                continue;
            };
            match app {
                App::Echo => {
                    let _ = tx
                        .send(agent_raw(&frame.connection_id, frame.payload, frame.is_eof))
                        .await;
                }
                App::Sse => {
                    if frame.is_eof {
                        continue;
                    }
                    // Opening frame triggers the event stream.
                    for i in 1..=3 {
                        let event = format!("event: tick\ndata: {i}\n\n");
                        let _ = tx
                            .send(agent_raw(&frame.connection_id, event.into_bytes(), false))
                            .await;
                    }
                    let _ = tx
                        .send(agent_raw(&frame.connection_id, Vec::new(), true))
                        .await;
                }
            }
        }
    });
}

/// Collect raw response frames from a RelayConnection stream until is_eof.
async fn read_until_eof(inbound: &mut tonic::Streaming<RawConnFrame>) -> Vec<u8> {
    let mut data = Vec::new();
    while let Some(item) = inbound.next().await {
        let frame = item.expect("frame ok");
        data.extend_from_slice(&frame.payload);
        if frame.is_eof {
            break;
        }
    }
    data
}

// Routed chunked upload + chunked download: the sidecar streams several upload
// frames; the echo agent returns them as a chunked download.
#[tokio::test]
async fn e2e_routed_chunked_upload_and_download() {
    let url = start_broker(AuthService::new(
        AuthMode::SessionId,
        None,
        None,
        None,
        None,
    ))
    .await;
    spawn_agent(&url, None, App::Echo).await;

    let mut client = connect(&url).await;
    let (tx, rx) = mpsc::channel::<RawConnFrame>(16);
    tx.send(sidecar_raw("c1", b"UP1", false)).await.unwrap();

    let mut inbound = client
        .relay_connection(Request::new(ReceiverStream::new(rx)))
        .await
        .unwrap()
        .into_inner();

    // Stream more upload chunks, then close the client half.
    tx.send(sidecar_raw("c1", b"UP2", false)).await.unwrap();
    tx.send(sidecar_raw("c1", b"UP3", false)).await.unwrap();
    tx.send(sidecar_raw("c1", b"", true)).await.unwrap();

    let got = read_until_eof(&mut inbound).await;
    assert_eq!(got, b"UP1UP2UP3");
}

// Routed server-sent events: a single opening frame yields a streamed sequence
// of SSE events delivered in order, terminated by is_eof.
#[tokio::test]
async fn e2e_routed_server_sent_events() {
    let url = start_broker(AuthService::new(
        AuthMode::SessionId,
        None,
        None,
        None,
        None,
    ))
    .await;
    spawn_agent(&url, None, App::Sse).await;

    let mut client = connect(&url).await;
    let (tx, rx) = mpsc::channel::<RawConnFrame>(16);
    tx.send(sidecar_raw("sse", b"GET /events", false))
        .await
        .unwrap();

    let mut inbound = client
        .relay_connection(Request::new(ReceiverStream::new(rx)))
        .await
        .unwrap()
        .into_inner();

    let got = read_until_eof(&mut inbound).await;
    let text = String::from_utf8(got).unwrap();
    assert_eq!(
        text,
        "event: tick\ndata: 1\n\nevent: tick\ndata: 2\n\nevent: tick\ndata: 3\n\n"
    );
}

// OIDC auth path, success case — exercised in signed-token mode (same validate
// seam). A valid token registers the session and receives the ack.
#[tokio::test]
async fn e2e_auth_success_registers_session() {
    let secret = "test-secret";
    let url = start_broker(AuthService::new(
        AuthMode::SignedToken,
        Some(secret.into()),
        None,
        None,
        None,
    ))
    .await;
    // spawn_agent asserts it receives a SessionAck.
    spawn_agent(&url, Some(make_jwt(secret)), App::Echo).await;
}

// OIDC auth path, failure case — an invalid token is rejected on the tunnel
// stream before the session is registered.
#[tokio::test]
async fn e2e_auth_failure_rejects_session() {
    let url = start_broker(AuthService::new(
        AuthMode::SignedToken,
        Some("the-real-secret".into()),
        None,
        None,
        None,
    ))
    .await;

    let mut client = connect(&url).await;
    let (tx, rx) = mpsc::channel::<AgentMessage>(8);
    tx.send(register_msg(SESSION)).await.unwrap();

    let mut request = Request::new(ReceiverStream::new(rx));
    request.metadata_mut().insert(
        "authorization",
        make_jwt("a-different-secret").parse().unwrap(),
    );

    let mut inbound = client.open_tunnel(request).await.unwrap().into_inner();
    let first = inbound.next().await.expect("a response");
    let err = first.expect_err("expected an auth rejection, not an ack");
    assert_eq!(err.code(), Code::Unauthenticated);
}

// Outbound SOCKS path with a (private) DNS name: the broker resolves the target
// hostname inside the cloud network and proxies bytes both ways.
#[tokio::test]
async fn e2e_outbound_tunnel_with_dns_name() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Stand-in for an in-cloud target reached by a private DNS name.
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut sock, _) = target.accept().await.unwrap();
        let mut buf = [0u8; 4];
        sock.read_exact(&mut buf).await.unwrap();
        sock.write_all(&buf).await.unwrap(); // echo
    });

    let url = start_broker(AuthService::new(
        AuthMode::SessionId,
        None,
        None,
        None,
        None,
    ))
    .await;
    // A registered session is required before outbound is allowed.
    spawn_agent(&url, None, App::Echo).await;

    let mut client = connect(&url).await;
    let (tx, rx) = mpsc::channel::<OutboundClientMsg>(8);
    // "localhost" is a DNS name (not an IP literal), exercising broker-side
    // resolution — the same path a private name like db.internal takes in cloud.
    tx.send(OutboundClientMsg {
        payload: Some(outbound_client_msg::Payload::Connect(OutboundConnect {
            session_id: SESSION.into(),
            host: "localhost".into(),
            port: target_port as u32,
        })),
    })
    .await
    .unwrap();

    let mut inbound = client
        .outbound_tunnel(Request::new(ReceiverStream::new(rx)))
        .await
        .unwrap()
        .into_inner();

    let ack = inbound.next().await.expect("ack").expect("ack ok");
    match ack.payload {
        Some(outbound_server_msg::Payload::Ack(a)) => {
            assert!(a.success, "outbound connect failed: {}", a.error)
        }
        other => panic!("expected an OutboundConnectAck, got {other:?}"),
    }

    tx.send(OutboundClientMsg {
        payload: Some(outbound_client_msg::Payload::Data(b"PING".to_vec())),
    })
    .await
    .unwrap();

    // Read the echoed bytes back.
    let mut got = Vec::new();
    while got.len() < 4 {
        match inbound
            .next()
            .await
            .expect("data")
            .expect("data ok")
            .payload
        {
            Some(outbound_server_msg::Payload::Data(d)) => got.extend_from_slice(&d),
            Some(outbound_server_msg::Payload::Fin(_)) => break,
            _ => {}
        }
    }
    assert_eq!(got, b"PING");
}

fn make_jwt(secret: &str) -> String {
    use jsonwebtoken::{encode, EncodingKey, Header};

    #[derive(serde::Serialize)]
    struct Claims {
        exp: u64,
        allowed_services: Option<Vec<String>>,
    }

    encode(
        &Header::default(),
        &Claims {
            exp: 9_999_999_999,
            allowed_services: None,
        },
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}
