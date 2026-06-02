use std::convert::Infallible;

use bytes::Bytes;
use futures::StreamExt;
use http::{Request, Response};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{error, info};

use detour_proto::detour::{
    agent_message, AgentMessage, Header, RawConnFrame, RelayRequest, RelayResponse,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn forward(
    req: RelayRequest,
    local_port: u16,
    tx: mpsc::Sender<AgentMessage>,
    body_rx: mpsc::Receiver<Bytes>,
) {
    let request_id = req.request_id.clone();
    info!(request_id = %request_id, method = %req.method, path = %req.path, "forwarding request");

    let result = do_forward(req, local_port, body_rx).await;

    match result {
        Ok((status, headers, mut body)) => {
            let mut headers = Some(
                headers
                    .into_iter()
                    .map(|(k, v)| Header { name: k, value: v })
                    .collect::<Vec<_>>(),
            );

            while let Some(frame) = body.frame().await {
                match frame {
                    Ok(frame) => {
                        if let Ok(data) = frame.into_data() {
                            let response_msg = AgentMessage {
                                payload: Some(agent_message::Payload::Response(RelayResponse {
                                    request_id: request_id.clone(),
                                    status_code: status as u32,
                                    headers: headers.take().unwrap_or_default(),
                                    body_chunk: data.to_vec(),
                                    end_of_body: false,
                                })),
                            };
                            if tx.send(response_msg).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        error!(request_id = %request_id, error = %e, "response body stream failed");
                        break;
                    }
                }
            }

            let response_msg = AgentMessage {
                payload: Some(agent_message::Payload::Response(RelayResponse {
                    request_id: request_id.clone(),
                    status_code: status as u32,
                    headers: headers.take().unwrap_or_default(),
                    body_chunk: Vec::new(),
                    end_of_body: true,
                })),
            };
            let _ = tx.send(response_msg).await;
        }
        Err(e) => {
            error!(request_id = %request_id, error = %e, "forward failed");
            let response_msg = AgentMessage {
                payload: Some(agent_message::Payload::Response(RelayResponse {
                    request_id,
                    status_code: 502,
                    headers: vec![],
                    body_chunk: b"Bad Gateway".to_vec(),
                    end_of_body: true,
                })),
            };
            let _ = tx.send(response_msg).await;
        }
    }
}

/// Raw byte-stream forwarder for a single intercepted connection (US-003).
///
/// `open` is the broker's opening frame (carries connection_id, service_name and
/// any initial payload). The agent dials the local upstream on `local_port` and
/// pumps bytes both ways: upstream → broker as `AgentMessage::Raw` frames tagged
/// with the same connection_id, and broker → upstream via `broker_rx`. is_eof on
/// either side closes the matching connection half.
pub async fn forward_connection(
    open: RawConnFrame,
    local_port: u16,
    tx: mpsc::Sender<AgentMessage>,
    mut broker_rx: mpsc::Receiver<RawConnFrame>,
) {
    let connection_id = open.connection_id.clone();
    info!(connection_id = %connection_id, service = %open.service_name, "forwarding raw connection");

    let stream = match TcpStream::connect(("127.0.0.1", local_port)).await {
        Ok(s) => s,
        Err(e) => {
            error!(connection_id = %connection_id, error = %e, "raw upstream dial failed");
            let _ = tx.send(raw_frame(&connection_id, Vec::new(), true)).await;
            return;
        }
    };

    let (mut tcp_rx, mut tcp_tx) = stream.into_split();

    // Initial payload carried on the opening frame.
    if !open.payload.is_empty() && tcp_tx.write_all(&open.payload).await.is_err() {
        let _ = tx.send(raw_frame(&connection_id, Vec::new(), true)).await;
        return;
    }
    // upstream → broker (agent emits AgentMessage::Raw frames)
    let tx_up = tx.clone();
    let cid_up = connection_id.clone();
    let upstream_to_broker = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match tcp_rx.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = tx_up.send(raw_frame(&cid_up, Vec::new(), true)).await;
                    break;
                }
                Ok(n) => {
                    if tx_up
                        .send(raw_frame(&cid_up, buf[..n].to_vec(), false))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    if open.is_eof {
        // Client closed its half on the opening frame, so there is nothing more
        // to pump broker → upstream. Close the write half and let the read half
        // drain. Waiting on broker_rx here would block until the sidecar drops
        // the stream, hanging this task.
        let _ = tcp_tx.shutdown().await;
    } else {
        // broker → upstream. The read half stays open so the response keeps
        // flowing until the upstream EOFs.
        while let Some(frame) = broker_rx.recv().await {
            if !frame.payload.is_empty() && tcp_tx.write_all(&frame.payload).await.is_err() {
                break;
            }
            if frame.is_eof {
                break;
            }
        }
        // The client half ended — via an is_eof frame, the broker stream closing
        // (client disconnect), or a write error. In every case close the upstream
        // write half so it sees EOF and the response can drain; otherwise the
        // read pump would block forever and leak this task.
        let _ = tcp_tx.shutdown().await;
    }

    // Keep relaying the upstream → broker half until the connection fully closes.
    let _ = upstream_to_broker.await;
}

fn raw_frame(connection_id: &str, payload: Vec<u8>, is_eof: bool) -> AgentMessage {
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

async fn do_forward(
    req: RelayRequest,
    local_port: u16,
    body_rx: mpsc::Receiver<Bytes>,
) -> anyhow::Result<(u16, Vec<(String, String)>, Incoming)> {
    let uri = format!("http://127.0.0.1:{}{}", local_port, req.path);

    let mut builder = Request::builder().method(req.method.as_str()).uri(&uri);

    for h in &req.headers {
        builder = builder.header(h.name.as_str(), h.value.as_str());
    }

    let body_stream =
        ReceiverStream::new(body_rx).map(|chunk| Ok::<_, Infallible>(Frame::data(chunk)));
    let body = StreamBody::new(body_stream);
    let request = builder.body(body)?;

    let client: Client<_, StreamBody<_>> = Client::builder(TokioExecutor::new()).build_http();

    let response: Response<Incoming> = client.request(request).await?;
    let status = response.status().as_u16();

    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    Ok((status, headers, response.into_body()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn open_frame(connection_id: &str, payload: Vec<u8>, is_eof: bool) -> RawConnFrame {
        RawConnFrame {
            session_id: "s".into(),
            connection_id: connection_id.to_string(),
            payload,
            is_eof,
            service_name: "svc".into(),
        }
    }

    // Spawns an upstream that echoes "PONG" after reading the request, then
    // closes. Verifies forward_connection pumps the opening payload upstream and
    // relays the upstream bytes back as AgentMessage::Raw, ending with is_eof.
    #[tokio::test]
    async fn forward_connection_pumps_both_halves() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let upstream = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            sock.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"PING");
            sock.write_all(b"PONG").await.unwrap();
            // drop closes the upstream write half -> EOF to the agent
        });

        let (tx, mut rx) = mpsc::channel::<AgentMessage>(16);
        let (_broker_tx, broker_rx) = mpsc::channel::<RawConnFrame>(16);

        // Opening frame carries the client's "PING" and immediately closes the
        // client→upstream half.
        let open = open_frame("conn-1", b"PING".to_vec(), true);
        let handle = tokio::spawn(async move {
            forward_connection(open, port, tx, broker_rx).await;
        });

        // Collect frames the agent sends back to the broker.
        let mut data = Vec::new();
        let mut saw_eof = false;
        while let Some(msg) = rx.recv().await {
            let Some(agent_message::Payload::Raw(frame)) = msg.payload else {
                panic!("expected raw frame");
            };
            assert_eq!(frame.connection_id, "conn-1");
            data.extend_from_slice(&frame.payload);
            if frame.is_eof {
                saw_eof = true;
                break;
            }
        }

        assert_eq!(data, b"PONG");
        assert!(saw_eof, "agent must emit a closing is_eof frame");

        handle.await.unwrap();
        upstream.await.unwrap();
    }

    // A failed upstream dial must surface a closing is_eof frame so the broker
    // and sidecar tear the connection down rather than hanging.
    #[tokio::test]
    async fn forward_connection_dial_failure_emits_eof() {
        // Bind then drop to obtain a port nothing is listening on.
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };

        let (tx, mut rx) = mpsc::channel::<AgentMessage>(16);
        let (_broker_tx, broker_rx) = mpsc::channel::<RawConnFrame>(16);

        forward_connection(open_frame("conn-2", Vec::new(), false), port, tx, broker_rx).await;

        let msg = rx.recv().await.expect("expected a closing frame");
        let Some(agent_message::Payload::Raw(frame)) = msg.payload else {
            panic!("expected raw frame");
        };
        assert_eq!(frame.connection_id, "conn-2");
        assert!(frame.is_eof);
    }

    // ── US-012 streaming robustness ─────────────────────────────────────────

    /// Spawn a TCP echo server; returns its port. Each connection echoes bytes
    /// back and closes its write half when the client half EOFs.
    async fn spawn_echo() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });
        port
    }

    /// Drain agent → broker frames until is_eof, returning the concatenated
    /// payload. Asserts the connection_id is stable and the task tears down.
    async fn collect_until_eof(rx: &mut mpsc::Receiver<AgentMessage>, cid: &str) -> Vec<u8> {
        let mut data = Vec::new();
        while let Some(msg) = rx.recv().await {
            let Some(agent_message::Payload::Raw(frame)) = msg.payload else {
                panic!("expected raw frame");
            };
            assert_eq!(frame.connection_id, cid);
            data.extend_from_slice(&frame.payload);
            if frame.is_eof {
                break;
            }
        }
        data
    }

    // Empty body: opening frame closes the client half immediately with no
    // payload. The agent must close cleanly and emit a single is_eof frame.
    #[tokio::test]
    async fn forward_connection_empty_body_closes_cleanly() {
        let port = spawn_echo().await;
        let (tx, mut rx) = mpsc::channel::<AgentMessage>(16);
        let (_btx, broker_rx) = mpsc::channel::<RawConnFrame>(16);

        let handle = tokio::spawn(forward_connection(
            open_frame("empty", Vec::new(), true),
            port,
            tx,
            broker_rx,
        ));

        let data = collect_until_eof(&mut rx, "empty").await;
        assert!(data.is_empty());
        handle.await.unwrap();
    }

    // Chunked upload: opening payload plus several continuation frames, then an
    // is_eof frame. The echo upstream returns the full concatenation in order.
    #[tokio::test]
    async fn forward_connection_chunked_upload_streams_in_order() {
        let port = spawn_echo().await;
        let (tx, mut rx) = mpsc::channel::<AgentMessage>(64);
        let (btx, broker_rx) = mpsc::channel::<RawConnFrame>(16);

        let handle = tokio::spawn(forward_connection(
            open_frame("chunk", b"AAA".to_vec(), false),
            port,
            tx,
            broker_rx,
        ));

        btx.send(open_frame("chunk", b"BBB".to_vec(), false))
            .await
            .unwrap();
        btx.send(open_frame("chunk", b"CCC".to_vec(), false))
            .await
            .unwrap();
        btx.send(open_frame("chunk", Vec::new(), true))
            .await
            .unwrap();

        let data = collect_until_eof(&mut rx, "chunk").await;
        assert_eq!(data, b"AAABBBCCC");
        handle.await.unwrap();
    }

    // Client disconnect mid-stream: the broker stream closes WITHOUT an is_eof
    // frame. forward_connection must still close the upstream write half so the
    // response drains and the task exits — no leaked/hung connection.
    #[tokio::test]
    async fn forward_connection_client_disconnect_terminates() {
        let port = spawn_echo().await;
        let (tx, mut rx) = mpsc::channel::<AgentMessage>(16);
        let (btx, broker_rx) = mpsc::channel::<RawConnFrame>(16);

        let handle = tokio::spawn(forward_connection(
            open_frame("drop", b"X".to_vec(), false),
            port,
            tx,
            broker_rx,
        ));

        // Client vanished without a clean eof.
        drop(btx);

        let data = collect_until_eof(&mut rx, "drop").await;
        assert_eq!(data, b"X");
        // The task must complete promptly; a hang here means a leaked connection.
        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("forward_connection leaked after client disconnect")
            .unwrap();
    }

    // Long-running stream: many small frames with a bounded broker channel
    // (capacity 1) exercises backpressure — send() blocks until the pump drains,
    // and order/teardown are preserved.
    #[tokio::test]
    async fn forward_connection_long_stream_with_backpressure() {
        let port = spawn_echo().await;
        let (tx, mut rx) = mpsc::channel::<AgentMessage>(8);
        let (btx, broker_rx) = mpsc::channel::<RawConnFrame>(1);

        let handle = tokio::spawn(forward_connection(
            open_frame("long", Vec::new(), false),
            port,
            tx,
            broker_rx,
        ));

        let writer = tokio::spawn(async move {
            for i in 0..200u32 {
                let byte = (b'0' + (i % 10) as u8) as char;
                let chunk = byte.to_string().repeat(4).into_bytes();
                // A capacity-1 channel makes this await apply backpressure.
                btx.send(open_frame("long", chunk, false)).await.unwrap();
            }
            btx.send(open_frame("long", Vec::new(), true))
                .await
                .unwrap();
        });

        let data = collect_until_eof(&mut rx, "long").await;
        assert_eq!(data.len(), 200 * 4);
        // Bytes arrive in send order (echoed verbatim).
        let mut expected = Vec::new();
        for i in 0..200u32 {
            let byte = b'0' + (i % 10) as u8;
            expected.extend(std::iter::repeat(byte).take(4));
        }
        assert_eq!(data, expected);

        writer.await.unwrap();
        handle.await.unwrap();
    }
}
