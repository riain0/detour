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
        // broker → upstream. is_eof closes the upstream write half; the read half
        // stays open so the response keeps flowing until upstream EOFs.
        while let Some(frame) = broker_rx.recv().await {
            if !frame.payload.is_empty() && tcp_tx.write_all(&frame.payload).await.is_err() {
                break;
            }
            if frame.is_eof {
                let _ = tcp_tx.shutdown().await;
                break;
            }
        }
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

    let body_stream = ReceiverStream::new(body_rx)
        .map(|chunk| Ok::<_, Infallible>(Frame::data(chunk)));
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
}
