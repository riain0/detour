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

use detour_proto::detour::{agent_message, AgentMessage, Header, RelayRequest, RelayResponse};

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
