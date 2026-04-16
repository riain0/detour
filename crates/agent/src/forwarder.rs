use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::sync::mpsc;
use tracing::{error, info};

use detour_proto::detour::{agent_message, AgentMessage, Header, RelayRequest, RelayResponse};

pub async fn forward(req: RelayRequest, local_port: u16, tx: mpsc::Sender<AgentMessage>) {
    let request_id = req.request_id.clone();
    info!(request_id = %request_id, method = %req.method, path = %req.path, "forwarding request");

    let result = do_forward(req, local_port).await;

    match result {
        Ok((status, headers, body)) => {
            let response_msg = AgentMessage {
                payload: Some(agent_message::Payload::Response(RelayResponse {
                    request_id:  request_id.clone(),
                    status_code: status as u32,
                    headers:     headers.into_iter().map(|(k, v)| Header { name: k, value: v }).collect(),
                    body_chunk:  body.to_vec(),
                    end_of_body: true,
                })),
            };
            let _ = tx.send(response_msg).await;
        }
        Err(e) => {
            error!(request_id = %request_id, error = %e, "forward failed");
            let response_msg = AgentMessage {
                payload: Some(agent_message::Payload::Response(RelayResponse {
                    request_id:  request_id,
                    status_code: 502,
                    headers:     vec![],
                    body_chunk:  b"Bad Gateway".to_vec(),
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
) -> anyhow::Result<(u16, Vec<(String, String)>, Bytes)> {
    let uri = format!("http://127.0.0.1:{}{}", local_port, req.path);

    let mut builder = Request::builder()
        .method(req.method.as_str())
        .uri(&uri);

    for h in &req.headers {
        builder = builder.header(h.name.as_str(), h.value.as_str());
    }

    let body  = Full::new(Bytes::from(req.body_chunk));
    let request = builder.body(body)?;

    let client: Client<_, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build_http();

    let response: Response<Incoming> = client.request(request).await?;
    let status = response.status().as_u16();

    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body = response.into_body().collect().await?.to_bytes();

    Ok((status, headers, body))
}
