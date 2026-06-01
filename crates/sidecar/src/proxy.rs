use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{Response, StatusCode},
    response::IntoResponse,
};
use bytes::Bytes;
use futures::StreamExt;
use http_body_util::BodyExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tracing::{info, warn};

use detour_proto::detour::{detour_client::DetourClient, Header, RelayRequestMsg};

use crate::inspector::SessionResolver;

#[derive(Clone)]
pub struct ProxyState {
    pub resolver: Arc<dyn SessionResolver>,
    pub app_upstream: String,
    pub broker_client: DetourClient<Channel>,
    pub service_name: String,
    pub log_routed: bool,
    pub max_body_mb: u64,
}

pub async fn handler(State(state): State<ProxyState>, req: Request) -> impl IntoResponse {
    let (parts, body) = req.into_parts();

    // Health check — respond immediately
    if parts.uri.path() == "/healthz" {
        return Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("ok"))
            .unwrap();
    }

    // Check for routing header
    let session = state.resolver.resolve(&parts.headers).await;

    match session {
        Some(record) => {
            if state.log_routed {
                info!(
                    session_id = %record.session_id,
                    method     = %parts.method,
                    path       = %parts.uri,
                    "routing to local"
                );
            }

            let request_id = uuid::Uuid::new_v4().to_string();
            let headers: Vec<Header> = parts
                .headers
                .iter()
                .map(|(k, v)| Header {
                    name: k.to_string(),
                    value: v.to_str().unwrap_or("").to_string(),
                })
                .collect();

            let (relay_tx, relay_rx) = mpsc::channel::<RelayRequestMsg>(16);
            let session_id = record.session_id.to_string();
            let service_name = state.service_name.clone();
            let method = parts.method.to_string();
            let path = parts.uri.to_string();
            let max_bytes = state.max_body_mb * 1024 * 1024;

            tokio::spawn(async move {
                let mut sent_headers = false;
                let mut total_bytes = 0u64;
                let mut body = body;

                while let Some(frame) = body.frame().await {
                    let frame = match frame {
                        Ok(frame) => frame,
                        Err(_) => return,
                    };

                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    total_bytes += data.len() as u64;
                    if total_bytes > max_bytes {
                        return;
                    }

                    let msg = RelayRequestMsg {
                        request_id: request_id.clone(),
                        session_id: session_id.clone(),
                        method: if sent_headers { String::new() } else { method.clone() },
                        path: if sent_headers { String::new() } else { path.clone() },
                        headers: if sent_headers { vec![] } else { headers.clone() },
                        body_chunk: data.to_vec(),
                        end_of_body: false,
                        service_name: service_name.clone(),
                    };
                    if relay_tx.send(msg).await.is_err() {
                        return;
                    }
                    sent_headers = true;
                }

                let _ = relay_tx
                    .send(RelayRequestMsg {
                        request_id,
                        session_id,
                        method: if sent_headers { String::new() } else { method },
                        path: if sent_headers { String::new() } else { path },
                        headers: if sent_headers { vec![] } else { headers },
                        body_chunk: Vec::new(),
                        end_of_body: true,
                        service_name,
                    })
                    .await;
            });

            let stream = ReceiverStream::new(relay_rx);
            let mut client = state.broker_client.clone();

            match client.relay_request(stream).await {
                Ok(resp) => {
                    let mut inbound = resp.into_inner();
                    match inbound.message().await {
                        Ok(Some(msg)) => {
                            let mut builder = Response::builder().status(msg.status_code as u16);
                            for h in &msg.headers {
                                builder = builder.header(h.name.as_str(), h.value.as_str());
                            }

                            if msg.end_of_body {
                                return builder.body(Body::from(msg.body_chunk)).unwrap();
                            }

                            let first_chunk = Ok::<Bytes, std::io::Error>(Bytes::from(msg.body_chunk));
                            let rest = inbound.map(|result| match result {
                                Ok(msg) if msg.end_of_body => Ok(Bytes::new()),
                                Ok(msg) => Ok(Bytes::from(msg.body_chunk)),
                                Err(err) => Err(std::io::Error::other(err.to_string())),
                            });
                            let body_stream: futures::stream::BoxStream<'static, Result<Bytes, std::io::Error>> =
                                Box::pin(futures::stream::once(async move { first_chunk }).chain(rest));

                            return builder.body(Body::from_stream(body_stream)).unwrap();
                        }
                        Ok(None) => Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .body(Body::from("relay closed before response"))
                            .unwrap(),
                        Err(e) => {
                            warn!(error = %e, "relay response stream failed");
                            Response::builder()
                                .status(StatusCode::BAD_GATEWAY)
                                .body(Body::from(e.to_string()))
                                .unwrap()
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "relay request failed");
                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Body::from(e.to_string()))
                        .unwrap()
                }
            }
        }
        None => passthrough(&parts, collect_body(body).await, &state.app_upstream).await,
    }
}

async fn passthrough(parts: &http::request::Parts, body: Bytes, upstream: &str) -> Response<Body> {
    let path = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let uri = if upstream.starts_with("http://") || upstream.starts_with("https://") {
        format!("{}{}", upstream.trim_end_matches('/'), path)
    } else {
        format!("http://{}{}", upstream, path)
    };

    let client = reqwest::Client::builder().build().unwrap();

    let mut req = client.request(parts.method.clone(), &uri).body(body);

    for (k, v) in &parts.headers {
        if k == "host" {
            continue;
        }
        req = req.header(k, v);
    }

    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let headers = resp.headers().clone();
            let body_bytes = resp.bytes().await.unwrap_or_default();

            let mut builder = Response::builder().status(status.as_u16());
            for (k, v) in &headers {
                builder = builder.header(k, v);
            }
            builder.body(Body::from(body_bytes)).unwrap()
        }
        Err(e) => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(Body::from(e.to_string()))
            .unwrap(),
    }
}

async fn collect_body(body: Body) -> Bytes {
    body.collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default()
}
