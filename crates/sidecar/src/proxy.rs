use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{Response, StatusCode},
    response::IntoResponse,
};
use bytes::Bytes;
use http_body_util::BodyExt;
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
            // Collect body (with size guard)
            let max_bytes = state.max_body_mb * 1024 * 1024;
            let body_bytes = match collect_limited(body, max_bytes).await {
                Ok(b) => b,
                Err(e) => {
                    warn!(error = %e, "request body too large or read error");
                    return Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(Body::from("payload too large"))
                        .unwrap();
                }
            };

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

            let chunks = vec![RelayRequestMsg {
                request_id: request_id.clone(),
                session_id: record.session_id.to_string(),
                method: parts.method.to_string(),
                path: parts.uri.to_string(),
                headers,
                body_chunk: body_bytes.to_vec(),
                end_of_body: true,
                service_name: state.service_name.clone(),
            }];

            let stream = tokio_stream::iter(chunks);
            let mut client = state.broker_client.clone();

            match client.relay_request(stream).await {
                Ok(resp) => {
                    let mut inbound = resp.into_inner();
                    if let Ok(Some(msg)) = inbound.message().await {
                        let mut builder = Response::builder().status(msg.status_code as u16);
                        for h in &msg.headers {
                            builder = builder.header(h.name.as_str(), h.value.as_str());
                        }
                        return builder.body(Body::from(msg.body_chunk)).unwrap();
                    }
                    passthrough(&parts, Bytes::new(), &state.app_upstream).await
                }
                Err(e) => {
                    warn!(error = %e, "relay request failed, falling back");
                    passthrough(&parts, body_bytes, &state.app_upstream).await
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

async fn collect_limited(body: Body, max_bytes: u64) -> anyhow::Result<Bytes> {
    let bytes = body.collect().await?.to_bytes();
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!("body exceeds {} bytes limit", max_bytes);
    }
    Ok(bytes)
}
