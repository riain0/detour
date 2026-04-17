use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{error, info, warn};
use uuid::Uuid;

use detour_core::{AuthMode, ServiceRoute, SessionId, SessionRecord};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use detour_proto::detour::{
    agent_message, broker_message, detour_server::Detour, outbound_client_msg, outbound_server_msg,
    AgentMessage, BrokerMessage, LookupRequest, LookupResponse, OutboundClientMsg,
    OutboundConnectAck, OutboundServerMsg, RelayRequestMsg, RelayResponse, RelayResponseMsg,
    SessionAck,
};

use crate::auth::AuthService;
use crate::connections::{ConnectionMap, PendingRequests};
use crate::registry::SessionRegistry;

/// How long relay_request waits for the agent to respond before giving up.
const RELAY_TIMEOUT: Duration = Duration::from_secs(30);

pub struct RelayService {
    pub registry:         Arc<dyn SessionRegistry>,
    pub connections:      ConnectionMap,
    pub pending_requests: PendingRequests,
    pub auth:             Arc<AuthService>,
    pub broker_id:        String,
    pub ttl_secs:         u64,
}

#[tonic::async_trait]
impl Detour for RelayService {
    type OpenTunnelStream    = ReceiverStream<Result<BrokerMessage, Status>>;
    type RelayRequestStream  = ReceiverStream<Result<RelayResponseMsg, Status>>;
    type OutboundTunnelStream = ReceiverStream<Result<OutboundServerMsg, Status>>;

    async fn open_tunnel(
        &self,
        request: Request<Streaming<AgentMessage>>,
    ) -> Result<Response<Self::OpenTunnelStream>, Status> {
        let (tx, rx) = mpsc::channel::<Result<BrokerMessage, Status>>(64);
        let mut stream = request.into_inner();

        let registry         = Arc::clone(&self.registry);
        let connections      = self.connections.clone();
        let pending_requests = self.pending_requests.clone();
        let auth             = Arc::clone(&self.auth);
        let broker_id        = self.broker_id.clone();
        let ttl_secs         = self.ttl_secs;
        let tx_clone         = tx.clone();

        tokio::spawn(async move {
            let mut session_id_opt: Option<SessionId> = None;

            while let Some(Ok(msg)) = stream.next().await {
                match msg.payload {
                    Some(agent_message::Payload::Register(reg)) => {
                        let sid = match SessionId::from_string(reg.session_id.clone()) {
                            Ok(s)  => s,
                            Err(e) => {
                                error!(error = %e, "invalid session id");
                                let _ = tx_clone
                                    .send(Err(Status::invalid_argument(e.to_string())))
                                    .await;
                                return;
                            }
                        };

                        if let Err(e) = auth.validate(&sid, None) {
                            let _ = tx_clone.send(Err(Status::unauthenticated(e.to_string()))).await;
                            return;
                        }

                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();

                        let routes: Vec<ServiceRoute> = reg.routes.into_iter()
                            .map(|r| ServiceRoute {
                                service_name: r.service_name,
                                local_port:   r.local_port as u16,
                            })
                            .collect();

                        let service_summary = routes.iter()
                            .map(|r| r.service_name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");

                        let record = SessionRecord {
                            session_id:      sid.clone(),
                            connection_id:   Uuid::new_v4().to_string(),
                            broker_instance: broker_id.clone(),
                            auth_mode:       AuthMode::SessionId,
                            registered_at:   now,
                            last_heartbeat:  now,
                            routes,
                        };

                        if let Err(e) = registry.register(record).await {
                            let _ = tx_clone.send(Err(Status::internal(e.to_string()))).await;
                            return;
                        }

                        connections.insert(&sid, tx_clone.clone()).await;
                        session_id_opt = Some(sid.clone());

                        info!(session_id = %sid, services = %service_summary, "session registered");

                        let _ = tx_clone.send(Ok(BrokerMessage {
                            payload: Some(broker_message::Payload::Ack(SessionAck {
                                session_id: sid.to_string(),
                                ttl:        ttl_secs,
                            })),
                        })).await;
                    }

                    Some(agent_message::Payload::Heartbeat(hb)) => {
                        if let Ok(sid) = SessionId::from_string(hb.session_id) {
                            let _ = registry.heartbeat(&sid).await;
                        }
                    }

                    Some(agent_message::Payload::Response(resp)) => {
                        // Agent has finished handling a relayed request. Deliver the
                        // response to whichever relay_request call is waiting for it.
                        if !pending_requests.complete(resp).await {
                            warn!("received RelayResponse for unknown request_id — dropped");
                        }
                    }

                    None => {}
                }
            }

            // Agent disconnected — clean up
            if let Some(sid) = session_id_opt {
                connections.remove(&sid).await;
                let _ = registry.expire(&sid).await;
                info!(session_id = %sid, "session expired on disconnect");
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn relay_request(
        &self,
        request: Request<Streaming<RelayRequestMsg>>,
    ) -> Result<Response<Self::RelayRequestStream>, Status> {
        let (resp_tx, resp_rx) = mpsc::channel::<Result<RelayResponseMsg, Status>>(4);
        let mut stream         = request.into_inner();
        let connections        = self.connections.clone();
        let pending_requests   = self.pending_requests.clone();

        tokio::spawn(async move {
            // Read the first chunk to get session routing info.
            // In practice the sidecar sends the whole (buffered) request in one chunk.
            let chunk = match stream.next().await {
                Some(Ok(c)) => c,
                Some(Err(e)) => {
                    let _ = resp_tx.send(Err(Status::internal(e.to_string()))).await;
                    return;
                }
                None => return,
            };

            let session_id = match SessionId::from_string(chunk.session_id.clone()) {
                Ok(s)  => s,
                Err(e) => {
                    let _ = resp_tx.send(Err(Status::invalid_argument(e.to_string()))).await;
                    return;
                }
            };

            let agent_tx = match connections.get(&session_id).await {
                Some(t) => t,
                None    => {
                    warn!(session_id = %session_id, "no tunnel found for session");
                    let _ = resp_tx.send(Err(Status::not_found("session not found"))).await;
                    return;
                }
            };

            // Register a rendezvous slot so open_tunnel can deliver the response.
            let (oneshot_tx, oneshot_rx) = tokio::sync::oneshot::channel::<RelayResponse>();
            let request_id = pending_requests.register(oneshot_tx).await;

            // Push the request to the agent over its OpenTunnel stream.
            let relay_msg = BrokerMessage {
                payload: Some(broker_message::Payload::Request(
                    detour_proto::detour::RelayRequest {
                        request_id:   request_id.clone(),
                        method:       chunk.method,
                        path:         chunk.path,
                        headers:      chunk.headers,
                        body_chunk:   chunk.body_chunk,
                        end_of_body:  chunk.end_of_body,
                        service_name: chunk.service_name,
                    },
                )),
            };

            if agent_tx.send(Ok(relay_msg)).await.is_err() {
                pending_requests.remove(&request_id).await;
                let _ = resp_tx.send(Err(Status::unavailable("agent tunnel closed"))).await;
                return;
            }

            // Wait for the agent to respond, with a timeout.
            let agent_response = tokio::time::timeout(RELAY_TIMEOUT, oneshot_rx).await;

            match agent_response {
                Ok(Ok(resp)) => {
                    let msg = RelayResponseMsg {
                        request_id:  resp.request_id,
                        status_code: resp.status_code,
                        headers:     resp.headers,
                        body_chunk:  resp.body_chunk,
                        end_of_body: resp.end_of_body,
                    };
                    let _ = resp_tx.send(Ok(msg)).await;
                }
                Ok(Err(_)) => {
                    // Oneshot sender dropped — agent disconnected mid-request
                    let _ = resp_tx.send(Err(Status::unavailable("agent disconnected during relay"))).await;
                }
                Err(_) => {
                    pending_requests.remove(&request_id).await;
                    let _ = resp_tx.send(Err(Status::deadline_exceeded("agent relay timeout"))).await;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(resp_rx)))
    }

    async fn lookup_session(
        &self,
        request: Request<LookupRequest>,
    ) -> Result<Response<LookupResponse>, Status> {
        let req    = request.into_inner();
        let sid    = SessionId::from_string(req.session_id)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        match self.registry.lookup(&sid, &req.service_name).await {
            Ok(Some(record)) => Ok(Response::new(LookupResponse {
                found:     true,
                auth_mode: record.auth_mode.to_string(),
            })),
            Ok(None) => Ok(Response::new(LookupResponse {
                found:     false,
                auth_mode: String::new(),
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }

    async fn outbound_tunnel(
        &self,
        request: Request<Streaming<OutboundClientMsg>>,
    ) -> Result<Response<Self::OutboundTunnelStream>, Status> {
        let (tx, rx) = mpsc::channel::<Result<OutboundServerMsg, Status>>(64);
        let mut stream = request.into_inner();
        let registry = Arc::clone(&self.registry);

        tokio::spawn(async move {
            // First message must be OutboundConnect
            let first = match stream.next().await {
                Some(Ok(msg)) => msg,
                _ => return,
            };

            let connect = match first.payload {
                Some(outbound_client_msg::Payload::Connect(c)) => c,
                _ => {
                    let _ = tx.send(Err(Status::invalid_argument("first message must be OutboundConnect"))).await;
                    return;
                }
            };

            // Validate session exists (empty service_name = any service)
            let sid = match SessionId::from_string(connect.session_id) {
                Ok(s)  => s,
                Err(e) => {
                    let _ = tx.send(Err(Status::invalid_argument(e.to_string()))).await;
                    return;
                }
            };

            match registry.lookup(&sid, "").await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    let _ = tx.send(Ok(OutboundServerMsg {
                        payload: Some(outbound_server_msg::Payload::Ack(OutboundConnectAck {
                            success: false,
                            error:   "session not found".into(),
                        })),
                    })).await;
                    return;
                }
                Err(e) => {
                    let _ = tx.send(Err(Status::internal(e.to_string()))).await;
                    return;
                }
            }

            // Connect to target from inside VPC
            let addr = format!("{}:{}", connect.host, connect.port);
            let tcp = match TcpStream::connect(&addr).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = tx.send(Ok(OutboundServerMsg {
                        payload: Some(outbound_server_msg::Payload::Ack(OutboundConnectAck {
                            success: false,
                            error:   e.to_string(),
                        })),
                    })).await;
                    return;
                }
            };

            let _ = tx.send(Ok(OutboundServerMsg {
                payload: Some(outbound_server_msg::Payload::Ack(OutboundConnectAck {
                    success: true,
                    error:   String::new(),
                })),
            })).await;

            let (mut tcp_rx, mut tcp_tx) = tcp.into_split();

            // TCP → gRPC
            let tx_clone = tx.clone();
            let tcp_to_grpc = tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                loop {
                    match tcp_rx.read(&mut buf).await {
                        Ok(0) | Err(_) => {
                            let _ = tx_clone.send(Ok(OutboundServerMsg {
                                payload: Some(outbound_server_msg::Payload::Fin(true)),
                            })).await;
                            break;
                        }
                        Ok(n) => {
                            if tx_clone.send(Ok(OutboundServerMsg {
                                payload: Some(outbound_server_msg::Payload::Data(buf[..n].to_vec())),
                            })).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });

            // gRPC → TCP
            while let Some(Ok(msg)) = stream.next().await {
                match msg.payload {
                    Some(outbound_client_msg::Payload::Data(data)) => {
                        if tcp_tx.write_all(&data).await.is_err() { break; }
                    }
                    Some(outbound_client_msg::Payload::Fin(true)) | None => break,
                    _ => {}
                }
            }

            tcp_to_grpc.abort();
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
