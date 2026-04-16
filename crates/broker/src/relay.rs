use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{error, info, warn};
use uuid::Uuid;

use detour_core::{AuthMode, SessionId, SessionRecord};
use detour_proto::detour::{
    agent_message, broker_message, detour_server::Detour, AgentMessage, BrokerMessage,
    LookupRequest, LookupResponse, RelayRequestMsg, RelayResponse, RelayResponseMsg, SessionAck,
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
    type OpenTunnelStream = ReceiverStream<Result<BrokerMessage, Status>>;
    type RelayRequestStream = ReceiverStream<Result<RelayResponseMsg, Status>>;

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

                        let record = SessionRecord {
                            session_id:       sid.clone(),
                            connection_id:    Uuid::new_v4().to_string(),
                            broker_instance:  broker_id.clone(),
                            service_name:     reg.service_name.clone(),
                            auth_mode:        AuthMode::SessionId,
                            registered_at:    now,
                            last_heartbeat:   now,
                            allowed_services: reg.allowed_services,
                        };

                        if let Err(e) = registry.register(record).await {
                            let _ = tx_clone.send(Err(Status::internal(e.to_string()))).await;
                            return;
                        }

                        connections.insert(&sid, tx_clone.clone()).await;
                        session_id_opt = Some(sid.clone());

                        info!(session_id = %sid, service = %reg.service_name, "session registered");

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
                        request_id:  request_id.clone(),
                        method:      chunk.method,
                        path:        chunk.path,
                        headers:     chunk.headers,
                        body_chunk:  chunk.body_chunk,
                        end_of_body: chunk.end_of_body,
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
        let id_str = request.into_inner().session_id;
        let sid    = SessionId::from_string(id_str)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        match self.registry.lookup(&sid).await {
            Ok(Some(record)) => Ok(Response::new(LookupResponse {
                found:        true,
                service_name: record.service_name,
                auth_mode:    record.auth_mode.to_string(),
            })),
            Ok(None) => Ok(Response::new(LookupResponse {
                found:        false,
                service_name: String::new(),
                auth_mode:    String::new(),
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }
}
