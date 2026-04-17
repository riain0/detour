use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, ClientTlsConfig};
use tracing::{error, info, warn};

use detour_core::SessionId;
use detour_proto::detour::{
    detour_client::DetourClient, outbound_client_msg, outbound_server_msg, OutboundClientMsg,
    OutboundConnect,
};

pub async fn serve(broker_url: String, session_id: SessionId, port: u16) {
    let addr = format!("127.0.0.1:{}", port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => {
            info!(addr = %addr, "outbound SOCKS5 proxy listening");
            l
        }
        Err(e) => {
            error!(addr = %addr, error = %e, "failed to bind SOCKS5 port");
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let broker_url = broker_url.clone();
                let session_id = session_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, broker_url, session_id).await {
                        warn!(error = %e, "SOCKS5 session error");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "SOCKS5 accept error");
            }
        }
    }
}

async fn handle(
    mut stream: tokio::net::TcpStream,
    broker_url: String,
    session_id: SessionId,
) -> anyhow::Result<()> {
    // SOCKS5 greeting
    let mut buf2 = [0u8; 2];
    stream.read_exact(&mut buf2).await?;
    anyhow::ensure!(buf2[0] == 5, "not SOCKS5");
    let nmethods = buf2[1] as usize;
    let mut _methods = vec![0u8; nmethods];
    stream.read_exact(&mut _methods).await?;
    stream.write_all(&[0x05, 0x00]).await?; // no-auth

    // SOCKS5 CONNECT request
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    anyhow::ensure!(hdr[0] == 5 && hdr[1] == 1, "only SOCKS5 CONNECT supported");

    let host = match hdr[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut hostname = vec![0u8; len[0] as usize];
            stream.read_exact(&mut hostname).await?;
            String::from_utf8(hostname)?
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => anyhow::bail!("unsupported ATYP"),
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    // Open OutboundTunnel gRPC stream to broker
    let mut endpoint = Channel::from_shared(broker_url.clone())?;
    if broker_url.starts_with("https://") {
        endpoint = endpoint.tls_config(ClientTlsConfig::new().with_webpki_roots())?;
    }
    let channel = endpoint.connect().await?;
    let mut client = DetourClient::new(channel);

    let (grpc_tx, grpc_rx) = tokio::sync::mpsc::channel::<OutboundClientMsg>(64);

    grpc_tx.send(OutboundClientMsg {
        payload: Some(outbound_client_msg::Payload::Connect(OutboundConnect {
            session_id: session_id.to_string(),
            host:       host.clone(),
            port:       port as u32,
        })),
    }).await?;

    let response = client.outbound_tunnel(ReceiverStream::new(grpc_rx)).await?;
    let mut inbound = response.into_inner();

    // Wait for connect ack from broker
    match inbound.message().await? {
        Some(msg) => match msg.payload {
            Some(outbound_server_msg::Payload::Ack(ack)) if ack.success => {}
            Some(outbound_server_msg::Payload::Ack(ack)) => {
                stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await.ok();
                anyhow::bail!("broker refused connection: {}", ack.error);
            }
            _ => anyhow::bail!("unexpected first message from broker"),
        },
        None => anyhow::bail!("broker closed stream before ack"),
    }

    // Send SOCKS5 success reply (BND.ADDR = 0.0.0.0, BND.PORT = 0)
    stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

    // Bridge: SOCKS5 client ↔ broker gRPC stream
    let (mut socks_rx, mut socks_tx) = stream.into_split();

    // SOCKS5 client → gRPC
    let grpc_tx2 = grpc_tx.clone();
    let s2g = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match socks_rx.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = grpc_tx2.send(OutboundClientMsg {
                        payload: Some(outbound_client_msg::Payload::Fin(true)),
                    }).await;
                    break;
                }
                Ok(n) => {
                    if grpc_tx2.send(OutboundClientMsg {
                        payload: Some(outbound_client_msg::Payload::Data(buf[..n].to_vec())),
                    }).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // gRPC → SOCKS5 client
    while let Some(msg) = inbound.message().await? {
        match msg.payload {
            Some(outbound_server_msg::Payload::Data(data)) => {
                if socks_tx.write_all(&data).await.is_err() { break; }
            }
            Some(outbound_server_msg::Payload::Fin(true)) | None => break,
            _ => {}
        }
    }

    s2g.abort();
    Ok(())
}
