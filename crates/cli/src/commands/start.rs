use std::time::Duration;

use clap::Args;

use detour_agent::{AgentConfig, AgentHandle};
use detour_core::{AuthMode, ServiceRoute, TunnelStatus};

#[derive(Args)]
pub struct StartArgs {
    /// Service route(s) in "service-name:local-port" format (repeatable)
    #[arg(long = "route", value_name = "SERVICE:PORT")]
    pub routes: Vec<String>,

    /// Broker URL (overrides DETOUR_BROKER_URL env var)
    #[arg(
        long,
        env = "DETOUR_BROKER_URL",
        default_value = "http://localhost:50051"
    )]
    pub broker: String,

    /// Output format: "human" or "json"
    #[arg(long, default_value = "human")]
    pub output: String,

    /// Auth mode: "session-id" or "signed-token"
    #[arg(long, default_value = "session-id")]
    pub auth_mode: String,

    /// Local port for the outbound SOCKS5 proxy (set LD_PRELOAD + DETOUR_SOCKS5_PORT to use)
    #[arg(long, default_value = "1081")]
    pub socks5_port: u16,
}

pub async fn run(args: StartArgs) -> anyhow::Result<()> {
    if args.routes.is_empty() {
        anyhow::bail!("at least one --route SERVICE:PORT is required");
    }

    let auth_mode: AuthMode = args
        .auth_mode
        .parse()
        .map_err(|e: detour_core::DetourError| anyhow::anyhow!(e))?;

    let routes = args
        .routes
        .iter()
        .map(|r| parse_route(r))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let config = AgentConfig {
        broker_url: args.broker.clone(),
        routes,
        auth_mode,
        socks5_port: args.socks5_port,
    };

    let handle = AgentHandle::start(config)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    let sessions = handle.sessions();

    if args.output != "json" {
        eprintln!();
        eprintln!("  Detour v{}", env!("CARGO_PKG_VERSION"));
        eprintln!("  Connecting to {} ...", args.broker);
    }

    // Wait up to 10s for all tunnels to connect
    let connected = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match handle.status() {
                TunnelStatus::Connected => return true,
                TunnelStatus::Stopped => return false,
                _ => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    })
    .await
    .unwrap_or(false);

    if args.output == "json" {
        let sessions_json: Vec<_> = sessions
            .iter()
            .map(|(svc, sid)| {
                serde_json::json!({
                    "service":    svc,
                    "session_id": sid.as_str(),
                })
            })
            .collect();
        let event = serde_json::json!({
            "event":      if connected { "ready" } else { "error" },
            "ts":         now_rfc3339(),
            "sessions":   sessions_json,
            "broker_url": args.broker,
        });
        println!("{}", event);
        if !connected {
            anyhow::bail!("failed to connect to broker");
        }
    } else if connected {
        // All sessions share the same session_id — print it once
        if let Some((_, sid)) = sessions.first() {
            eprintln!();
            eprintln!("  X-Route-To: {}", sid);
            eprintln!();
            for (svc, _) in &sessions {
                eprintln!(
                    "  {}  →  localhost:{}",
                    svc,
                    args.routes
                        .iter()
                        .find(|r| r.starts_with(&format!("{}:", svc)))
                        .and_then(|r| r.rsplit(':').next())
                        .unwrap_or("?")
                );
            }
            eprintln!();
            eprintln!("  Status: connected");
            eprintln!();
        }
    } else {
        anyhow::bail!("failed to connect to broker — check broker URL and network");
    }

    tokio::signal::ctrl_c().await?;

    handle.stop().await.map_err(|e| anyhow::anyhow!(e))?;

    if args.output == "json" {
        let event = serde_json::json!({
            "event":  "status",
            "ts":     now_rfc3339(),
            "status": "stopped",
        });
        println!("{}", event);
    } else {
        eprintln!("  Tunnel stopped.");
    }

    Ok(())
}

fn parse_route(s: &str) -> anyhow::Result<ServiceRoute> {
    let colon = s
        .rfind(':')
        .ok_or_else(|| anyhow::anyhow!("invalid route {:?}: expected SERVICE:PORT", s))?;
    let service_name = s[..colon].to_string();
    let local_port: u16 = s[colon + 1..]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid port in route {:?}", s))?;
    if service_name.is_empty() {
        anyhow::bail!("service name is empty in route {:?}", s);
    }
    Ok(ServiceRoute {
        service_name,
        local_port,
    })
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}Z", secs)
}
