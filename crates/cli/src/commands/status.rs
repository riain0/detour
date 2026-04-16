use clap::Args;

#[derive(Args)]
pub struct StatusArgs {
    /// Status endpoint port (default: 29876)
    #[arg(long, default_value = "29876")]
    pub port: u16,
}

pub async fn run(args: StatusArgs) -> anyhow::Result<()> {
    let url = format!("http://127.0.0.1:{}/status", args.port);

    let resp = reqwest::get(&url).await;

    match resp {
        Ok(r) => {
            let body: serde_json::Value = r.json().await?;
            let status = body.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");

            if status == "connected" {
                let session_id = body.get("session_id").and_then(|v| v.as_str()).unwrap_or("-");
                let service    = body.get("service").and_then(|v| v.as_str()).unwrap_or("-");
                let port       = body.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
                let broker_url = body.get("broker_url").and_then(|v| v.as_str()).unwrap_or("-");

                println!("Status:     connected");
                println!("Session ID: {}", session_id);
                println!("Service:    {}", service);
                println!("Port:       {}", port);
                println!("Broker:     {}", broker_url);
            } else {
                println!("Status: {}", status);
            }
        }
        Err(_) => {
            println!("Status: stopped (agent not running on port {})", args.port);
        }
    }

    Ok(())
}
