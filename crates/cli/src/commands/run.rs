use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use anyhow::{bail, Context};
use clap::{Args, Subcommand};
use tokio::process::Command;

use detour_agent::{AgentConfig, AgentHandle};
use detour_core::{AuthMode, TunnelStatus};

use crate::auth::resolve_auth_token;
use crate::commands::env::{load_cloud_run_profile, CloudRunEnvArgs};
use crate::commands::start::{parse_route, wait_until_connected};

#[derive(Args)]
pub struct RunArgs {
    #[command(subcommand)]
    pub command: RunCommand,
}

#[derive(Subcommand)]
pub enum RunCommand {
    /// Run a local process with Cloud Run runtime defaults
    CloudRun(CloudRunRunArgs),
}

#[derive(Args)]
pub struct CloudRunRunArgs {
    /// Cloud Run service name
    #[arg(long)]
    pub service: String,

    /// Cloud Run region
    #[arg(long)]
    pub region: String,

    /// GCP project ID (defaults to active gcloud project)
    #[arg(long)]
    pub project: Option<String>,

    /// Container name inside the service
    #[arg(long)]
    pub container: Option<String>,

    /// Service route in SERVICE:PORT format
    #[arg(long = "route", value_name = "SERVICE:PORT")]
    pub route: String,

    /// Broker URL (overrides DETOUR_BROKER_URL env var)
    #[arg(
        long,
        env = "DETOUR_BROKER_URL",
        default_value = "http://localhost:50051"
    )]
    pub broker: String,

    /// Auth mode: session-id, signed-token, or gcp-oidc
    #[arg(long, default_value = "session-id")]
    pub auth_mode: String,

    /// Local port for the outbound SOCKS5 proxy
    #[arg(long, default_value = "1081")]
    pub socks5_port: u16,

    /// Explicit path to libdetour_layer
    #[arg(long, env = "DETOUR_LAYER_PATH")]
    pub layer_path: Option<PathBuf>,

    /// Skip importing remote Cloud Run env
    #[arg(long, default_value_t = false)]
    pub no_remote_env: bool,

    /// Command to run locally after `--`
    #[arg(required = true, trailing_var_arg = true, last = true)]
    pub command: Vec<String>,
}

pub async fn run(args: RunArgs) -> anyhow::Result<()> {
    match args.command {
        RunCommand::CloudRun(args) => run_cloud_run(args).await,
    }
}

async fn run_cloud_run(args: CloudRunRunArgs) -> anyhow::Result<()> {
    let profile = if args.no_remote_env {
        None
    } else {
        Some(load_cloud_run_profile(&CloudRunEnvArgs {
            service: args.service.clone(),
            region: args.region.clone(),
            project: args.project.clone(),
            container: args.container.clone(),
            output: "shell".to_string(),
        })?)
    };

    let auth_mode: AuthMode = args
        .auth_mode
        .parse()
        .map_err(|e: detour_core::DetourError| anyhow::anyhow!(e))?;
    let route = parse_route(&args.route)?;
    let auth_token = resolve_auth_token(&auth_mode, &args.broker)?;

    let handle = AgentHandle::start(AgentConfig {
        broker_url: args.broker.clone(),
        routes: vec![route.clone()],
        auth_mode,
        auth_token,
        socks5_port: args.socks5_port,
    })
    .await
    .map_err(|e| anyhow::anyhow!(e))?;

    let sessions = handle.sessions();
    let connected = wait_until_connected(&handle).await;
    if !connected {
        let status = handle.status();
        let _ = handle.stop().await;
        match status {
            TunnelStatus::Error(err) => bail!("failed to connect to broker: {}", err),
            _ => bail!("failed to connect to broker"),
        }
    }

    let layer_path = resolve_layer_path(args.layer_path.as_deref())?;

    if let Some((_, sid)) = sessions.first() {
        eprintln!();
        eprintln!("  Detour v{}", env!("CARGO_PKG_VERSION"));
        eprintln!("  Connecting to {} ...", args.broker);
        eprintln!();
        eprintln!("  X-Route-To: {}", sid);
        eprintln!();
        eprintln!("  {}  →  localhost:{}", route.service_name, route.local_port);
        if let Some(profile) = &profile {
            let imported = profile.env_vars.iter().filter(|var| var.value.is_some()).count();
            let unresolved = profile.env_vars.iter().filter(|var| var.value.is_none()).count();
            eprintln!();
            eprintln!(
                "  Runtime: Cloud Run {} ({})",
                profile.service, profile.container_name
            );
            eprintln!("  Env: {} imported, {} unresolved", imported, unresolved);
        }
        eprintln!("  Layer: {}", layer_path.display());
        eprintln!();
    }

    let status = run_child_process(&args, &route, profile.as_ref(), &layer_path).await;
    let _ = handle.stop().await;

    match status {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(err) => Err(err),
    }
}

async fn run_child_process(
    args: &CloudRunRunArgs,
    route: &detour_core::ServiceRoute,
    profile: Option<&crate::commands::env::CloudRunProfile>,
    layer_path: &Path,
) -> anyhow::Result<ExitStatus> {
    let mut child = Command::new(&args.command[0]);
    child.args(&args.command[1..]);
    child.stdin(std::process::Stdio::inherit());
    child.stdout(std::process::Stdio::inherit());
    child.stderr(std::process::Stdio::inherit());

    if let Some(profile) = profile {
        for var in &profile.env_vars {
            if let Some(value) = &var.value {
                if std::env::var_os(&var.name).is_none() {
                    child.env(&var.name, value);
                }
            }
        }

        let unresolved: Vec<_> = profile.env_vars.iter().filter(|var| var.value.is_none()).collect();
        if !unresolved.is_empty() {
            eprintln!(
                "Skipped {} secret-backed env var(s) from Cloud Run; local overrides can still supply them.",
                unresolved.len()
            );
        }
    }

    if std::env::var_os("PORT").is_none() {
        child.env("PORT", route.local_port.to_string());
    }
    child.env("DETOUR_SOCKS5_PORT", args.socks5_port.to_string());
    configure_preload_env(&mut child, layer_path);

    let mut child = child.spawn().with_context(|| {
        format!(
            "failed to start local process {:?}",
            args.command.first().cloned().unwrap_or_default()
        )
    })?;

    tokio::select! {
        status = child.wait() => status.context("failed waiting for local process"),
        _ = tokio::signal::ctrl_c() => {
            let _ = child.kill().await;
            child.wait().await.context("failed waiting for local process after ctrl-c")
        }
    }
}

fn configure_preload_env(child: &mut Command, layer_path: &Path) {
    #[cfg(target_os = "linux")]
    {
        child.env("LD_PRELOAD", prepend_env_path("LD_PRELOAD", layer_path));
    }

    #[cfg(target_os = "macos")]
    {
        child.env(
            "DYLD_INSERT_LIBRARIES",
            prepend_env_path("DYLD_INSERT_LIBRARIES", layer_path),
        );
        if std::env::var_os("DYLD_FORCE_FLAT_NAMESPACE").is_none() {
            child.env("DYLD_FORCE_FLAT_NAMESPACE", "1");
        }
    }
}

fn prepend_env_path(var_name: &str, new_path: &Path) -> OsString {
    let mut value = OsString::from(new_path.as_os_str());
    if let Some(existing) = std::env::var_os(var_name) {
        if !existing.is_empty() {
            value.push(OsString::from(":").as_os_str());
            value.push(existing);
        }
    }
    value
}

fn resolve_layer_path(explicit: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(path) = explicit {
        if path.exists() {
            return Ok(path.to_path_buf());
        }
        bail!("detour layer library not found at {}", path.display());
    }

    let file_name = if cfg!(target_os = "macos") {
        "libdetour_layer.dylib"
    } else {
        "libdetour_layer.so"
    };

    let current_dir = std::env::current_dir().ok();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf));

    let candidates = [
        exe_dir.clone().map(|dir| dir.join(file_name)),
        exe_dir.clone().map(|dir| dir.join("..").join(file_name)),
        current_dir.clone().map(|dir| dir.join("target").join("debug").join(file_name)),
        current_dir.map(|dir| dir.join("target").join("release").join(file_name)),
    ];

    for candidate in candidates.into_iter().flatten() {
        let normalized = candidate.canonicalize().unwrap_or(candidate.clone());
        if normalized.exists() {
            return Ok(normalized);
        }
    }

    bail!(
        "could not locate {} automatically; set DETOUR_LAYER_PATH or pass --layer-path",
        file_name
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepend_env_path_adds_existing_value() {
        unsafe { std::env::set_var("DETOUR_TEST_PRELOAD", "existing") };
        let value = prepend_env_path("DETOUR_TEST_PRELOAD", Path::new("/tmp/layer"));
        assert_eq!(value.to_string_lossy(), "/tmp/layer:existing");
        unsafe { std::env::remove_var("DETOUR_TEST_PRELOAD") };
    }

    #[test]
    fn prepend_env_path_handles_empty_existing_value() {
        unsafe { std::env::remove_var("DETOUR_TEST_PRELOAD_EMPTY") };
        let value = prepend_env_path("DETOUR_TEST_PRELOAD_EMPTY", Path::new("/tmp/layer"));
        assert_eq!(value.to_string_lossy(), "/tmp/layer");
    }
}
