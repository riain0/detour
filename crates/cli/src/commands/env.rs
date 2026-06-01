use std::process::Command;

use anyhow::{anyhow, bail, Context};
use clap::{Args, Subcommand};
use serde_json::Value;

#[derive(Args)]
pub struct EnvArgs {
    #[command(subcommand)]
    pub command: EnvCommand,
}

#[derive(Subcommand)]
pub enum EnvCommand {
    /// Print environment values from a Cloud Run service
    CloudRun(CloudRunEnvArgs),
}

#[derive(Args)]
#[derive(Clone)]
pub struct CloudRunEnvArgs {
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

    /// Output format: shell or json
    #[arg(long, default_value = "shell")]
    pub output: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvVar {
    pub name: String,
    pub value: Option<String>,
    pub source: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloudRunProfile {
    pub service: String,
    pub region: String,
    pub project: Option<String>,
    pub container_name: String,
    pub env_vars: Vec<EnvVar>,
}

pub async fn run(args: EnvArgs) -> anyhow::Result<()> {
    match args.command {
        EnvCommand::CloudRun(args) => run_cloud_run(args),
    }
}

fn run_cloud_run(args: CloudRunEnvArgs) -> anyhow::Result<()> {
    let profile = load_cloud_run_profile(&args)?;

    let resolved: Vec<_> = profile.env_vars.iter().filter(|v| v.value.is_some()).collect();
    let unresolved: Vec<_> = profile.env_vars.iter().filter(|v| v.value.is_none()).collect();

    match args.output.as_str() {
        "shell" => {
            for var in &resolved {
                println!(
                    "export {}={}",
                    var.name,
                    shell_escape(var.value.as_deref().unwrap_or_default())
                );
            }
        }
        "json" => {
            let body = serde_json::json!({
                "service": args.service,
                "region": args.region,
                "project": args.project,
                "container": profile.container_name,
                "env": resolved
                    .iter()
                    .map(|var| {
                        (
                            var.name.clone(),
                            Value::String(var.value.clone().unwrap_or_default()),
                        )
                    })
                    .collect::<serde_json::Map<String, Value>>(),
                "unresolved": unresolved
                    .iter()
                    .map(|var| serde_json::json!({
                        "name": var.name,
                        "source": var.source,
                    }))
                    .collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&body)?);
        }
        other => bail!("unsupported output format {:?}: expected shell or json", other),
    }

    if !unresolved.is_empty() {
        eprintln!();
        eprintln!(
            "Skipped {} unresolved env var(s) from container {}.",
            unresolved.len(),
            profile.container_name
        );
        eprintln!(
            "These are usually secret-backed values that Cloud Run does not return via describe."
        );
        for var in unresolved {
            eprintln!(
                "  {} ({})",
                var.name,
                var.source.as_deref().unwrap_or("unknown source")
            );
        }
    }

    Ok(())
}

pub fn load_cloud_run_profile(args: &CloudRunEnvArgs) -> anyhow::Result<CloudRunProfile> {
    let service = describe_cloud_run_service(args)?;
    let (container_name, env_vars) = extract_container_env(&service, args.container.as_deref())?;
    Ok(CloudRunProfile {
        service: args.service.clone(),
        region: args.region.clone(),
        project: args.project.clone(),
        container_name,
        env_vars,
    })
}

fn describe_cloud_run_service(args: &CloudRunEnvArgs) -> anyhow::Result<Value> {
    let mut command = Command::new("gcloud");
    command.args([
        "run",
        "services",
        "describe",
        args.service.as_str(),
        "--region",
        args.region.as_str(),
        "--format=json",
    ]);

    if let Some(project) = &args.project {
        command.arg("--project").arg(project);
    }

    let output = command
        .output()
        .with_context(|| "failed to run gcloud; install gcloud CLI and authenticate first")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("gcloud run services describe failed: {}", stderr.trim());
    }

    serde_json::from_slice(&output.stdout).context("failed to parse gcloud JSON output")
}

fn extract_container_env(service: &Value, requested_container: Option<&str>) -> anyhow::Result<(String, Vec<EnvVar>)> {
    let containers = service
        .pointer("/template/containers")
        .or_else(|| service.pointer("/spec/template/spec/containers"))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("could not find containers in Cloud Run service description"))?;

    let container = if let Some(name) = requested_container {
        containers
            .iter()
            .find(|container| container.get("name").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| anyhow!("container {:?} not found in Cloud Run service", name))?
    } else {
        containers
            .iter()
            .find(|container| container.get("name").and_then(Value::as_str) != Some("detour-sidecar"))
            .or_else(|| containers.first())
            .ok_or_else(|| anyhow!("Cloud Run service has no containers"))?
    };

    let container_name = container
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>")
        .to_string();

    let env_vars = container
        .get("env")
        .and_then(Value::as_array)
        .map(|vars| vars.iter().filter_map(parse_env_var).collect())
        .unwrap_or_default();

    Ok((container_name, env_vars))
}

fn parse_env_var(value: &Value) -> Option<EnvVar> {
    let name = value.get("name")?.as_str()?.to_string();
    let literal = value.get("value").and_then(Value::as_str).map(str::to_string);
    let source = value
        .pointer("/valueSource/secretKeyRef/secret")
        .and_then(Value::as_str)
        .map(|secret| {
            let version = value
                .pointer("/valueSource/secretKeyRef/version")
                .and_then(Value::as_str)
                .unwrap_or("latest");
            format!("secret:{}:{}", secret, version)
        })
        .or_else(|| {
            value
                .pointer("/valueFrom/secretKeyRef/name")
                .and_then(Value::as_str)
                .map(|secret| format!("secret:{}", secret))
        });

    Some(EnvVar {
        name,
        value: literal,
        source,
    })
}

fn shell_escape(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chooses_app_container_over_detour_sidecar() {
        let service = serde_json::json!({
            "template": {
                "containers": [
                    {"name": "detour-sidecar", "env": []},
                    {"name": "app", "env": [{"name": "PORT", "value": "8080"}]}
                ]
            }
        });

        let (name, vars) = extract_container_env(&service, None).unwrap();
        assert_eq!(name, "app");
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].name, "PORT");
        assert_eq!(vars[0].value.as_deref(), Some("8080"));
    }

    #[test]
    fn parses_secret_backed_env_as_unresolved() {
        let var = parse_env_var(&serde_json::json!({
            "name": "DB_PASSWORD",
            "valueSource": {
                "secretKeyRef": {
                    "secret": "db-password",
                    "version": "5"
                }
            }
        }))
        .unwrap();

        assert_eq!(var.name, "DB_PASSWORD");
        assert!(var.value.is_none());
        assert_eq!(var.source.as_deref(), Some("secret:db-password:5"));
    }

    #[test]
    fn shell_escape_wraps_single_quotes() {
        assert_eq!(shell_escape("abc"), "'abc'");
        assert_eq!(shell_escape("a'b"), "'a'\"'\"'b'");
    }
}
