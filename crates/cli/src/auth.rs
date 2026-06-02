use std::process::Command;

use anyhow::{bail, Context};

use detour_core::AuthMode;

pub fn resolve_auth_token(
    auth_mode: &AuthMode,
    broker_url: &str,
) -> anyhow::Result<Option<String>> {
    match auth_mode {
        AuthMode::SessionId => Ok(None),
        AuthMode::SignedToken => std::env::var("DETOUR_AUTH_TOKEN")
            .map(Some)
            .with_context(|| "signed-token mode requires DETOUR_AUTH_TOKEN to be set"),
        AuthMode::GcpOidc => Ok(Some(get_gcp_identity_token(&identity_audience(
            broker_url,
        ))?)),
    }
}

pub fn get_gcp_identity_token(audience: &str) -> anyhow::Result<String> {
    let output = Command::new("gcloud")
        .args(["auth", "print-identity-token", "--audiences", audience])
        .output()
        .context("failed to execute gcloud auth print-identity-token")?;

    if !output.status.success() {
        bail!(
            "gcloud auth print-identity-token failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if token.is_empty() {
        bail!("gcloud returned an empty identity token")
    }

    Ok(token)
}

fn identity_audience(broker_url: &str) -> String {
    std::env::var("DETOUR_GCP_OIDC_AUDIENCE").unwrap_or_else(|_| broker_url.to_string())
}
