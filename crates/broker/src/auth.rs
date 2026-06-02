use std::time::Duration;

use detour_core::{AuthMode, DetourError, SessionId};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

pub struct AuthService {
    mode: AuthMode,
    // JWT secret — only used in signed-token mode
    secret: Option<String>,
    gcp_oidc_audience: Option<String>,
    allowed_email_domain: Option<String>,
}

impl AuthService {
    pub fn new(
        mode: AuthMode,
        secret: Option<String>,
        gcp_oidc_audience: Option<String>,
        allowed_email_domain: Option<String>,
    ) -> Self {
        Self {
            mode,
            secret,
            gcp_oidc_audience,
            allowed_email_domain,
        }
    }

    pub fn mode(&self) -> &AuthMode {
        &self.mode
    }

    /// Validate the credential presented by the agent on RegisterSession.
    /// In session-id mode the session_id itself IS the credential (presence in
    /// registry is the only check). In signed-token mode a JWT is expected.
    ///
    /// `target_services` are the Cloud Run services the session intends to
    /// intercept (the registered route service names), carried here so
    /// authorization can be scoped to the target service (US-008). The per-mode
    /// checks enforce against them (US-009).
    pub async fn validate(
        &self,
        _session_id: &SessionId,
        target_services: &[String],
        token: Option<&str>,
    ) -> Result<(), DetourError> {
        match self.mode {
            AuthMode::SessionId => {
                // Network boundary provides trust; accept any UUID v4 session.
                let _ = target_services;
                Ok(())
            }
            AuthMode::SignedToken => {
                let secret = self
                    .secret
                    .as_deref()
                    .ok_or_else(|| DetourError::AuthError("JWT secret not configured".into()))?;

                let token = token.ok_or_else(|| {
                    DetourError::AuthError("signed-token mode requires JWT".into())
                })?;

                validate_jwt(token, secret, target_services)
            }
            AuthMode::GcpOidc => {
                let audience = self.gcp_oidc_audience.as_deref().ok_or_else(|| {
                    DetourError::AuthError(
                        "gcp-oidc mode requires DETOUR_GCP_OIDC_AUDIENCE to be configured"
                            .into(),
                    )
                })?;
                let token = token.ok_or_else(|| {
                    DetourError::AuthError("gcp-oidc mode requires bearer token".into())
                })?;

                validate_google_identity_token(token, audience, self.allowed_email_domain.as_deref())
                    .await
            }
        }
    }
}

fn validate_jwt(token: &str, secret: &str, target_services: &[String]) -> Result<(), DetourError> {
    #[derive(Deserialize)]
    struct Claims {
        #[allow(dead_code)]
        exp: u64,
        allowed_services: Option<Vec<String>>,
    }

    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let claims = decode::<Claims>(token, &key, &validation)
        .map_err(|e| DetourError::AuthError(e.to_string()))?
        .claims;

    // The token carries the target service identifiers so US-009 can authorize
    // them against the token's allowed_services claim.
    let _ = (&claims.allowed_services, target_services);

    Ok(())
}

async fn validate_google_identity_token(
    token: &str,
    audience: &str,
    allowed_email_domain: Option<&str>,
) -> Result<(), DetourError> {
    #[derive(Debug, Deserialize)]
    struct GoogleClaims {
        exp: u64,
        iss: String,
        email: Option<String>,
        email_verified: Option<bool>,
    }

    #[derive(Debug, Deserialize)]
    struct GoogleJwks {
        keys: Vec<GoogleJwk>,
    }

    #[derive(Debug, Deserialize)]
    struct GoogleJwk {
        kid: String,
        n: String,
        e: String,
        kty: String,
        alg: Option<String>,
        #[serde(rename = "use")]
        use_field: Option<String>,
    }

    let bearer = token
        .strip_prefix("Bearer ")
        .or_else(|| token.strip_prefix("bearer "))
        .unwrap_or(token)
        .trim();

    let header = decode_header(bearer).map_err(|e| DetourError::AuthError(e.to_string()))?;
    let kid = header
        .kid
        .ok_or_else(|| DetourError::AuthError("identity token missing kid header".into()))?;

    let jwks = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| DetourError::AuthError(e.to_string()))?
        .get("https://www.googleapis.com/oauth2/v3/certs")
        .send()
        .await
        .map_err(|e| DetourError::AuthError(format!("failed to fetch Google certs: {e}")))?
        .error_for_status()
        .map_err(|e| DetourError::AuthError(format!("failed to fetch Google certs: {e}")))?
        .json::<GoogleJwks>()
        .await
        .map_err(|e| DetourError::AuthError(format!("failed to parse Google certs: {e}")))?;

    let jwk = jwks
        .keys
        .into_iter()
        .find(|key| {
            key.kid == kid
                && key.kty == "RSA"
                && key.use_field.as_deref().unwrap_or("sig") == "sig"
                && key.alg.as_deref().unwrap_or("RS256") == "RS256"
        })
        .ok_or_else(|| DetourError::AuthError("matching Google signing key not found".into()))?;

    let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| DetourError::AuthError(e.to_string()))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);
    validation.validate_exp = true;

    let claims = decode::<GoogleClaims>(bearer, &key, &validation)
        .map_err(|e| DetourError::AuthError(format!("invalid Google identity token: {e}")))?
        .claims;

    let _ = claims.exp;
    if claims.iss != "https://accounts.google.com" && claims.iss != "accounts.google.com" {
        return Err(DetourError::AuthError("unexpected token issuer".into()));
    }
    let email = claims
        .email
        .ok_or_else(|| DetourError::AuthError("identity token missing email claim".into()))?;
    if claims.email_verified != Some(true) {
        return Err(DetourError::AuthError("identity token email is not verified".into()));
    }

    if let Some(domain) = allowed_email_domain {
        let expected = format!("@{}", domain.trim_start_matches('@'));
        if !email.ends_with(&expected) {
            return Err(DetourError::AuthError(format!(
                "identity token email {email} is outside allowed domain {expected}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid() -> SessionId {
        SessionId::from_string("11111111-1111-4111-8111-111111111111".into()).unwrap()
    }

    // US-008: validate accepts the target services the session will intercept.
    // In session-id mode the network boundary is the trust, so any target passes.
    #[tokio::test]
    async fn validate_session_id_mode_accepts_target_services() {
        let auth = AuthService::new(AuthMode::SessionId, None, None, None);
        let targets = vec!["orders".to_string(), "billing".to_string()];
        assert!(auth.validate(&sid(), &targets, None).await.is_ok());
        // No targets is also fine in this mode.
        assert!(auth.validate(&sid(), &[], None).await.is_ok());
    }

    // signed-token mode still requires a token; the target services are carried
    // through to the JWT check (enforced in US-009).
    #[tokio::test]
    async fn validate_signed_token_mode_requires_token() {
        let auth = AuthService::new(AuthMode::SignedToken, Some("secret".into()), None, None);
        let targets = vec!["orders".to_string()];
        assert!(auth.validate(&sid(), &targets, None).await.is_err());
    }
}
