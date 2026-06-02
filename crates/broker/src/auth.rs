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
    // Broker-wide allow-list of interceptable services. None = no restriction.
    allowed_services: Option<Vec<String>>,
}

impl AuthService {
    pub fn new(
        mode: AuthMode,
        secret: Option<String>,
        gcp_oidc_audience: Option<String>,
        allowed_email_domain: Option<String>,
        allowed_services: Option<Vec<String>>,
    ) -> Self {
        Self {
            mode,
            secret,
            gcp_oidc_audience,
            allowed_email_domain,
            allowed_services,
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
                // Network boundary provides trust; still enforce the broker-wide
                // service allow-list so a session can only intercept permitted
                // services (US-009).
                authorize_services(target_services, self.allowed_services.as_deref())
            }
            AuthMode::SignedToken => {
                let secret = self
                    .secret
                    .as_deref()
                    .ok_or_else(|| DetourError::AuthError("JWT secret not configured".into()))?;

                let token = token.ok_or_else(|| {
                    DetourError::AuthError("signed-token mode requires JWT".into())
                })?;

                validate_jwt(
                    token,
                    secret,
                    target_services,
                    self.allowed_services.as_deref(),
                )
            }
            AuthMode::GcpOidc => {
                let audience = self.gcp_oidc_audience.as_deref().ok_or_else(|| {
                    DetourError::AuthError(
                        "gcp-oidc mode requires DETOUR_GCP_OIDC_AUDIENCE to be configured".into(),
                    )
                })?;
                let token = token.ok_or_else(|| {
                    DetourError::AuthError("gcp-oidc mode requires bearer token".into())
                })?;

                // The identity must be a valid Google identity AND permitted to
                // intercept every target service (US-009).
                validate_google_identity_token(
                    token,
                    audience,
                    self.allowed_email_domain.as_deref(),
                )
                .await?;
                authorize_services(target_services, self.allowed_services.as_deref())
            }
        }
    }
}

/// Reject the registration unless every target service is permitted by `allowed`.
/// `None` means no broker-wide restriction is configured (all services allowed).
fn authorize_services(
    target_services: &[String],
    allowed: Option<&[String]>,
) -> Result<(), DetourError> {
    let Some(allowed) = allowed else {
        return Ok(());
    };
    for service in target_services {
        if !allowed.iter().any(|a| a == service) {
            return Err(DetourError::AuthError(format!(
                "not authorized to intercept service '{service}'"
            )));
        }
    }
    Ok(())
}

fn validate_jwt(
    token: &str,
    secret: &str,
    target_services: &[String],
    broker_allowed: Option<&[String]>,
) -> Result<(), DetourError> {
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

    // The token's own allowed_services claim is authoritative when present
    // (per-identity scoping); otherwise fall back to the broker-wide allow-list
    // (US-009).
    let allowed = claims.allowed_services.as_deref().or(broker_allowed);
    authorize_services(target_services, allowed)
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
        return Err(DetourError::AuthError(
            "identity token email is not verified".into(),
        ));
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

    fn svc(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    // US-008: validate accepts the target services the session will intercept.
    // With no broker allow-list configured, any target passes in session-id mode.
    #[tokio::test]
    async fn validate_session_id_mode_accepts_target_services() {
        let auth = AuthService::new(AuthMode::SessionId, None, None, None, None);
        assert!(auth
            .validate(&sid(), &svc(&["orders", "billing"]), None)
            .await
            .is_ok());
        // No targets is also fine in this mode.
        assert!(auth.validate(&sid(), &[], None).await.is_ok());
    }

    // signed-token mode still requires a token; the target services are carried
    // through to the JWT check.
    #[tokio::test]
    async fn validate_signed_token_mode_requires_token() {
        let auth = AuthService::new(
            AuthMode::SignedToken,
            Some("secret".into()),
            None,
            None,
            None,
        );
        assert!(auth
            .validate(&sid(), &svc(&["orders"]), None)
            .await
            .is_err());
    }

    // US-009: the broker-wide allow-list scopes which services may be intercepted.
    #[test]
    fn authorize_services_enforces_allow_list() {
        let allowed = svc(&["orders", "billing"]);
        // Subset of the allow-list is permitted.
        assert!(authorize_services(&svc(&["orders"]), Some(&allowed)).is_ok());
        assert!(authorize_services(&svc(&["orders", "billing"]), Some(&allowed)).is_ok());
        // A service outside the allow-list is rejected.
        assert!(authorize_services(&svc(&["payments"]), Some(&allowed)).is_err());
        assert!(authorize_services(&svc(&["orders", "payments"]), Some(&allowed)).is_err());
        // No allow-list configured = no restriction.
        assert!(authorize_services(&svc(&["anything"]), None).is_ok());
    }

    // US-009: session-id mode rejects a target outside the configured allow-list
    // before any interception starts.
    #[tokio::test]
    async fn validate_session_id_mode_rejects_unlisted_service() {
        let auth = AuthService::new(
            AuthMode::SessionId,
            None,
            None,
            None,
            Some(svc(&["orders"])),
        );
        assert!(auth.validate(&sid(), &svc(&["orders"]), None).await.is_ok());
        let err = auth.validate(&sid(), &svc(&["payments"]), None).await;
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("payments"));
    }
}
