use detour_core::{AuthMode, DetourError, SessionId};

pub struct AuthService {
    mode: AuthMode,
    // JWT secret — only used in signed-token mode
    secret: Option<String>,
}

impl AuthService {
    pub fn new(mode: AuthMode, secret: Option<String>) -> Self {
        Self { mode, secret }
    }

    /// Validate the credential presented by the agent on RegisterSession.
    /// In session-id mode the session_id itself IS the credential (presence in
    /// registry is the only check). In signed-token mode a JWT is expected.
    pub fn validate(
        &self,
        _session_id: &SessionId,
        token: Option<&str>,
    ) -> Result<(), DetourError> {
        match self.mode {
            AuthMode::SessionId => {
                // Network boundary provides trust; accept any UUID v4 session
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

                validate_jwt(token, secret)
            }
        }
    }
}

fn validate_jwt(token: &str, secret: &str) -> Result<(), DetourError> {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct Claims {
        exp: u64,
        allowed_services: Option<Vec<String>>,
    }

    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    decode::<Claims>(token, &key, &validation)
        .map_err(|e| DetourError::AuthError(e.to_string()))?;

    Ok(())
}
