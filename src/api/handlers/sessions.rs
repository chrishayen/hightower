use askama::Template;
use axum::{
    body::Body,
    extract::{Json, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    http::header::{CONTENT_TYPE, COOKIE, SET_COOKIE},
    response::Response,
};
use rand::RngCore;

use super::super::types::{
    ApiState, LoginAlertTemplate, SessionApiError, SessionRequest,
    SESSION_COOKIE, SESSION_NAMESPACE,
};

pub(crate) async fn create_session(
    State(state): State<ApiState>,
    Json(body): Json<SessionRequest>,
) -> Result<Response, SessionApiError> {
    let SessionRequest { username, password } = body;
    let username = username.trim().to_owned();

    tracing::debug!(username = %username, "Session creation attempt");

    if username.is_empty() || password.is_empty() {
        tracing::warn!("Empty username or password");
        return build_login_alert("error", "Username and password are required.");
    }

    let authenticated = state
        .auth
        .verify_password(&username, &password)
        .map_err(|err| {
            tracing::error!(?err, username = %username, "Failed to verify password");
            SessionApiError::Internal(format!("failed to verify credentials: {}", err))
        })?;

    if !authenticated {
        tracing::warn!(username = %username, "Invalid credentials");
        return build_login_alert("error", "Invalid username or password.");
    }

    let token = generate_session_token();
    persist_session(&state, &token, &username)?;
    let cookie = build_session_cookie(&token);
    let cookie_value = HeaderValue::from_str(&cookie)
        .map_err(|err| {
            tracing::error!(?err, "Failed to create cookie header");
            SessionApiError::Internal(format!("invalid cookie header: {}", err))
        })?;

    tracing::info!(username = %username, "Session created successfully");

    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(SET_COOKIE, cookie_value)
        .header(
            HeaderName::from_static("hx-redirect"),
            HeaderValue::from_static("/dashboard"),
        )
        .body(Body::empty())
        .map_err(|err| {
            tracing::error!(?err, "Failed to build response");
            SessionApiError::Internal(format!("failed to build response: {}", err))
        })
}

pub(crate) async fn delete_session(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Response, SessionApiError> {
    if let Some(token) = extract_session_token(&headers) {
        let kv = {
            let guard = state.kv.read().expect("gateway shared kv read lock");
            guard.clone()
        };

        let sessions = kv.clone_with_additional_prefix(SESSION_NAMESPACE);
        if let Err(err) = sessions.put_bytes(token.as_bytes(), b"__DELETED__") {
            tracing::error!(?err, "Failed to delete session");
        } else {
            tracing::info!("Session deleted successfully");
        }
    }

    let clear_cookie = format!("{}=; HttpOnly; Path=/; Max-Age=0", SESSION_COOKIE);
    let cookie_value = HeaderValue::from_str(&clear_cookie)
        .map_err(|err| {
            tracing::error!(?err, "Failed to create clear cookie header");
            SessionApiError::Internal(format!("invalid cookie header: {}", err))
        })?;

    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(SET_COOKIE, cookie_value)
        .header(axum::http::header::LOCATION, "/")
        .body(Body::empty())
        .map_err(|err| {
            tracing::error!(?err, "Failed to build logout response");
            SessionApiError::Internal(format!("failed to build response: {}", err))
        })
}

fn build_login_alert(kind: &str, message: &str) -> Result<Response, SessionApiError> {
    let template = LoginAlertTemplate { kind, message };
    let markup = template.render().map_err(|err| {
        SessionApiError::Internal(format!("failed to render login alert: {}", err))
    })?;

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(markup))
        .map_err(|err| {
            SessionApiError::Internal(format!("failed to build alert response: {}", err))
        })
}

fn persist_session(state: &ApiState, token: &str, username: &str) -> Result<(), SessionApiError> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    let sessions = kv.clone_with_additional_prefix(SESSION_NAMESPACE);
    sessions
        .put_bytes(token.as_bytes(), username.as_bytes())
        .map_err(|err| SessionApiError::Internal(format!("failed to persist session: {}", err)))
}

fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn build_session_cookie(token: &str) -> String {
    format!(
        "{}={}; HttpOnly; Path=/; SameSite=Strict; Max-Age=86400",
        SESSION_COOKIE, token
    )
}

pub(crate) fn has_valid_session(state: &ApiState, headers: &HeaderMap) -> Result<bool, hightower_kv::Error> {
    match extract_session_token(headers) {
        Some(token) => session_exists(state, &token),
        None => Ok(false),
    }
}

fn session_exists(state: &ApiState, token: &str) -> Result<bool, hightower_kv::Error> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    let sessions = kv.clone_with_additional_prefix(SESSION_NAMESPACE);
    sessions
        .get_bytes(token.as_bytes())
        .map(|value| {
            match value {
                Some(bytes) => bytes != b"__DELETED__",
                None => false,
            }
        })
}

fn extract_session_token(headers: &HeaderMap) -> Option<String> {
    let header = headers.get(COOKIE)?;
    let value = header.to_str().ok()?;
    let needle = format!("{}=", SESSION_COOKIE);

    value.split(';').find_map(|part| {
        let trimmed = part.trim();
        trimmed.strip_prefix(&needle).map(|token| token.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{CommonContext, initialize_kv};
    use std::sync::{Arc, RwLock};
    use tempfile::TempDir;

    #[tokio::test]
    async fn create_session_returns_no_content_for_valid_credentials() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        context
            .auth
            .create_user("console-admin", "super-secret")
            .expect("create default user");

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
            auth: Arc::clone(&context.auth),
        };

        let body = SessionRequest {
            username: "console-admin".into(),
            password: "super-secret".into(),
        };

        let response = create_session(State(state.clone()), Json(body))
            .await
            .expect("session creation succeeds");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let cookie_header = response
            .headers()
            .get(SET_COOKIE)
            .expect("set-cookie present")
            .to_str()
            .expect("cookie header str");
        assert!(cookie_header.contains(SESSION_COOKIE));

        let redirect_header = response
            .headers()
            .get(HeaderName::from_static("hx-redirect"))
            .expect("hx-redirect present")
            .to_str()
            .expect("hx redirect str");
        assert_eq!(redirect_header, "/dashboard");

        let token = cookie_header
            .split(';')
            .next()
            .and_then(|segment| segment.strip_prefix(&format!("{}=", SESSION_COOKIE)))
            .expect("session token present")
            .to_string();

        let sessions = context.kv.clone_with_additional_prefix(SESSION_NAMESPACE);
        let stored = sessions
            .get_bytes(token.as_bytes())
            .expect("read session store")
            .expect("session stored");
        assert_eq!(stored, b"console-admin");
    }

    #[tokio::test]
    async fn create_session_rejects_invalid_credentials() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        context
            .auth
            .create_user("console-admin", "super-secret")
            .expect("create default user");

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
            auth: Arc::clone(&context.auth),
        };

        let body = SessionRequest {
            username: "console-admin".into(),
            password: "not-it".into(),
        };

        let response = create_session(State(state), Json(body))
            .await
            .expect("session response");

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let rendered = String::from_utf8(body_bytes.into()).expect("body utf8");
        assert!(rendered.contains("Invalid username or password."));
        assert!(rendered.contains("login-alert"));
    }
}
