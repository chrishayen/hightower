use askama::Template;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use tracing::error;

use super::super::types::{ApiState, DashboardTemplate, EndpointsTemplate, LoginTemplate, SettingsTemplate};
use super::sessions::has_valid_session;

pub(crate) async fn console_root() -> Response {
    match LoginTemplate.render() {
        Ok(html) => (StatusCode::OK, Html(html)).into_response(),
        Err(err) => {
            error!(?err, "Failed to render login template");
            (StatusCode::INTERNAL_SERVER_ERROR, "failed to render page").into_response()
        }
    }
}

pub(crate) async fn console_dashboard(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    match has_valid_session(&state, &headers) {
        Ok(true) => match DashboardTemplate.render() {
            Ok(html) => (StatusCode::OK, Html(html)).into_response(),
            Err(err) => {
                error!(?err, "Failed to render dashboard template");
                (StatusCode::INTERNAL_SERVER_ERROR, "failed to render page").into_response()
            }
        },
        Ok(false) => Redirect::to("/").into_response(),
        Err(err) => {
            error!(?err, "Failed to validate session for dashboard");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to validate session",
            )
                .into_response()
        }
    }
}

pub(crate) async fn console_endpoints(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    match has_valid_session(&state, &headers) {
        Ok(true) => match EndpointsTemplate.render() {
            Ok(html) => (StatusCode::OK, Html(html)).into_response(),
            Err(err) => {
                error!(?err, "Failed to render endpoints template");
                (StatusCode::INTERNAL_SERVER_ERROR, "failed to render page").into_response()
            }
        },
        Ok(false) => Redirect::to("/").into_response(),
        Err(err) => {
            error!(?err, "Failed to validate session for endpoints");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to validate session",
            )
                .into_response()
        }
    }
}

pub(crate) async fn console_settings(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    match has_valid_session(&state, &headers) {
        Ok(true) => match SettingsTemplate.render() {
            Ok(html) => (StatusCode::OK, Html(html)).into_response(),
            Err(err) => {
                error!(?err, "Failed to render settings template");
                (StatusCode::INTERNAL_SERVER_ERROR, "failed to render page").into_response()
            }
        },
        Ok(false) => Redirect::to("/").into_response(),
        Err(err) => {
            error!(?err, "Failed to validate session for settings");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to validate session",
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{CommonContext, initialize_kv};
    use crate::api::handlers::sessions::create_session;
    use crate::api::types::{SessionRequest, SESSION_COOKIE};
    use axum::{
        extract::Json,
        http::header::{COOKIE, SET_COOKIE},
    };
    use axum::http::HeaderValue;
    use std::sync::{Arc, RwLock};
    use tempfile::TempDir;

    #[tokio::test]
    async fn dashboard_redirects_without_session() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);

        let state = ApiState {
            kv: Arc::new(RwLock::new(context.kv.clone())),
            auth: Arc::clone(&context.auth),
        };

        let response = console_dashboard(State(state), HeaderMap::new()).await;

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .expect("location header")
            .to_str()
            .expect("location str");
        assert_eq!(location, "/");
    }

    #[tokio::test]
    async fn dashboard_renders_when_session_valid() {
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

        let response = create_session(
            State(state.clone()),
            Json(SessionRequest {
                username: "console-admin".into(),
                password: "super-secret".into(),
            }),
        )
        .await
        .expect("session creation succeeds");

        let cookie_header = response
            .headers()
            .get(SET_COOKIE)
            .expect("set-cookie present")
            .to_str()
            .expect("cookie str");
        let token = cookie_header
            .split(';')
            .next()
            .and_then(|segment| segment.strip_prefix(&format!("{}=", SESSION_COOKIE)))
            .expect("session token present")
            .to_string();

        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("{}={}", SESSION_COOKIE, token))
                .expect("cookie header value"),
        );

        let response = console_dashboard(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let rendered = String::from_utf8(body_bytes.into()).expect("body utf8");
        assert!(rendered.contains("Dashboard"));
        assert!(rendered.contains("hx-get=\"/api/dashboard/endpoints\""));
    }
}
