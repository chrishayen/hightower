use askama::Template;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    http::header::CONTENT_TYPE,
    response::{IntoResponse, Response},
};
use tracing::error;

use crate::context::NamespacedKv;
use super::super::types::{
    ApiState, EndpointRegistrationRequest, EndpointsTableTemplate,
    ENDPOINT_REGISTRATION_PREFIX, ENDPOINT_TOKEN_PREFIX,
};
use super::sessions::has_valid_session;

pub(crate) async fn dashboard_endpoints(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    match has_valid_session(&state, &headers) {
        Ok(true) => match fetch_registered_endpoints(&state) {
            Ok(endpoints) => match render_endpoints_partial(&endpoints) {
                Ok(markup) => match Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/html; charset=utf-8")
                    .body(Body::from(markup))
                {
                    Ok(response) => response,
                    Err(err) => {
                        error!(?err, "Failed to build dashboard table response");
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "failed to render dashboard",
                        )
                            .into_response()
                    }
                },
                Err(err) => {
                    error!(?err, "Failed to render dashboard table template");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "failed to render dashboard",
                    )
                        .into_response()
                }
            },
            Err(err) => {
                error!(?err, "Failed to fetch endpoint registrations");
                (StatusCode::INTERNAL_SERVER_ERROR, "failed to load endpoints").into_response()
            }
        },
        Ok(false) => unauthorized_redirect(),
        Err(err) => {
            error!(?err, "Failed to validate session for dashboard endpoints");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to validate session",
            )
                .into_response()
        }
    }
}

fn render_endpoints_partial(endpoints: &[EndpointRegistrationRequest]) -> Result<String, askama::Error> {
    let template = EndpointsTableTemplate { endpoints };
    template.render()
}

fn unauthorized_redirect() -> Response {
    match Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(
            HeaderName::from_static("hx-redirect"),
            HeaderValue::from_static("/"),
        )
        .body(Body::empty())
    {
        Ok(response) => response,
        Err(err) => {
            error!(?err, "Failed to build unauthorized redirect response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to build response",
            )
                .into_response()
        }
    }
}

fn fetch_registered_endpoints(state: &ApiState) -> Result<Vec<EndpointRegistrationRequest>, String> {
    let kv = {
        let guard = state.kv.read().expect("gateway shared kv read lock");
        guard.clone()
    };

    let entries = kv
        .list_by_prefix(ENDPOINT_REGISTRATION_PREFIX.as_bytes())
        .map_err(|err| format!("failed to read endpoint registrations: {}", err))?;

    let mut endpoints = Vec::new();
    for (_key, value) in entries {
        if value == b"__DELETED__" {
            continue;
        }
        let mut endpoint: EndpointRegistrationRequest = serde_json::from_slice(&value)
            .map_err(|err| format!("failed to decode endpoint registration: {}", err))?;

        // Find the token for this endpoint
        if let Some(ref endpoint_id) = endpoint.endpoint_id {
            endpoint.token = find_token_for_endpoint(&kv, endpoint_id);
        }

        endpoints.push(endpoint);
    }

    endpoints.sort_by(|a, b| a.endpoint_id.cmp(&b.endpoint_id));
    Ok(endpoints)
}

fn find_token_for_endpoint(kv: &NamespacedKv, endpoint_id: &str) -> Option<String> {
    let token_entries = kv.list_by_prefix(ENDPOINT_TOKEN_PREFIX.as_bytes()).ok()?;

    for (key, value) in token_entries {
        if value == b"__DELETED__" {
            continue;
        }
        if value == endpoint_id.as_bytes() {
            // The key returned by list_by_prefix has the prefix stripped already
            let token = String::from_utf8(key).ok()?;
            return Some(token);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{CommonContext, initialize_kv};
    use crate::api::handlers::endpoints::persist_registration;
    use crate::api::handlers::sessions::create_session;
    use crate::api::types::{SessionRequest, SESSION_COOKIE};
    use axum::{
        extract::Json,
        http::header::{COOKIE, SET_COOKIE},
    };
    use std::sync::{Arc, RwLock};
    use tempfile::TempDir;

    #[tokio::test]
    async fn dashboard_lists_registered_endpoints() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let context = CommonContext::new(kv);
        context
            .auth
            .create_user("console-admin", "super-secret")
            .expect("create default user");

        let shared_kv = Arc::new(RwLock::new(context.kv.clone()));

        let state = ApiState {
            kv: Arc::clone(&shared_kv),
            auth: Arc::clone(&context.auth),
        };

        let registration = EndpointRegistrationRequest {
            endpoint_id: Some("ht-endpoint-1".into()),
            public_key_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            token: None,
            assigned_ip: None,
            public_ip: None,
            public_port: None,
            local_ip: None,
            local_port: None,
        };

        let kv = {
            let guard = shared_kv.read().expect("shared kv read lock");
            guard.clone()
        };
        persist_registration(&kv, &registration, "test-token").expect("persist registration");

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

        let response = dashboard_endpoints(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        let rendered = String::from_utf8(body_bytes.into()).expect("body utf8");
        assert!(rendered.contains("ht-endpoint-1"));
    }
}
