use axum::{
    extract::Path as AxumPath,
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub(crate) async fn acme_challenge(AxumPath(token): AxumPath<String>) -> Response {
    tracing::info!(token = %token, "Received ACME challenge request");
    if let Some(acme_client) = crate::api::ACME_CLIENT.get() {
        if let Some(key_auth) = acme_client.get_challenge(&token) {
            tracing::info!(token = %token, key_auth = %key_auth, "Serving ACME challenge response");
            return (StatusCode::OK, key_auth).into_response();
        }
    }
    tracing::warn!(token = %token, "ACME challenge not found");
    StatusCode::NOT_FOUND.into_response()
}
