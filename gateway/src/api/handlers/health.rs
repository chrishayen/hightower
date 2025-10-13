use axum::{body::Body, http::{Request, StatusCode}};

pub(crate) async fn root_health(_request: Request<Body>) -> StatusCode {
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn root_health_returns_ok() {
        let request = Request::builder()
            .method("GET")
            .uri("/")
            .body(Body::empty())
            .expect("request");
        assert_eq!(root_health(request).await, StatusCode::OK);
    }
}
