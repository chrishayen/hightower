use axum::response::Html;

const PLACEHOLDER_HTML: &str = r#"
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Hightower UI</title>
    <style>
        body { font-family: system-ui, sans-serif; margin: 2rem; }
        main { max-width: 40rem; }
    </style>
</head>
<body>
    <main>
        <h1>Hightower Control Panel</h1>
        <p>This placeholder page will host the upcoming web interface.</p>
    </main>
</body>
</html>
"#;

pub(crate) async fn index() -> Html<&'static str> {
    Html(PLACEHOLDER_HTML)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn index_returns_placeholder_html() {
        let response = index().await;
        assert!(response.0.contains("Hightower Control Panel"));
    }
}
