use anyhow::{Context, Result};
use hightower_client::HightowerConnection;

pub async fn run(
    url: &str,
    gateway: Option<&str>,
    auth_token: Option<&str>,
    verbose: bool,
) -> Result<()> {
    let url = url::Url::parse(url).context("Invalid URL")?;

    let peer_ip = url
        .host_str()
        .context("URL must contain a host (peer IP)")?;
    let port = url.port().unwrap_or(80);
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let query = url.query().map(|q| format!("?{}", q)).unwrap_or_default();

    if verbose {
        eprintln!("Connecting to Hightower gateway...");
    }

    let connection = if let Some(auth_token) = auth_token {
        let gateway_url = gateway.unwrap_or("http://127.0.0.1:8008");
        HightowerConnection::connect(gateway_url, auth_token)
            .await
            .context("Failed to connect to Hightower gateway")?
    } else {
        anyhow::bail!("Authentication token required (use --auth-token or HIGHTOWER_AUTH_TOKEN env var)");
    };

    if verbose {
        eprintln!("Connected to gateway as {}", connection.node_id());
        eprintln!("Assigned IP: {}", connection.assigned_ip());
        eprintln!("Fetching from peer {} on port {}...", peer_ip, port);
    }

    let mut conn = connection
        .dial(peer_ip, port)
        .await
        .context(format!("Failed to dial peer {}", peer_ip))?;

    if verbose {
        eprintln!("Connected to peer, sending HTTP request...");
    }

    let request = format!(
        "GET {}{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, query, peer_ip
    );

    conn.send(request.as_bytes())
        .await
        .context("Failed to send HTTP request")?;

    if verbose {
        eprintln!("Request sent, waiting for response...");
    }

    let mut response_data = Vec::new();

    loop {
        let data = conn.recv().await.context("Failed to receive response")?;
        if data.is_empty() {
            break;
        }
        response_data.extend_from_slice(&data);
    }

    let response_str = String::from_utf8_lossy(&response_data);

    if verbose {
        eprintln!("Received {} bytes", response_data.len());
    }

    if let Some(body_start) = response_str.find("\r\n\r\n") {
        let headers = &response_str[..body_start];
        let body = &response_str[body_start + 4..];

        if verbose {
            eprintln!("\nResponse headers:");
            eprintln!("{}\n", headers);
        }

        println!("{}", body);
    } else {
        println!("{}", response_str);
    }

    Ok(())
}
