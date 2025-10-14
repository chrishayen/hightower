use anyhow::{Context, Result};
use client::HightowerConnection;

pub async fn run(
    url: &str,
    gateway: Option<&str>,
    auth_token: Option<&str>,
    verbose: bool,
) -> Result<()> {
    let url = url::Url::parse(url).context("Invalid URL")?;

    let peer = url
        .host_str()
        .context("URL must contain a host (endpoint ID or assigned IP)")?;
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
        eprintln!("Connected to gateway as {}", connection.endpoint_id());
        eprintln!("Assigned IP: {}", connection.assigned_ip());
        eprintln!("\nLooking up peer info for '{}'...", peer);
    }

    // Get peer info to show details
    let peer_info = connection
        .get_peer_info(peer)
        .await
        .context(format!("Failed to lookup peer '{}'", peer))?;

    if verbose {
        eprintln!("Found peer:");
        eprintln!("  Endpoint ID: {}", peer_info.endpoint_id.as_deref().unwrap_or("unknown"));
        eprintln!("  Assigned IP: {}", peer_info.assigned_ip.as_deref().unwrap_or("unknown"));
        eprintln!("  Public Key: {}...", &peer_info.public_key_hex[..16]);
        if let Some(endpoint) = peer_info.endpoint() {
            eprintln!("  Public Endpoint: {}", endpoint);
        }
        eprintln!("\nEstablishing WireGuard connection...");
    }

    let mut conn = connection
        .dial(peer, port)
        .await
        .context(format!("Failed to dial peer '{}'", peer))?;

    if verbose {
        eprintln!("Connected to peer, sending HTTP request...");
    }

    let request = format!(
        "GET {}{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, query, peer
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
