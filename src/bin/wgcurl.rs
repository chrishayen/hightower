use anyhow::{Context, Result};
use clap::Parser;
use hightower_client::HightowerConnection;

#[derive(Parser, Debug)]
#[command(name = "wgcurl")]
#[command(about = "Fetch content from WireGuard peer endpoints via hightower", long_about = None)]
struct Args {
    /// The URL to fetch (e.g., http://<peer-ip>/endpoint)
    url: String,

    /// Gateway URL (defaults to http://127.0.0.1:8008)
    #[arg(short, long)]
    gateway: Option<String>,

    /// Authentication token for gateway
    #[arg(short, long, env = "HIGHTOWER_AUTH_TOKEN")]
    auth_token: Option<String>,

    /// Show verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Parse the URL
    let url = url::Url::parse(&args.url).context("Invalid URL")?;

    // Extract peer IP and path
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

    if args.verbose {
        eprintln!("Connecting to Hightower gateway...");
    }

    // Connect to hightower gateway
    let connection = if let Some(auth_token) = args.auth_token {
        let gateway_url = args
            .gateway
            .as_deref()
            .unwrap_or("http://127.0.0.1:8008");
        HightowerConnection::connect(gateway_url, auth_token)
            .await
            .context("Failed to connect to Hightower gateway")?
    } else {
        anyhow::bail!("Authentication token required (use --auth-token or HIGHTOWER_AUTH_TOKEN env var)");
    };

    if args.verbose {
        eprintln!("Connected to gateway as {}", connection.node_id());
        eprintln!("Assigned IP: {}", connection.assigned_ip());
        eprintln!("Fetching from peer {} on port {}...", peer_ip, port);
    }

    // Dial the peer
    let conn = connection
        .dial(peer_ip, port)
        .await
        .context(format!("Failed to dial peer {}", peer_ip))?;

    if args.verbose {
        eprintln!("Connected to peer, sending HTTP request...");
    }

    // Build and send HTTP request
    let request = format!(
        "GET {}{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, query, peer_ip
    );

    conn.send(request.as_bytes())
        .await
        .context("Failed to send HTTP request")?;

    if args.verbose {
        eprintln!("Request sent, waiting for response...");
    }

    // Receive and print response
    let mut response_data = Vec::new();
    let mut buf = vec![0u8; 8192];

    loop {
        let n = conn.recv(&mut buf).await.context("Failed to receive response")?;
        if n == 0 {
            break; // Connection closed
        }
        response_data.extend_from_slice(&buf[..n]);
    }

    // Parse HTTP response to extract body
    let response_str = String::from_utf8_lossy(&response_data);

    if args.verbose {
        eprintln!("Received {} bytes", response_data.len());
    }

    // Find the end of headers (blank line)
    if let Some(body_start) = response_str.find("\r\n\r\n") {
        let headers = &response_str[..body_start];
        let body = &response_str[body_start + 4..];

        if args.verbose {
            eprintln!("\nResponse headers:");
            eprintln!("{}\n", headers);
        }

        // Print the body
        println!("{}", body);
    } else {
        // No clear header/body separation, print everything
        println!("{}", response_str);
    }

    Ok(())
}
