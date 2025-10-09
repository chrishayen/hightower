use std::process::Command;

#[test]
fn test_wgcurl_requires_url() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "wgcurl"])
        .output()
        .expect("Failed to execute wgcurl");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("required") || stderr.contains("URL"));
}

#[test]
fn test_wgcurl_requires_auth_token() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "wgcurl", "--", "http://100.64.0.5/test"])
        .output()
        .expect("Failed to execute wgcurl");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Authentication token required") || stderr.contains("auth"));
}

#[test]
fn test_wgcurl_help() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "wgcurl", "--", "--help"])
        .output()
        .expect("Failed to execute wgcurl");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("wgcurl"));
    assert!(stdout.contains("Fetch content from WireGuard peer endpoints"));
}
