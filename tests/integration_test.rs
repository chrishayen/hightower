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

#[test]
fn test_ht_help() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "ht", "--", "--help"])
        .output()
        .expect("Failed to execute ht");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Hightower CLI tool"));
    assert!(stdout.contains("stun"));
    assert!(stdout.contains("gateway"));
    assert!(stdout.contains("node"));
}

#[test]
fn test_ht_stun_help() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "ht", "--", "stun", "--help"])
        .output()
        .expect("Failed to execute ht stun");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Run STUN server"));
    assert!(stdout.contains("--bind"));
}

#[test]
fn test_ht_stun_invalid_address() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "ht", "--", "stun", "--bind", "invalid:address"])
        .output()
        .expect("Failed to execute ht stun");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error") || stderr.contains("error") || stderr.contains("invalid"));
}
