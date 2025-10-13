use std::process::Command;

#[test]
fn test_ht_curl_requires_url() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "ht", "--", "curl"])
        .output()
        .expect("Failed to execute ht curl");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("required") || stderr.contains("URL") || stderr.contains("url"));
}

#[test]
fn test_ht_curl_requires_auth_token() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "ht", "--", "curl", "http://100.64.0.5/test"])
        .output()
        .expect("Failed to execute ht curl");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Authentication token required") || stderr.contains("auth"));
}

#[test]
fn test_ht_curl_help() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "ht", "--", "curl", "--help"])
        .output()
        .expect("Failed to execute ht curl");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
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
    assert!(stdout.contains("curl"));
    assert!(stdout.contains("run"));
}

#[test]
fn test_ht_stun_help() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "ht", "--", "stun", "--help"])
        .output()
        .expect("Failed to execute ht stun");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Query a STUN server"));
    assert!(stdout.contains("address"));
}

#[test]
fn test_ht_stun_requires_address() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "ht", "--", "stun"])
        .output()
        .expect("Failed to execute ht stun");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("required") || stderr.contains("address"));
}

#[test]
fn test_ht_run_help() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "ht", "--", "run", "--help"])
        .output()
        .expect("Failed to execute ht run");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Run services"));
    assert!(stdout.contains("stun"));
    assert!(stdout.contains("gateway"));
    assert!(stdout.contains("node"));
}

#[test]
fn test_ht_run_stun_help() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "ht", "--", "run", "stun", "--help"])
        .output()
        .expect("Failed to execute ht run stun");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Run STUN server"));
    assert!(stdout.contains("--bind"));
}

#[test]
fn test_ht_run_stun_invalid_address() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "ht", "--", "run", "stun", "--bind", "invalid:address"])
        .output()
        .expect("Failed to execute ht run stun");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Error") || stderr.contains("error") || stderr.contains("invalid"));
}

#[test]
fn test_ht_run_gateway_help() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "ht", "--", "run", "gateway", "--help"])
        .output()
        .expect("Failed to execute ht run gateway");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Run gateway server"));
    assert!(stdout.contains("--kv-path"));
    assert!(stdout.contains("/var/lib/hightower/gateway/db"));
}

