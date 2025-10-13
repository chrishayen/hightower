use kv::{SingleNodeEngine, StoreConfig};
use tempfile::TempDir;

fn main() -> kv::Result<()> {
    let temp_dir = TempDir::new()?;
    let mut config = StoreConfig::default();
    config.data_dir = temp_dir.path().join("prefix-demo").to_string_lossy().into_owned();
    config.worker_threads = 2;

    let engine = SingleNodeEngine::with_config(config)?;

    println!("Populating store with namespaced keys...");

    // Users namespace
    engine.put(b"user:1001".to_vec(), b"alice@example.com".to_vec())?;
    engine.put(b"user:1002".to_vec(), b"bob@example.com".to_vec())?;
    engine.put(b"user:1003".to_vec(), b"charlie@example.com".to_vec())?;

    // Sessions namespace
    engine.put(b"session:abc123".to_vec(), b"user:1001".to_vec())?;
    engine.put(b"session:def456".to_vec(), b"user:1002".to_vec())?;
    engine.put(b"session:ghi789".to_vec(), b"user:1003".to_vec())?;

    // Config namespace
    engine.put(b"config:max_conn".to_vec(), b"100".to_vec())?;
    engine.put(b"config:timeout".to_vec(), b"30".to_vec())?;
    engine.put(b"config:debug".to_vec(), b"true".to_vec())?;

    // Other keys
    engine.put(b"stats:requests".to_vec(), b"12345".to_vec())?;
    engine.put(b"cache:page1".to_vec(), b"<html>...</html>".to_vec())?;

    println!("\n=== Querying all users (prefix: 'user:') ===");
    let users = engine.get_prefix(b"user:")?;
    println!("Found {} users:", users.len());
    for (key, value) in &users {
        println!(
            "  {} => {}",
            String::from_utf8_lossy(key),
            String::from_utf8_lossy(value)
        );
    }

    println!("\n=== Querying all sessions (prefix: 'session:') ===");
    let sessions = engine.get_prefix(b"session:")?;
    println!("Found {} sessions:", sessions.len());
    for (key, value) in &sessions {
        println!(
            "  {} => {}",
            String::from_utf8_lossy(key),
            String::from_utf8_lossy(value)
        );
    }

    println!("\n=== Querying all config (prefix: 'config:') ===");
    let config_items = engine.get_prefix(b"config:")?;
    println!("Found {} config items:", config_items.len());
    for (key, value) in &config_items {
        println!(
            "  {} => {}",
            String::from_utf8_lossy(key),
            String::from_utf8_lossy(value)
        );
    }

    println!("\n=== Querying non-existent prefix ===");
    let missing = engine.get_prefix(b"missing:")?;
    println!("Found {} items with prefix 'missing:': {:?}", missing.len(), missing);

    println!("\n=== Querying all keys (empty prefix) ===");
    let all_keys = engine.get_prefix(b"")?;
    println!("Total keys in store: {}", all_keys.len());

    // Demonstrate deletion and prefix query
    println!("\n=== Deleting user:1002 and re-querying ===");
    engine.delete(b"user:1002".to_vec())?;
    let users_after_delete = engine.get_prefix(b"user:")?;
    println!("Users after deletion: {}", users_after_delete.len());
    for (key, value) in &users_after_delete {
        println!(
            "  {} => {}",
            String::from_utf8_lossy(key),
            String::from_utf8_lossy(value)
        );
    }

    // Demonstrate hierarchical prefixes
    println!("\n=== Hierarchical prefix queries ===");
    engine.put(b"api:v1:users".to_vec(), b"/users".to_vec())?;
    engine.put(b"api:v1:posts".to_vec(), b"/posts".to_vec())?;
    engine.put(b"api:v2:users".to_vec(), b"/v2/users".to_vec())?;
    engine.put(b"api:v2:posts".to_vec(), b"/v2/posts".to_vec())?;

    let api_all = engine.get_prefix(b"api:")?;
    println!("All API routes: {} entries", api_all.len());

    let api_v1 = engine.get_prefix(b"api:v1:")?;
    println!("API v1 routes: {} entries", api_v1.len());
    for (key, value) in &api_v1 {
        println!(
            "  {} => {}",
            String::from_utf8_lossy(key),
            String::from_utf8_lossy(value)
        );
    }

    let api_v2 = engine.get_prefix(b"api:v2:")?;
    println!("API v2 routes: {} entries", api_v2.len());
    for (key, value) in &api_v2 {
        println!(
            "  {} => {}",
            String::from_utf8_lossy(key),
            String::from_utf8_lossy(value)
        );
    }

    engine.flush()?;
    println!("\n✓ All prefix queries completed successfully");

    Ok(())
}
