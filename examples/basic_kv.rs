use hightower_kv::{KvEngine, SingleNodeEngine, StoreConfig};
use std::error::Error;
use std::path::PathBuf;
use tempfile::TempDir;

fn main() -> Result<(), Box<dyn Error>> {
    // Each example run writes to an isolated temporary directory.
    let tempdir = TempDir::new()?;
    let data_dir = tempdir.path().join("kv-data");

    // Configure the engine for four worker threads so concurrent writers scale.
    let mut config = StoreConfig::default();
    config.data_dir = path_to_string(data_dir);
    config.worker_threads = 4;

    let engine = SingleNodeEngine::with_config(config)?;

    // Submit writes. `SingleNodeEngine::put` assigns versions automatically.
    engine.put(b"alpha".to_vec(), b"bravo".to_vec())?;
    engine.put(b"charlie".to_vec(), b"delta".to_vec())?;

    // Reads go through the `KvEngine` trait.
    let alpha = engine.get(b"alpha")?.expect("alpha should exist");
    println!("alpha => {}", String::from_utf8_lossy(&alpha));

    // Update an existing value with a newer version.
    engine.put(b"alpha".to_vec(), b"echo".to_vec())?;
    let alpha_updated = engine.get(b"alpha")?.expect("alpha should still exist");
    println!(
        "alpha (after update) => {}",
        String::from_utf8_lossy(&alpha_updated)
    );

    // Deleting keys simply enqueues a tombstone entry.
    engine.delete(b"charlie".to_vec())?;
    assert!(engine.get(b"charlie")?.is_none());

    // Flush outstanding writes to disk before exiting.
    engine.flush()?;

    Ok(())
}

fn path_to_string(path: PathBuf) -> String {
    path.to_string_lossy().into_owned()
}
