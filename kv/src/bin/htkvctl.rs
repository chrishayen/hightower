use std::env;
use std::error::Error;
use std::path::PathBuf;

use kv::auth_types::UserRecord;
use kv::storage::Storage;
use kv::{SingleNodeEngine, StoreConfig};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let command = args
        .next()
        .ok_or_else(|| "usage: htkvctl <compact|segments|list-users> [data_dir]".to_string())?;
    let data_dir = args.next();

    match command.as_str() {
        "compact" => {
            let cfg = build_config(data_dir)?;
            let engine = SingleNodeEngine::with_config(cfg.clone())?;
            engine.run_compaction_now()?;
            println!("compaction complete for {}", cfg.data_dir);
        }
        "segments" => {
            let cfg = build_config(data_dir)?;
            for (id, entries, bytes) in collect_segments(&cfg)? {
                println!("segment-{id:05} entries:{entries} bytes:{bytes}");
            }
        }
        "list-users" => {
            let cfg = build_config(data_dir)?;
            let users = collect_users(&cfg)?;
            if users.is_empty() {
                println!("no users found");
            } else {
                for (user_id, username) in users {
                    println!("{username} ({user_id})");
                }
            }
        }
        _ => return Err("unknown command".into()),
    }

    Ok(())
}

fn build_config(data_dir: Option<String>) -> Result<StoreConfig, Box<dyn Error>> {
    let mut cfg = StoreConfig::default();
    if let Some(dir) = data_dir {
        cfg.data_dir = PathBuf::from(dir).to_string_lossy().into_owned();
    }
    Ok(cfg)
}

fn collect_segments(cfg: &StoreConfig) -> Result<Vec<(u64, u64, u64)>, Box<dyn Error>> {
    let storage = Storage::new(cfg)?;
    let mut segments: Vec<(u64, u64, u64)> = storage
        .segment_snapshot()
        .into_iter()
        .map(|segment| (segment.id(), segment.entries(), segment.bytes_written()))
        .collect();
    segments.sort_by_key(|(id, _, _)| *id);
    Ok(segments)
}

fn collect_users(cfg: &StoreConfig) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let storage = Storage::new(cfg)?;
    let snapshot = storage.state_snapshot();
    let mut users = Vec::new();
    for (key, (value, _)) in snapshot.iter() {
        if !key.starts_with(b"auth/user/") {
            continue;
        }
        let record: UserRecord = serde_cbor::from_slice(value)?;
        users.push((record.user_id.clone(), record.username.clone()));
    }
    users.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(users)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn segments_returns_active_segments() {
        let temp = tempdir().unwrap();
        let mut cfg = StoreConfig::default();
        cfg.data_dir = temp.path().join("segments").to_string_lossy().into_owned();
        let engine = SingleNodeEngine::with_config(cfg.clone()).unwrap();
        engine.put(b"a".to_vec(), b"1".to_vec()).unwrap();
        engine.flush().unwrap();
        let segments = collect_segments(&cfg).unwrap();
        assert_eq!(segments.len(), 1);
    }

    #[test]
    fn collect_users_extracts_records() {
        let temp = tempdir().unwrap();
        let mut cfg = StoreConfig::default();
        cfg.data_dir = temp.path().join("users").to_string_lossy().into_owned();
        let engine = SingleNodeEngine::with_config(cfg.clone()).unwrap();
        let service = kv::AuthService::new(
            engine,
            kv::crypto::Argon2SecretHasher::default(),
            kv::crypto::AesGcmEncryptor::new([0u8; 32]),
        );
        service.create_user("alice", "password").unwrap();
        let users = collect_users(&cfg).unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].1, "alice");
    }
}
