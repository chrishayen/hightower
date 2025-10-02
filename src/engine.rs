use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;

use crate::command::Command;
use crate::config::StoreConfig;
use crate::error::{Error, Result};
use crate::id_generator::IdGenerator;
use crate::state::{ApplyOutcome, KvState};
use crate::storage::Storage;

pub trait KvEngine: Send + Sync {
    fn submit(&self, command: Command) -> Result<ApplyOutcome>;
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
}

#[derive(Debug)]
pub struct SingleNodeEngine {
    storage: Storage,
    state: RwLock<KvState>,
    version_gen: IdGenerator,
}

impl SingleNodeEngine {
    pub fn new() -> Result<Self> {
        Self::with_config(StoreConfig::default())
    }

    pub fn with_config(config: StoreConfig) -> Result<Self> {
        let storage = Storage::new(&config)?;
        let mut state = KvState::new();
        let mut max_version = 0u64;
        storage.replay(|command| {
            max_version = max_version.max(command.version());
            state.apply(&command);
            Ok(())
        })?;
        let start_version = max_version
            .checked_add(1)
            .ok_or(Error::Unimplemented("engine::version_overflow"))?;
        Ok(Self {
            storage,
            state: RwLock::new(state),
            version_gen: IdGenerator::new(start_version.max(1)),
        })
    }

    fn next_version(&self) -> u64 {
        self.version_gen.next()
    }

    pub fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<ApplyOutcome> {
        let version = self.next_version();
        let command = Command::Set {
            key,
            value,
            version,
            timestamp: current_timestamp(),
        };
        self.submit(command)
    }

    pub fn delete(&self, key: Vec<u8>) -> Result<ApplyOutcome> {
        let version = self.next_version();
        let command = Command::Delete {
            key,
            version,
            timestamp: current_timestamp(),
        };
        self.submit(command)
    }

    pub fn len(&self) -> usize {
        self.state.read().len()
    }

    pub fn flush(&self) -> Result<()> {
        self.storage.sync()
    }
}

impl KvEngine for SingleNodeEngine {
    fn submit(&self, command: Command) -> Result<ApplyOutcome> {
        let mut guard = self.state.write();
        let outcome = guard.evaluate(&command);
        match outcome {
            ApplyOutcome::Applied | ApplyOutcome::Removed => {
                self.storage.apply(&command)?;
                let applied = guard.apply(&command);
                debug_assert!(matches!(
                    applied,
                    ApplyOutcome::Applied | ApplyOutcome::Removed
                ));
                Ok(applied)
            }
            ApplyOutcome::IgnoredStale => Ok(ApplyOutcome::IgnoredStale),
        }
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(value) = self.state.read().get(key) {
            return Ok(Some(value.to_vec()));
        }

        let entry = match self.storage.lookup(key) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        if entry.is_tombstone {
            let mut guard = self.state.write();
            guard.apply(&Command::Delete {
                key: key.to_vec(),
                version: entry.version,
                timestamp: 0,
            });
            return Ok(None);
        }

        let command = match self.storage.fetch_command(&entry)? {
            Some(command) => command,
            None => return Ok(None),
        };

        let command_timestamp = command.timestamp();
        match command {
            Command::Set {
                key,
                value,
                version,
                ..
            } => {
                let mut guard = self.state.write();
                let cloned_value = value.clone();
                guard.apply(&Command::Set {
                    key: key.clone(),
                    value,
                    version,
                    timestamp: command_timestamp,
                });
                Ok(Some(cloned_value))
            }
            Command::Delete { key, version, .. } => {
                let mut guard = self.state.write();
                guard.apply(&Command::Delete {
                    key,
                    version,
                    timestamp: command_timestamp,
                });
                Ok(None)
            }
        }
    }
}

fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn temp_config(dir: &std::path::Path) -> StoreConfig {
        let mut cfg = StoreConfig::default();
        cfg.data_dir = dir.join("engine-data").to_string_lossy().into_owned();
        cfg
    }

    #[test]
    fn put_and_get_via_engine() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let engine = SingleNodeEngine::with_config(cfg).unwrap();
        engine.put(b"alpha".to_vec(), b"beta".to_vec()).unwrap();
        let fetched = engine.get(b"alpha").unwrap();
        assert_eq!(fetched, Some(b"beta".to_vec()));
        assert_eq!(engine.len(), 1);
    }

    #[test]
    fn delete_removes_key() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let engine = SingleNodeEngine::with_config(cfg).unwrap();
        engine.put(b"key".to_vec(), b"value".to_vec()).unwrap();
        engine.delete(b"key".to_vec()).unwrap();
        assert!(engine.get(b"key").unwrap().is_none());
    }

    #[test]
    fn persists_across_reopen() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        {
            let engine = SingleNodeEngine::with_config(cfg.clone()).unwrap();
            engine.put(b"persist".to_vec(), b"value".to_vec()).unwrap();
        }
        let reopened = SingleNodeEngine::with_config(cfg).unwrap();
        let value = reopened.get(b"persist").unwrap();
        assert_eq!(value, Some(b"value".to_vec()));
    }

    #[test]
    fn get_reads_from_storage_on_cache_miss() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let engine = SingleNodeEngine::with_config(cfg).unwrap();
        engine.put(b"alpha".to_vec(), b"beta".to_vec()).unwrap();

        {
            let mut guard = engine.state.write();
            guard.clear_for_test();
        }

        let fetched = engine.get(b"alpha").unwrap();
        assert_eq!(fetched, Some(b"beta".to_vec()));
        assert_eq!(engine.len(), 1);
    }

    #[test]
    fn flush_propagates_to_storage() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let engine = SingleNodeEngine::with_config(cfg).unwrap();
        engine.put(b"key".to_vec(), b"value".to_vec()).unwrap();
        engine.flush().unwrap();
    }
}
