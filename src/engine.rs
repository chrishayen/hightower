use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};

use crate::command::Command;
use crate::compactor::{CompactionConfig, Compactor};
use crate::config::StoreConfig;
use crate::error::{Error, Result};
use crate::id_generator::IdGenerator;
use crate::state::{ApplyOutcome, KvState};
use crate::storage::Storage;

pub trait KvEngine: Send + Sync {
    fn submit(&self, command: Command) -> Result<ApplyOutcome>;
    fn submit_batch<I>(&self, commands: I) -> Result<Vec<ApplyOutcome>>
    where
        I: IntoIterator<Item = Command>,
    {
        let mut outcomes = Vec::new();
        for command in commands {
            outcomes.push(self.submit(command)?);
        }
        Ok(outcomes)
    }
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
}

#[derive(Debug)]
pub struct SingleNodeEngine {
    storage: Arc<Storage>,
    state: RwLock<KvState>,
    version_gen: IdGenerator,
    compactor: Compactor,
    compaction_interval: Duration,
    last_compaction: Mutex<Instant>,
}

impl SingleNodeEngine {
    pub fn new() -> Result<Self> {
        Self::with_config(StoreConfig::default())
    }

    pub fn with_config(config: StoreConfig) -> Result<Self> {
        let storage = Arc::new(Storage::new(&config)?);
        let (mut state, mut max_version) = match storage.load_snapshot()? {
            Some((state, version)) => (state, version),
            None => (KvState::new(), 0u64),
        };
        storage.replay(|command| {
            if command.version() > max_version {
                max_version = max_version.max(command.version());
                state.apply(&command);
            }
            Ok(())
        })?;
        let start_version = max_version
            .checked_add(1)
            .ok_or(Error::Unimplemented("engine::version_overflow"))?;
        let compactor_config = CompactionConfig {
            min_bytes: config.max_segment_size,
            emit_snapshot: config.emit_snapshot_after_compaction,
            ..CompactionConfig::default()
        };
        let compactor = Compactor::new(Arc::clone(&storage), compactor_config);
        let last_compaction = Mutex::new(Instant::now());
        Ok(Self {
            storage,
            state: RwLock::new(state),
            version_gen: IdGenerator::new(start_version.max(1)),
            compactor,
            compaction_interval: config.compaction_interval,
            last_compaction,
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

    pub fn submit_batch<I>(&self, commands: I) -> Result<Vec<ApplyOutcome>>
    where
        I: IntoIterator<Item = Command>,
    {
        self.submit_batch_inner(commands.into_iter())
    }

    pub fn read_with<F, R>(&self, reader: F) -> R
    where
        F: FnOnce(&KvState) -> R,
    {
        let guard = self.state.read();
        reader(&guard)
    }

    pub fn run_compaction_now(&self) -> Result<()> {
        self.compactor.run_once()?;
        *self.last_compaction.lock() = Instant::now();
        Ok(())
    }

    fn submit_batch_inner<I>(&self, commands: I) -> Result<Vec<ApplyOutcome>>
    where
        I: Iterator<Item = Command>,
    {
        let mut state_guard = self.state.write();
        let mut outcomes = Vec::new();
        let mut pending: Vec<(usize, Command)> = Vec::new();
        let mut mutated = false;

        for command in commands {
            let outcome = state_guard.evaluate(&command);
            match outcome {
                ApplyOutcome::Applied | ApplyOutcome::Removed => {
                    let index = outcomes.len();
                    outcomes.push(outcome);
                    pending.push((index, command));
                    mutated = true;
                }
                ApplyOutcome::IgnoredStale => {
                    outcomes.push(ApplyOutcome::IgnoredStale);
                }
            }
        }

        for (index, command) in pending {
            self.storage.apply(&command)?;
            let applied = state_guard.apply(&command);
            debug_assert_eq!(applied, outcomes[index]);
        }

        drop(state_guard);
        if mutated {
            self.maybe_run_compaction()?;
        }

        Ok(outcomes)
    }

    fn maybe_run_compaction(&self) -> Result<()> {
        if self.compaction_interval == Duration::from_secs(0) {
            return Ok(());
        }
        let now = Instant::now();
        {
            let last = self.last_compaction.lock();
            if now.duration_since(*last) < self.compaction_interval {
                return Ok(());
            }
        }
        self.compactor.run_once()?;
        *self.last_compaction.lock() = now;
        Ok(())
    }
}

impl KvEngine for SingleNodeEngine {
    fn submit(&self, command: Command) -> Result<ApplyOutcome> {
        let mut guard = self.state.write();
        let outcome = guard.evaluate(&command);
        let result = match outcome {
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
        };
        let mutated = matches!(result, Ok(ApplyOutcome::Applied | ApplyOutcome::Removed));
        drop(guard);
        if mutated {
            self.maybe_run_compaction()?;
        }
        result
    }

    fn submit_batch<I>(&self, commands: I) -> Result<Vec<ApplyOutcome>>
    where
        I: IntoIterator<Item = Command>,
    {
        self.submit_batch_inner(commands.into_iter())
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
    use std::time::Duration;
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

    #[test]
    fn submit_batch_applies_multiple_commands() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let engine = SingleNodeEngine::with_config(cfg).unwrap();

        let commands = vec![
            Command::Set {
                key: b"a".to_vec(),
                value: b"1".to_vec(),
                version: engine.version_gen.next(),
                timestamp: 1,
            },
            Command::Set {
                key: b"b".to_vec(),
                value: b"2".to_vec(),
                version: engine.version_gen.next(),
                timestamp: 2,
            },
        ];

        let outcomes = engine.submit_batch(commands.clone()).unwrap();
        assert!(
            outcomes
                .iter()
                .all(|outcome| matches!(outcome, ApplyOutcome::Applied))
        );
        assert_eq!(engine.get(b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(engine.get(b"b").unwrap(), Some(b"2".to_vec()));
    }

    #[test]
    fn submit_batch_skips_stale_commands() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let engine = SingleNodeEngine::with_config(cfg).unwrap();
        engine.put(b"k".to_vec(), b"v1".to_vec()).unwrap();

        let stale = Command::Set {
            key: b"k".to_vec(),
            value: b"old".to_vec(),
            version: 1,
            timestamp: 10,
        };
        let fresh = Command::Set {
            key: b"k".to_vec(),
            value: b"v2".to_vec(),
            version: engine.version_gen.next(),
            timestamp: 11,
        };

        let outcomes = engine.submit_batch(vec![stale, fresh]).unwrap();
        assert!(matches!(outcomes[0], ApplyOutcome::IgnoredStale));
        assert!(matches!(outcomes[1], ApplyOutcome::Applied));
        assert_eq!(engine.get(b"k").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn read_with_provides_consistent_snapshot() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let engine = SingleNodeEngine::with_config(cfg).unwrap();
        engine.put(b"snap".to_vec(), b"value".to_vec()).unwrap();

        let snapshot = engine.read_with(|state| {
            state
                .get(b"snap")
                .map(|bytes| bytes.to_vec())
                .unwrap_or_default()
        });

        assert_eq!(snapshot, b"value".to_vec());
    }

    #[test]
    fn run_compaction_now_merges_segments_and_creates_snapshot() {
        let temp = tempdir().unwrap();
        let mut cfg = temp_config(temp.path());
        cfg.max_segment_size = 64;
        cfg.compaction_interval = Duration::from_secs(0);
        cfg.emit_snapshot_after_compaction = true;
        let engine = SingleNodeEngine::with_config(cfg.clone()).unwrap();

        for i in 0..6 {
            engine
                .put(format!("key{i}").into_bytes(), vec![b'x'; 16])
                .unwrap();
        }

        let sealed_before = engine.storage.sealed_segments_snapshot();
        assert!(sealed_before.len() >= 1);

        engine.run_compaction_now().unwrap();

        let sealed_after = engine.storage.sealed_segments_snapshot();
        assert!(sealed_after.len() <= sealed_before.len());

        let snapshot_path = std::path::Path::new(&cfg.data_dir).join("snapshot.bin");
        assert!(snapshot_path.exists());

        drop(engine);

        let reopened = SingleNodeEngine::with_config(cfg).unwrap();
        assert!(reopened.get(b"key0").unwrap().is_some());
    }
}
