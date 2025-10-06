use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, bounded, unbounded};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;

use crate::auth_service::AuthService;
use crate::command::Command;
use crate::compactor::{CompactionConfig, Compactor};
use crate::config::StoreConfig;
use crate::crypto::{AesGcmEncryptor, Argon2SecretHasher};
use crate::error::{Error, Result};
use crate::id_generator::IdGenerator;
use crate::state::{ApplyOutcome, ConcurrentKvState, KvState};
use crate::storage::Storage;

/// Core key-value engine trait for command submission and retrieval.
pub trait KvEngine: Send + Sync {
    /// Submits a single command for execution.
    fn submit(&self, command: Command) -> Result<ApplyOutcome>;
    /// Submits a batch of commands for execution.
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
    /// Retrieves the value for a key if it exists.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    /// Retrieves all key-value pairs with the given prefix.
    fn get_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;
}

/// Trait for engines that can produce state snapshots.
pub trait SnapshotEngine {
    /// Returns a snapshot of the current key-value state.
    fn snapshot_state(&self) -> KvState;
    /// Returns the latest version number in the store.
    fn latest_version(&self) -> u64;
}

#[derive(Debug)]
struct EngineShared {
    storage: Arc<Storage>,
    state: Arc<ConcurrentKvState>,
    version_gen: IdGenerator,
    compactor: Compactor,
    compaction_interval: Duration,
    last_compaction: Mutex<Instant>,
}

impl EngineShared {
    fn new(
        storage: Arc<Storage>,
        state: Arc<ConcurrentKvState>,
        version_gen: IdGenerator,
        compactor: Compactor,
        compaction_interval: Duration,
    ) -> Self {
        Self {
            storage,
            state,
            version_gen,
            compactor,
            compaction_interval,
            last_compaction: Mutex::new(Instant::now()),
        }
    }

    fn next_version(&self) -> u64 {
        self.version_gen.next()
    }

    fn len(&self) -> usize {
        self.state.len()
    }

    fn read_with<F, R>(&self, reader: F) -> R
    where
        F: FnOnce(&KvState) -> R,
    {
        self.state.read_with(reader)
    }

    fn apply_single(&self, command: Command) -> Result<ApplyOutcome> {
        let mut guard = self.state.lock_entry(command.key());
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

    fn apply_batch(&self, commands: Vec<Command>) -> Result<Vec<ApplyOutcome>> {
        let mut outcomes = Vec::with_capacity(commands.len());
        let mut mutated = false;

        for command in commands {
            let mut guard = self.state.lock_entry(command.key());
            let outcome = guard.evaluate(&command);
            match outcome {
                ApplyOutcome::Applied | ApplyOutcome::Removed => {
                    self.storage.apply(&command)?;
                    let applied = guard.apply(&command);
                    debug_assert!(matches!(
                        applied,
                        ApplyOutcome::Applied | ApplyOutcome::Removed
                    ));
                    if matches!(applied, ApplyOutcome::Applied | ApplyOutcome::Removed) {
                        mutated = true;
                    }
                    outcomes.push(applied);
                }
                ApplyOutcome::IgnoredStale => outcomes.push(ApplyOutcome::IgnoredStale),
            }
        }

        if mutated {
            self.maybe_run_compaction()?;
        }

        Ok(outcomes)
    }

    fn maybe_run_compaction(&self) -> Result<()> {
        if self.compaction_interval.is_zero() {
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

    fn run_compaction_now(&self) -> Result<()> {
        self.compactor.run_once()?;
        *self.last_compaction.lock() = Instant::now();
        Ok(())
    }
}

enum WorkItem {
    Command {
        command: Command,
        responder: Sender<Result<ApplyOutcome>>,
    },
    Batch {
        commands: Vec<Command>,
        responder: Sender<Result<Vec<ApplyOutcome>>>,
    },
}

/// Single-node key-value engine with worker threads and automatic compaction.
#[derive(Debug)]
pub struct SingleNodeEngine {
    shared: Arc<EngineShared>,
    dispatcher: Option<Sender<WorkItem>>,
    workers: Vec<JoinHandle<()>>,
    compaction_signal: Option<Sender<()>>,
    compaction_worker: Option<JoinHandle<()>>,
}

impl SingleNodeEngine {
    /// Creates a new engine with default configuration.
    pub fn new() -> Result<Self> {
        Self::with_config(StoreConfig::default())
    }

    /// Creates a new engine with the specified configuration.
    pub fn with_config(config: StoreConfig) -> Result<Self> {
        let worker_threads = config.worker_threads;
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

        let concurrent_state = Arc::new(ConcurrentKvState::from(state));

        let shared = Arc::new(EngineShared::new(
            storage,
            Arc::clone(&concurrent_state),
            IdGenerator::new(start_version.max(1)),
            compactor,
            config.compaction_interval,
        ));

        let (dispatcher, workers) = if worker_threads == 0 {
            (None, Vec::new())
        } else {
            let (task_tx, task_rx) = unbounded::<WorkItem>();
            let workers = spawn_workers(worker_threads, Arc::clone(&shared), task_rx);
            (Some(task_tx), workers)
        };

        let (shutdown_tx, shutdown_rx) = unbounded::<()>();
        let compaction_worker = spawn_compaction_worker(Arc::clone(&shared), shutdown_rx);
        let compaction_signal = compaction_worker.as_ref().map(|_| shutdown_tx);

        Ok(Self {
            shared,
            dispatcher,
            workers,
            compaction_signal,
            compaction_worker,
        })
    }

    fn next_version(&self) -> u64 {
        self.shared.next_version()
    }

    /// Inserts or updates a key-value pair.
    pub fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<ApplyOutcome> {
        let version = self.next_version();
        let command = Command::Set {
            key,
            value,
            version,
            timestamp: current_timestamp(),
        };
        self.dispatch_command(command)
    }

    /// Deletes a key from the store.
    pub fn delete(&self, key: Vec<u8>) -> Result<ApplyOutcome> {
        let version = self.next_version();
        let command = Command::Delete {
            key,
            version,
            timestamp: current_timestamp(),
        };
        self.dispatch_command(command)
    }

    /// Returns the number of keys in the store.
    pub fn len(&self) -> usize {
        self.shared.len()
    }

    /// Flushes pending writes to disk.
    pub fn flush(&self) -> Result<()> {
        self.shared.storage.sync()
    }

    /// Submits a batch of commands for execution.
    pub fn submit_batch<I>(&self, commands: I) -> Result<Vec<ApplyOutcome>>
    where
        I: IntoIterator<Item = Command>,
    {
        let collected: Vec<Command> = commands.into_iter().collect();
        self.dispatch_batch(collected)
    }

    /// Executes a read operation with a consistent snapshot of the state.
    pub fn read_with<F, R>(&self, reader: F) -> R
    where
        F: FnOnce(&KvState) -> R,
    {
        self.shared.read_with(reader)
    }

    /// Triggers an immediate compaction run.
    pub fn run_compaction_now(&self) -> Result<()> {
        self.shared.run_compaction_now()
    }

    /// Retrieves all key-value pairs with the given prefix.
    pub fn get_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let entries = self.shared.storage.get_prefix(prefix);
        let mut results = Vec::with_capacity(entries.len());

        for (key, entry) in entries {
            if entry.is_tombstone {
                continue;
            }

            // Try to get from state first
            if let Some(value) = self.shared.state.get(&key) {
                results.push((key, value));
                continue;
            }

            // Fetch from storage if not in state
            if let Some(command) = self.shared.storage.fetch_command(&entry)? {
                if let Command::Set { key, value, version, timestamp } = command {
                    let mut guard = self.shared.state.lock_entry(&key);
                    guard.apply(&Command::Set {
                        key: key.clone(),
                        value: value.clone(),
                        version,
                        timestamp,
                    });
                    results.push((key, value));
                }
            }
        }

        Ok(results)
    }

    /// Wraps the engine in an `Arc` and constructs an `AuthService` configured with Argon2 hashing and AES-GCM encryption.
    pub fn into_argon2_hasher_aes_gcm_auth_service(
        self,
        master_key: [u8; 32],
    ) -> (
        Arc<SingleNodeEngine>,
        AuthService<Arc<SingleNodeEngine>, Argon2SecretHasher, AesGcmEncryptor>,
    ) {
        let engine = Arc::new(self);
        let auth = AuthService::new(
            Arc::clone(&engine),
            Argon2SecretHasher::default(),
            AesGcmEncryptor::new(master_key),
        );
        (engine, auth)
    }

    fn dispatch_command(&self, command: Command) -> Result<ApplyOutcome> {
        if let Some(dispatcher) = &self.dispatcher {
            let (tx, rx) = bounded(1);
            dispatcher
                .send(WorkItem::Command {
                    command,
                    responder: tx,
                })
                .map_err(|_| Error::Invariant("engine dispatcher unavailable"))?;
            rx.recv()
                .map_err(|_| Error::Invariant("engine worker terminated"))?
        } else {
            self.shared.apply_single(command)
        }
    }

    fn dispatch_batch(&self, commands: Vec<Command>) -> Result<Vec<ApplyOutcome>> {
        if let Some(dispatcher) = &self.dispatcher {
            let (tx, rx) = bounded(1);
            dispatcher
                .send(WorkItem::Batch {
                    commands,
                    responder: tx,
                })
                .map_err(|_| Error::Invariant("engine dispatcher unavailable"))?;
            rx.recv()
                .map_err(|_| Error::Invariant("engine worker terminated"))?
        } else {
            self.shared.apply_batch(commands)
        }
    }
    #[cfg(test)]
    pub(crate) fn test_next_version(&self) -> u64 {
        self.next_version()
    }

    #[cfg(test)]
    pub(crate) fn storage_for_test(&self) -> Arc<Storage> {
        Arc::clone(&self.shared.storage)
    }

    #[cfg(test)]
    pub(crate) fn clear_state_for_test(&self) {
        self.shared.state.clear_for_test()
    }
}

impl Drop for SingleNodeEngine {
    fn drop(&mut self) {
        if let Some(dispatcher) = self.dispatcher.take() {
            drop(dispatcher);
        }

        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }

        if let Some(signal) = self.compaction_signal.take() {
            let _ = signal.send(());
        }

        if let Some(handle) = self.compaction_worker.take() {
            let _ = handle.join();
        }
    }
}

impl KvEngine for SingleNodeEngine {
    fn submit(&self, command: Command) -> Result<ApplyOutcome> {
        self.dispatch_command(command)
    }

    fn submit_batch<I>(&self, commands: I) -> Result<Vec<ApplyOutcome>>
    where
        I: IntoIterator<Item = Command>,
    {
        let collected: Vec<Command> = commands.into_iter().collect();
        self.dispatch_batch(collected)
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(value) = self.shared.state.get(key) {
            return Ok(Some(value));
        }

        let entry = match self.shared.storage.lookup(key) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        if entry.is_tombstone {
            let mut guard = self.shared.state.lock_entry(key);
            guard.apply(&Command::Delete {
                key: key.to_vec(),
                version: entry.version,
                timestamp: 0,
            });
            return Ok(None);
        }

        let command = match self.shared.storage.fetch_command(&entry)? {
            Some(command) => command,
            None => return Ok(None),
        };

        let command_timestamp = command.timestamp();
        match &command {
            Command::Set {
                key,
                value,
                version,
                ..
            } => {
                let mut guard = self.shared.state.lock_entry(key);
                let cloned_value = value.clone();
                guard.apply(&Command::Set {
                    key: key.clone(),
                    value: value.clone(),
                    version: *version,
                    timestamp: command_timestamp,
                });
                Ok(Some(cloned_value))
            }
            Command::Delete { key, version, .. } => {
                let mut guard = self.shared.state.lock_entry(key);
                guard.apply(&Command::Delete {
                    key: key.clone(),
                    version: *version,
                    timestamp: command_timestamp,
                });
                Ok(None)
            }
        }
    }

    fn get_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.get_prefix(prefix)
    }
}

impl<E> KvEngine for Arc<E>
where
    E: KvEngine,
{
    fn submit(&self, command: Command) -> Result<ApplyOutcome> {
        (**self).submit(command)
    }

    fn submit_batch<I>(&self, commands: I) -> Result<Vec<ApplyOutcome>>
    where
        I: IntoIterator<Item = Command>,
    {
        (**self).submit_batch(commands)
    }

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        (**self).get(key)
    }

    fn get_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        (**self).get_prefix(prefix)
    }
}

impl SnapshotEngine for SingleNodeEngine {
    fn snapshot_state(&self) -> KvState {
        self.shared.storage.state_snapshot()
    }

    fn latest_version(&self) -> u64 {
        self.shared.storage.latest_version()
    }
}

/// Spawns worker threads to process commands concurrently.
fn spawn_workers(
    count: usize,
    shared: Arc<EngineShared>,
    task_rx: Receiver<WorkItem>,
) -> Vec<JoinHandle<()>> {
    let count = count.max(1);
    let mut handles = Vec::with_capacity(count);
    for index in 0..count {
        let worker_rx = task_rx.clone();
        let worker_shared = Arc::clone(&shared);
        let handle = thread::Builder::new()
            .name(format!("hightower-engine-worker-{index}"))
            .spawn(move || worker_loop(worker_shared, worker_rx))
            .expect("failed to spawn engine worker");
        handles.push(handle);
    }
    drop(task_rx);
    handles
}

fn worker_loop(shared: Arc<EngineShared>, task_rx: Receiver<WorkItem>) {
    while let Ok(item) = task_rx.recv() {
        match item {
            WorkItem::Command { command, responder } => {
                let result = shared.apply_single(command);
                let _ = responder.send(result);
            }
            WorkItem::Batch {
                commands,
                responder,
            } => {
                let result = shared.apply_batch(commands);
                let _ = responder.send(result);
            }
        }
    }
}

/// Spawns a background worker to run periodic compaction.
fn spawn_compaction_worker(
    shared: Arc<EngineShared>,
    shutdown: Receiver<()>,
) -> Option<JoinHandle<()>> {
    if shared.compaction_interval.is_zero() {
        return None;
    }

    let interval = shared.compaction_interval;
    Some(
        thread::Builder::new()
            .name("hightower-compactor".into())
            .spawn(move || {
                loop {
                    match shutdown.recv_timeout(interval) {
                        Ok(_) | Err(RecvTimeoutError::Disconnected) => break,
                        Err(RecvTimeoutError::Timeout) => {
                            let _ = shared.maybe_run_compaction();
                        }
                    }
                }
            })
            .expect("failed to spawn compaction worker"),
    )
}

/// Returns the current Unix timestamp in seconds.
fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;

    fn temp_config(dir: &std::path::Path) -> StoreConfig {
        let mut cfg = StoreConfig::default();
        cfg.data_dir = dir.join("engine-data").to_string_lossy().into_owned();
        cfg.worker_threads = 2;
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

        engine.clear_state_for_test();

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
                version: engine.test_next_version(),
                timestamp: 1,
            },
            Command::Set {
                key: b"b".to_vec(),
                value: b"2".to_vec(),
                version: engine.test_next_version(),
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
            version: engine.test_next_version(),
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

        let storage_before = engine.storage_for_test();
        let sealed_before = storage_before.sealed_segments_snapshot();
        assert!(sealed_before.len() >= 1);

        engine.run_compaction_now().unwrap();

        let storage_after = engine.storage_for_test();
        let sealed_after = storage_after.sealed_segments_snapshot();
        assert!(sealed_after.len() <= sealed_before.len());

        let snapshot_path = std::path::Path::new(&cfg.data_dir).join("snapshot.bin");
        assert!(snapshot_path.exists());

        drop(engine);

        let reopened = SingleNodeEngine::with_config(cfg).unwrap();
        assert!(reopened.get(b"key0").unwrap().is_some());
    }

    #[test]
    fn into_argon2_hasher_aes_gcm_auth_service_returns_handles() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let engine = SingleNodeEngine::with_config(cfg).unwrap();

        let (engine, auth) = engine.into_argon2_hasher_aes_gcm_auth_service([7u8; 32]);

        let user = auth.create_user("bundle", "secret").unwrap();
        assert!(auth.verify_password("bundle", "secret").unwrap());

        let (record, token) = auth.create_api_key(&user.user_id, None).unwrap();
        assert!(token.starts_with(&record.key_id));
        assert!(auth.authenticate_api_key(&token).unwrap().is_some());

        engine.put(b"key".to_vec(), b"value".to_vec()).unwrap();
        assert_eq!(engine.get(b"key").unwrap(), Some(b"value".to_vec()));
    }

    #[test]
    fn concurrent_submitters_share_workers() {
        let temp = tempdir().unwrap();
        let mut cfg = temp_config(temp.path());
        cfg.compaction_interval = Duration::from_secs(0);
        let engine = Arc::new(SingleNodeEngine::with_config(cfg).unwrap());

        let threads: Vec<_> = (0..4)
            .map(|worker| {
                let engine = Arc::clone(&engine);
                thread::spawn(move || {
                    for idx in 0..25 {
                        let key = format!("k-{worker}-{idx}").into_bytes();
                        let value = format!("v-{worker}-{idx}").into_bytes();
                        engine.put(key, value).unwrap();
                    }
                })
            })
            .collect();

        for handle in threads {
            handle.join().unwrap();
        }

        for worker in 0..4 {
            for idx in 0..25 {
                let key = format!("k-{worker}-{idx}").into_bytes();
                let expected = format!("v-{worker}-{idx}").into_bytes();
                assert_eq!(engine.get(&key).unwrap(), Some(expected));
            }
        }
    }

    #[test]
    fn get_prefix_returns_matching_keys() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let engine = SingleNodeEngine::with_config(cfg).unwrap();

        engine.put(b"app:user:1".to_vec(), b"alice".to_vec()).unwrap();
        engine.put(b"app:user:2".to_vec(), b"bob".to_vec()).unwrap();
        engine.put(b"app:session:1".to_vec(), b"s1".to_vec()).unwrap();
        engine.put(b"other:key".to_vec(), b"value".to_vec()).unwrap();

        let results = engine.get_prefix(b"app:user:").unwrap();
        assert_eq!(results.len(), 2);

        let mut keys: Vec<Vec<u8>> = results.iter().map(|(k, _)| k.clone()).collect();
        keys.sort();
        assert_eq!(keys[0], b"app:user:1");
        assert_eq!(keys[1], b"app:user:2");

        let values: Vec<Vec<u8>> = results.iter().map(|(_, v)| v.clone()).collect();
        assert!(values.contains(&b"alice".to_vec()));
        assert!(values.contains(&b"bob".to_vec()));
    }

    #[test]
    fn get_prefix_excludes_deleted_keys() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let engine = SingleNodeEngine::with_config(cfg).unwrap();

        engine.put(b"prefix:key1".to_vec(), b"value1".to_vec()).unwrap();
        engine.put(b"prefix:key2".to_vec(), b"value2".to_vec()).unwrap();
        engine.delete(b"prefix:key1".to_vec()).unwrap();

        let results = engine.get_prefix(b"prefix:").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, b"prefix:key2");
        assert_eq!(results[0].1, b"value2");
    }

    #[test]
    fn get_prefix_with_empty_prefix_returns_all() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let engine = SingleNodeEngine::with_config(cfg).unwrap();

        engine.put(b"a".to_vec(), b"1".to_vec()).unwrap();
        engine.put(b"b".to_vec(), b"2".to_vec()).unwrap();
        engine.put(b"c".to_vec(), b"3".to_vec()).unwrap();

        let results = engine.get_prefix(b"").unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn get_prefix_persists_across_reopen() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());

        {
            let engine = SingleNodeEngine::with_config(cfg.clone()).unwrap();
            engine.put(b"persist:1".to_vec(), b"v1".to_vec()).unwrap();
            engine.put(b"persist:2".to_vec(), b"v2".to_vec()).unwrap();
            engine.put(b"other".to_vec(), b"v3".to_vec()).unwrap();
        }

        let reopened = SingleNodeEngine::with_config(cfg).unwrap();
        let results = reopened.get_prefix(b"persist:").unwrap();
        assert_eq!(results.len(), 2);

        let keys: Vec<Vec<u8>> = results.iter().map(|(k, _)| k.clone()).collect();
        assert!(keys.contains(&b"persist:1".to_vec()));
        assert!(keys.contains(&b"persist:2".to_vec()));
    }
}
