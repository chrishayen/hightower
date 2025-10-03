use hashbrown::HashMap;
use hashbrown::hash_map::Entry;
use parking_lot::Mutex;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::command::Command;

const DEFAULT_SHARDS: usize = 64;

/// Single-threaded key-value state with versioned entries
#[derive(Debug, Default)]
pub struct KvState {
    entries: HashMap<Vec<u8>, (Vec<u8>, u64)>,
}

/// Outcome of applying a command to the state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Command was successfully applied
    Applied,
    /// Command was ignored because it was stale
    IgnoredStale,
    /// Key was removed from the state
    Removed,
}

impl KvState {
    /// Creates a new empty key-value state
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of entries in the state
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Gets the value for the given key
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.entries
            .get(key)
            .map(|(value, _version)| value.as_slice())
    }

    /// Evaluates what would happen if the command were applied without mutating state
    pub fn evaluate(&self, command: &Command) -> ApplyOutcome {
        match command {
            Command::Set { key, version, .. } => match self.entries.get(key) {
                Some((_, current_version)) if *version <= *current_version => {
                    ApplyOutcome::IgnoredStale
                }
                _ => ApplyOutcome::Applied,
            },
            Command::Delete { key, version, .. } => match self.entries.get(key) {
                Some((_, current_version)) if *version > *current_version => ApplyOutcome::Removed,
                Some(_) => ApplyOutcome::IgnoredStale,
                None => ApplyOutcome::Removed,
            },
        }
    }

    /// Applies a command to the state and returns the outcome
    pub fn apply(&mut self, command: &Command) -> ApplyOutcome {
        match command {
            Command::Set {
                key,
                value,
                version,
                ..
            } => {
                let outcome = self.evaluate(command);
                if matches!(outcome, ApplyOutcome::Applied) {
                    self.entries.insert(key.clone(), (value.clone(), *version));
                }
                outcome
            }
            Command::Delete { key, .. } => {
                let outcome = self.evaluate(command);
                if matches!(outcome, ApplyOutcome::Removed) {
                    self.entries.remove(key);
                }
                outcome
            }
        }
    }

    /// Inserts a snapshot entry directly into the state without version checking
    pub fn insert_snapshot(&mut self, key: Vec<u8>, value: Vec<u8>, version: u64) {
        self.entries.insert(key, (value, version));
    }

    /// Returns an iterator over all entries in the state
    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &(Vec<u8>, u64))> {
        self.entries.iter()
    }

    /// Consumes the state and returns the underlying entries map
    pub fn into_entries(self) -> HashMap<Vec<u8>, (Vec<u8>, u64)> {
        self.entries
    }
}

/// Thread-safe sharded key-value state for concurrent access
#[derive(Debug)]
pub struct ConcurrentKvState {
    shards: Vec<Shard>,
}

impl Default for ConcurrentKvState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConcurrentKvState {
    /// Creates a new concurrent key-value state with default shard count
    pub fn new() -> Self {
        Self::with_shard_count(DEFAULT_SHARDS)
    }

    fn with_shard_count(count: usize) -> Self {
        let shard_count = count.max(1);
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(Shard::new());
        }
        Self { shards }
    }

    /// Returns the total number of entries across all shards
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.len.load(Ordering::Relaxed))
            .sum()
    }

    /// Gets a cloned value for the given key
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let shard = self.shard_for(key);
        let guard = shard.entries.lock();
        guard.get(key).map(|(value, _)| value.clone())
    }

    /// Locks the shard containing the given key and returns an entry guard
    pub fn lock_entry<'a>(&'a self, key: &[u8]) -> EntryGuard<'a> {
        let shard = self.shard_for(key);
        let guard = shard.entries.lock();
        EntryGuard { shard, guard }
    }

    /// Executes a read operation on a snapshot of the entire state
    pub fn read_with<F, R>(&self, reader: F) -> R
    where
        F: FnOnce(&KvState) -> R,
    {
        let snapshot = self.to_snapshot();
        reader(&snapshot)
    }

    /// Creates a consistent snapshot of the entire state
    pub fn to_snapshot(&self) -> KvState {
        let mut snapshot = KvState::new();
        for shard in &self.shards {
            let guard = shard.entries.lock();
            for (key, (value, version)) in guard.iter() {
                snapshot.insert_snapshot(key.clone(), value.clone(), *version);
            }
        }
        snapshot
    }

    /// Inserts a snapshot entry directly into the state
    pub fn insert_snapshot(&self, key: Vec<u8>, value: Vec<u8>, version: u64) {
        let shard = self.shard_for(&key);
        let mut guard = shard.entries.lock();
        if guard.insert(key, (value, version)).is_none() {
            shard.len.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn shard_for(&self, key: &[u8]) -> &Shard {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % self.shards.len();
        &self.shards[idx]
    }

    #[cfg(test)]
    pub(crate) fn clear_for_test(&self) {
        for shard in &self.shards {
            let mut guard = shard.entries.lock();
            guard.clear();
            shard.len.store(0, Ordering::Relaxed);
        }
    }
}

impl From<KvState> for ConcurrentKvState {
    fn from(state: KvState) -> Self {
        let concurrent = ConcurrentKvState::new();
        for (key, (value, version)) in state.into_entries() {
            concurrent.insert_snapshot(key, value, version);
        }
        concurrent
    }
}

/// Guard for a locked shard entry that allows atomic operations
pub struct EntryGuard<'a> {
    shard: &'a Shard,
    guard: parking_lot::MutexGuard<'a, HashMap<Vec<u8>, (Vec<u8>, u64)>>,
}

impl<'a> EntryGuard<'a> {
    /// Evaluates what would happen if the command were applied without mutating state
    pub fn evaluate(&self, command: &Command) -> ApplyOutcome {
        match command {
            Command::Set { key, version, .. } => match self.guard.get(key) {
                Some((_, current_version)) if *version <= *current_version => {
                    ApplyOutcome::IgnoredStale
                }
                _ => ApplyOutcome::Applied,
            },
            Command::Delete { key, version, .. } => match self.guard.get(key) {
                Some((_, current_version)) if *version > *current_version => ApplyOutcome::Removed,
                Some(_) => ApplyOutcome::IgnoredStale,
                None => ApplyOutcome::Removed,
            },
        }
    }

    /// Applies a command to the locked entry and returns the outcome
    pub fn apply(&mut self, command: &Command) -> ApplyOutcome {
        match command {
            Command::Set {
                key,
                value,
                version,
                ..
            } => {
                let outcome = self.evaluate(command);
                if matches!(outcome, ApplyOutcome::Applied) {
                    match self.guard.entry(key.clone()) {
                        Entry::Occupied(mut entry) => {
                            entry.insert((value.clone(), *version));
                        }
                        Entry::Vacant(entry) => {
                            entry.insert((value.clone(), *version));
                            self.shard.len.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                outcome
            }
            Command::Delete { key, .. } => {
                let outcome = self.evaluate(command);
                if matches!(outcome, ApplyOutcome::Removed) {
                    if self.guard.remove(key).is_some() {
                        self.shard.len.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                outcome
            }
        }
    }
}

#[derive(Debug)]
struct Shard {
    entries: Mutex<HashMap<Vec<u8>, (Vec<u8>, u64)>>,
    len: AtomicUsize,
}

impl Shard {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            len: AtomicUsize::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_get_roundtrip() {
        let mut state = KvState::new();
        let cmd = Command::Set {
            key: b"key".to_vec(),
            value: b"value".to_vec(),
            version: 1,
            timestamp: 1,
        };
        assert_eq!(state.apply(&cmd), ApplyOutcome::Applied);
        assert_eq!(state.get(b"key"), Some(&b"value"[..]));
        assert_eq!(state.len(), 1);
    }

    #[test]
    fn stale_write_is_ignored() {
        let mut state = KvState::new();
        let first = Command::Set {
            key: b"key".to_vec(),
            value: b"v1".to_vec(),
            version: 5,
            timestamp: 5,
        };
        let stale = Command::Set {
            key: b"key".to_vec(),
            value: b"v0".to_vec(),
            version: 4,
            timestamp: 4,
        };
        assert_eq!(state.apply(&first), ApplyOutcome::Applied);
        assert_eq!(state.apply(&stale), ApplyOutcome::IgnoredStale);
        assert_eq!(state.get(b"key"), Some(&b"v1"[..]));
    }

    #[test]
    fn delete_removes_newer_versions() {
        let mut state = KvState::new();
        let set = Command::Set {
            key: b"key".to_vec(),
            value: b"v1".to_vec(),
            version: 5,
            timestamp: 5,
        };
        let delete = Command::Delete {
            key: b"key".to_vec(),
            version: 6,
            timestamp: 6,
        };
        assert_eq!(state.apply(&set), ApplyOutcome::Applied);
        assert_eq!(state.apply(&delete), ApplyOutcome::Removed);
        assert!(state.get(b"key").is_none());
    }

    #[test]
    fn concurrent_state_handles_set_and_get() {
        let state = ConcurrentKvState::new();
        let command = Command::Set {
            key: b"k".to_vec(),
            value: b"v".to_vec(),
            version: 1,
            timestamp: 1,
        };
        {
            let mut guard = state.lock_entry(command.key());
            assert_eq!(guard.evaluate(&command), ApplyOutcome::Applied);
            assert_eq!(guard.apply(&command), ApplyOutcome::Applied);
        }
        assert_eq!(state.get(b"k"), Some(b"v".to_vec()));
    }

    #[test]
    fn concurrent_state_respects_versions() {
        let state = ConcurrentKvState::new();
        let first = Command::Set {
            key: b"k".to_vec(),
            value: b"one".to_vec(),
            version: 2,
            timestamp: 1,
        };
        let stale = Command::Set {
            key: b"k".to_vec(),
            value: b"zero".to_vec(),
            version: 1,
            timestamp: 0,
        };
        {
            let mut guard = state.lock_entry(first.key());
            assert_eq!(guard.apply(&first), ApplyOutcome::Applied);
        }
        {
            let mut guard = state.lock_entry(stale.key());
            assert_eq!(guard.apply(&stale), ApplyOutcome::IgnoredStale);
        }
        assert_eq!(state.get(b"k"), Some(b"one".to_vec()));
    }

    #[test]
    fn snapshot_round_trip_between_states() {
        let mut snapshot = KvState::new();
        snapshot.insert_snapshot(b"a".to_vec(), b"1".to_vec(), 1);
        snapshot.insert_snapshot(b"b".to_vec(), b"2".to_vec(), 2);

        let concurrent: ConcurrentKvState = snapshot.into();
        let reflect = concurrent.to_snapshot();
        assert_eq!(reflect.len(), 2);
        assert_eq!(reflect.get(b"a"), Some(&b"1"[..]));
        assert_eq!(reflect.get(b"b"), Some(&b"2"[..]));
    }
}

#[cfg(test)]
impl KvState {
    pub(crate) fn clear_for_test(&mut self) {
        self.entries.clear();
    }
}
