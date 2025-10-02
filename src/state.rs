use hashbrown::HashMap;

use crate::command::Command;

#[derive(Debug, Default)]
pub struct KvState {
    entries: HashMap<Vec<u8>, (Vec<u8>, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied,
    IgnoredStale,
    Removed,
}

impl KvState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.entries
            .get(key)
            .map(|(value, _version)| value.as_slice())
    }

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

    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &(Vec<u8>, u64))> {
        self.entries.iter()
    }

    pub fn insert_snapshot(&mut self, key: Vec<u8>, value: Vec<u8>, version: u64) {
        self.entries.insert(key, (value, version));
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
    fn evaluate_matches_apply_outcome() {
        let mut state = KvState::new();
        let insert = Command::Set {
            key: b"k".to_vec(),
            value: b"v".to_vec(),
            version: 1,
            timestamp: 1,
        };
        assert_eq!(state.evaluate(&insert), ApplyOutcome::Applied);
        assert_eq!(state.apply(&insert), ApplyOutcome::Applied);
        let stale = Command::Set {
            key: b"k".to_vec(),
            value: b"new".to_vec(),
            version: 1,
            timestamp: 2,
        };
        assert_eq!(state.evaluate(&stale), ApplyOutcome::IgnoredStale);
        let delete = Command::Delete {
            key: b"k".to_vec(),
            version: 2,
            timestamp: 3,
        };
        assert_eq!(state.evaluate(&delete), ApplyOutcome::Removed);
        assert_eq!(state.apply(&delete), ApplyOutcome::Removed);
    }
}

#[cfg(test)]
impl KvState {
    pub(crate) fn clear_for_test(&mut self) {
        self.entries.clear();
    }
}
