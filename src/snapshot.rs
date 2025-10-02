use std::fs::{File, create_dir_all};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::state::KvState;

const SNAPSHOT_TMP_SUFFIX: &str = "tmp";

#[derive(Debug)]
pub struct Snapshot {
    path: PathBuf,
}

impl Snapshot {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn write(&self, state: &KvState, last_version: u64) -> Result<()> {
        let parent = self
            .path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        create_dir_all(&parent)?;

        let tmp_path = self.path.with_extension(SNAPSHOT_TMP_SUFFIX);

        let data = SnapshotData::from_state(state, last_version);
        let bytes =
            serde_cbor::to_vec(&data).map_err(|err| Error::Serialization(err.to_string()))?;

        {
            let mut file = File::create(&tmp_path)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }

        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    pub fn load(&self) -> Result<Option<(KvState, u64)>> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(Error::Io(err)),
        };

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let data: SnapshotData =
            serde_cbor::from_slice(&bytes).map_err(|err| Error::Serialization(err.to_string()))?;
        Ok(Some(data.into_state()))
    }
}

#[derive(Serialize, Deserialize)]
struct SnapshotEntry {
    key: Vec<u8>,
    value: Vec<u8>,
    version: u64,
}

#[derive(Serialize, Deserialize)]
struct SnapshotData {
    last_version: u64,
    entries: Vec<SnapshotEntry>,
}

impl SnapshotData {
    fn from_state(state: &KvState, last_version: u64) -> Self {
        let entries = state
            .iter()
            .map(|(key, (value, version))| SnapshotEntry {
                key: key.clone(),
                value: value.clone(),
                version: *version,
            })
            .collect();
        Self {
            last_version,
            entries,
        }
    }

    fn into_state(self) -> (KvState, u64) {
        let mut state = KvState::new();
        for entry in self.entries {
            state.insert_snapshot(entry.key, entry.value, entry.version);
        }
        (state, self.last_version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn write_and_load_snapshot_round_trip() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("snapshot.bin");
        let snapshot = Snapshot::new(&path);

        let mut state = KvState::new();
        state.insert_snapshot(b"k".to_vec(), b"v".to_vec(), 5);
        snapshot.write(&state, 5).unwrap();

        let (restored, last_version) = snapshot.load().unwrap().unwrap();
        assert_eq!(last_version, 5);
        assert_eq!(restored.get(b"k"), Some(&b"v"[..]));
    }

    #[test]
    fn load_missing_snapshot_returns_none() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("snapshot.bin");
        let snapshot = Snapshot::new(&path);
        assert!(snapshot.load().unwrap().is_none());
    }
}
