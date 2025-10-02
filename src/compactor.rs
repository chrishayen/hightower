use std::sync::Arc;
use std::time::Duration;

use crate::error::Result;
use crate::storage::{CompactionOptions, Storage};

/// Coordinates background segment merges to keep disk usage and read
/// amplification under control.
///
/// The intended lifecycle for a single compaction run is:
/// 1. Inspect storage metadata and pick cold segments whose combined size
///    exceeds `min_bytes` or whose live-data ratio falls below a future
///    heuristic. We cap the batch using `max_segments` to avoid long stalls.
/// 2. Stream the chosen segments in log order, retaining the newest value per
///    key while skipping tombstones older than `tombstone_grace`.
/// 3. Write the surviving entries into a fresh segment, fsync it, rebuild its
///    sparse index/Bloom filter, and atomically swap it into Storage while
///    removing the old segment files.
/// 4. Optionally trigger snapshotting so restart time stays stable even as log
///    history churns.
#[derive(Debug, Clone)]
pub struct CompactionConfig {
    pub min_bytes: u64,
    pub max_segments: usize,
    pub tombstone_grace: Duration,
    pub emit_snapshot: bool,
}

impl Default for CompactionConfig {
    fn default() -> Self {
        Self {
            min_bytes: 32 * 1024 * 1024,
            max_segments: 4,
            tombstone_grace: Duration::from_secs(300),
            emit_snapshot: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Compactor {
    storage: Arc<Storage>,
    config: CompactionConfig,
}

impl Compactor {
    pub fn new(storage: Arc<Storage>, config: CompactionConfig) -> Self {
        Self { storage, config }
    }

    pub fn run_once(&self) -> Result<()> {
        let sealed = self.storage.sealed_segments_snapshot();
        if sealed.is_empty() {
            return Ok(());
        }

        let total_bytes: u64 = sealed.iter().map(|segment| segment.bytes_written()).sum();
        if total_bytes < self.config.min_bytes {
            return Ok(());
        }

        let options = CompactionOptions {
            tombstone_grace: self.config.tombstone_grace,
            min_bytes: self.config.min_bytes,
            max_segments: self.config.max_segments,
            emit_snapshot: self.config.emit_snapshot,
        };
        if !self.storage.compact_all(options)? {
            return Ok(());
        }

        self.storage.sync()?;
        Ok(())
    }

    pub fn storage(&self) -> Arc<Storage> {
        Arc::clone(&self.storage)
    }

    pub fn config(&self) -> &CompactionConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::Command;
    use crate::config::StoreConfig;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn run_once_is_noop_when_under_threshold() {
        let temp = tempdir().unwrap();
        let mut cfg = StoreConfig::default();
        cfg.data_dir = temp.path().join("compactor").to_string_lossy().into_owned();
        cfg.max_segment_size = 1_000_000;
        let storage = Arc::new(Storage::new(&cfg).unwrap());
        let compactor = Compactor::new(storage.clone(), CompactionConfig::default());
        compactor.run_once().unwrap();
        assert_eq!(storage.segment_snapshot().len(), 1);
    }

    #[test]
    fn compacts_multiple_segments_into_one() {
        let temp = tempdir().unwrap();
        let mut cfg = StoreConfig::default();
        cfg.data_dir = temp.path().join("compactor").to_string_lossy().into_owned();
        cfg.max_segment_size = 64;
        let storage = Arc::new(Storage::new(&cfg).unwrap());
        for i in 0..5 {
            let command = Command::Set {
                key: format!("key{i}").into_bytes(),
                value: vec![b'x'; 32],
                version: i + 1,
                timestamp: i as i64,
            };
            storage.apply(&command).unwrap();
        }
        storage
            .apply(&Command::Delete {
                key: b"key1".to_vec(),
                version: 99,
                timestamp: 0,
            })
            .unwrap();
        assert!(storage.segment_snapshot().len() > 1);

        let sealed_before = storage.sealed_segments_snapshot();
        assert!(sealed_before.len() >= 2);
        let bytes_target: u64 = sealed_before
            .iter()
            .take(2)
            .map(|segment| segment.bytes_written())
            .sum();
        let segments_to_merge = sealed_before.len().min(2);

        let mut config = CompactionConfig::default();
        config.min_bytes = bytes_target;
        config.max_segments = 2;
        let compactor = Compactor::new(storage.clone(), config);
        compactor.run_once().unwrap();

        let sealed_after = storage.sealed_segments_snapshot();
        assert_eq!(
            sealed_after.len(),
            sealed_before.len() - segments_to_merge + 1
        );
        let entry = storage.lookup(b"key1").unwrap();
        assert!(entry.is_tombstone);
        let command = storage.fetch_command(&entry).unwrap().unwrap();
        assert!(matches!(command, Command::Delete { .. }));
    }

    #[test]
    fn tombstone_grace_evicts_old_deletes() {
        let temp = tempdir().unwrap();
        let mut cfg = StoreConfig::default();
        cfg.data_dir = temp.path().join("compactor").to_string_lossy().into_owned();
        cfg.max_segment_size = 64;
        let storage = Arc::new(Storage::new(&cfg).unwrap());

        storage
            .apply(&Command::Set {
                key: b"victim".to_vec(),
                value: b"value".to_vec(),
                version: 1,
                timestamp: 1,
            })
            .unwrap();
        storage
            .apply(&Command::Delete {
                key: b"victim".to_vec(),
                version: 2,
                timestamp: 0,
            })
            .unwrap();

        for i in 0..5 {
            storage
                .apply(&Command::Set {
                    key: format!("filler{i}").into_bytes(),
                    value: vec![b'x'; 32],
                    version: 10 + i,
                    timestamp: 10 + i as i64,
                })
                .unwrap();
        }

        let victim_segment = storage.lookup(b"victim").unwrap().segment_id;
        let sealed_before = storage.sealed_segments_snapshot();
        let mut target_bytes = 0u64;
        let mut segments_needed = 0usize;
        for segment in &sealed_before {
            segments_needed += 1;
            target_bytes += segment.bytes_written();
            if segment.id() == victim_segment {
                break;
            }
        }

        let mut config = CompactionConfig::default();
        config.min_bytes = target_bytes;
        config.max_segments = segments_needed;
        config.tombstone_grace = Duration::from_secs(1);
        let compactor = Compactor::new(storage.clone(), config);
        compactor.run_once().unwrap();

        assert!(storage.lookup(b"victim").is_none());
    }

    #[test]
    fn respects_max_segment_limit() {
        let temp = tempdir().unwrap();
        let mut cfg = StoreConfig::default();
        cfg.data_dir = temp.path().join("compactor").to_string_lossy().into_owned();
        cfg.max_segment_size = 64;
        let storage = Arc::new(Storage::new(&cfg).unwrap());

        for i in 0..8 {
            storage
                .apply(&Command::Set {
                    key: format!("hot{i}").into_bytes(),
                    value: vec![b'x'; 32],
                    version: i + 1,
                    timestamp: i as i64,
                })
                .unwrap();
        }

        let sealed_before = storage.sealed_segments_snapshot();
        assert!(sealed_before.len() >= 2);

        let mut config = CompactionConfig::default();
        config.min_bytes = 0;
        config.max_segments = 1;
        let compactor = Compactor::new(storage.clone(), config);
        compactor.run_once().unwrap();

        let sealed_after = storage.sealed_segments_snapshot();
        let before_ids: Vec<u64> = sealed_before.iter().map(|segment| segment.id()).collect();
        let after_ids: Vec<u64> = sealed_after.iter().map(|segment| segment.id()).collect();

        let new_ids: Vec<u64> = after_ids
            .iter()
            .copied()
            .filter(|id| !before_ids.contains(id))
            .collect();
        assert_eq!(new_ids.len(), 1);
        assert!(!after_ids.contains(&before_ids[0]));
        for id in before_ids.iter().skip(1) {
            assert!(after_ids.contains(id));
        }
    }

    #[test]
    fn emit_snapshot_is_best_effort() {
        let temp = tempdir().unwrap();
        let mut cfg = StoreConfig::default();
        cfg.data_dir = temp.path().join("compactor").to_string_lossy().into_owned();
        cfg.max_segment_size = 64;
        let storage = Arc::new(Storage::new(&cfg).unwrap());

        for i in 0..8 {
            storage
                .apply(&Command::Set {
                    key: format!("snap{i}").into_bytes(),
                    value: vec![b'x'; 32],
                    version: i + 1,
                    timestamp: i as i64,
                })
                .unwrap();
        }

        let mut config = CompactionConfig::default();
        config.min_bytes = 0;
        config.emit_snapshot = true;
        let snapshot_path = PathBuf::from(cfg.data_dir.clone()).join("snapshot.bin");
        let compactor = Compactor::new(storage, config);
        compactor.run_once().unwrap();

        assert!(snapshot_path.exists());
    }

    #[test]
    fn config_defaults_are_reasonable() {
        let cfg = CompactionConfig::default();
        assert!(cfg.min_bytes >= 4 * 1024 * 1024);
        assert!(cfg.max_segments >= 1);
        assert!(cfg.tombstone_grace >= Duration::from_secs(60));
    }
}
