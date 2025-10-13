use std::collections::{HashMap, HashSet};
use std::fs::{create_dir_all, read_dir, remove_file};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};

use crate::command::Command;
use crate::config::StoreConfig;
use crate::error::{Error, Result};
use crate::index::{Index, IndexEntry};
use crate::log_segment::{LogSegment, SegmentConfig};
use crate::snapshot::Snapshot;
use crate::state::KvState;

const SEGMENT_PREFIX: &str = "segment-";
const SEGMENT_SUFFIX: &str = ".log";

/// Options for controlling log compaction behavior.
#[derive(Clone, Debug)]
pub struct CompactionOptions {
    /// Minimum age before tombstones are permanently removed
    pub tombstone_grace: Duration,
    /// Minimum bytes to accumulate before compaction runs
    pub min_bytes: u64,
    /// Maximum number of segments to compact in one pass
    pub max_segments: usize,
    /// Whether to emit a snapshot after compaction
    pub emit_snapshot: bool,
}

/// Log-structured storage engine with indexing and compaction.
#[derive(Debug)]
pub struct Storage {
    config: StoreConfig,
    index: RwLock<Index>,
    segments: RwLock<Vec<Arc<LogSegment>>>,
    active_segment: RwLock<Arc<LogSegment>>,
    next_segment_id: Mutex<u64>,
    snapshot_path: PathBuf,
}

impl Storage {
    /// Creates a new storage instance, loading existing segments from disk.
    pub fn new(config: &StoreConfig) -> Result<Self> {
        let data_dir = PathBuf::from(&config.data_dir);
        create_dir_all(&data_dir)?;

        let mut segments = load_segments(&data_dir, config)?;
        let next_segment_id = match segments.last() {
            Some(segment) => segment.id() + 1,
            None => {
                let segment = Arc::new(open_segment(&data_dir, 1, config)?);
                segments.push(segment.clone());
                2
            }
        };

        let active_segment = segments
            .last()
            .cloned()
            .ok_or_else(|| Error::Unimplemented("storage::active_segment_missing"))?;
        let index = rebuild_index(&segments)?;

        let snapshot_path = data_dir.join("snapshot.bin");

        Ok(Self {
            config: config.clone(),
            index: RwLock::new(index),
            segments: RwLock::new(segments),
            active_segment: RwLock::new(active_segment),
            next_segment_id: Mutex::new(next_segment_id),
            snapshot_path,
        })
    }

    /// Appends a command to the active segment and updates the index.
    pub fn apply(&self, command: &Command) -> Result<()> {
        let active = { self.active_segment.read().clone() };
        let position = active.append(command)?;
        let entry = IndexEntry {
            segment_id: active.id(),
            offset: position.offset,
            length: position.length,
            version: command.version(),
            is_tombstone: matches!(command, Command::Delete { .. }),
        };
        self.index.write().upsert(command.key().to_vec(), entry);
        if active.bytes_written() >= self.config.max_segment_size {
            self.roll_segment()?;
        }
        Ok(())
    }

    /// Looks up the index entry for a key, recovering from disk if needed.
    pub fn lookup(&self, key: &[u8]) -> Option<IndexEntry> {
        if let Some(entry) = self.index.read().get(key).cloned() {
            return Some(entry);
        }
        match self.recover_index_entry(key) {
            Ok(entry) => entry,
            Err(_) => None,
        }
    }

    /// Gets all key-entry pairs with the given prefix
    pub fn get_prefix(&self, prefix: &[u8]) -> Vec<(Vec<u8>, IndexEntry)> {
        self.index.read().get_prefix(prefix)
    }

    /// Reads the command corresponding to an index entry from its segment.
    pub fn fetch_command(&self, entry: &IndexEntry) -> Result<Option<Command>> {
        let segment = self.segment_for(entry.segment_id)?;
        segment.read(entry.offset)
    }

    /// Returns a snapshot of all segments.
    pub fn segment_snapshot(&self) -> Vec<Arc<LogSegment>> {
        self.segments.read().iter().cloned().collect()
    }

    /// Returns a snapshot of sealed (non-active) segments.
    pub(crate) fn sealed_segments_snapshot(&self) -> Vec<Arc<LogSegment>> {
        let guard = self.segments.read();
        if guard.len() <= 1 {
            return Vec::new();
        }
        guard[..guard.len() - 1].to_vec()
    }

    /// Compacts sealed segments according to the provided options.
    pub fn compact_all(&self, options: CompactionOptions) -> Result<bool> {
        match SuspendedCompaction::prepare(self, options.clone())? {
            Some(compaction) => compaction.execute(options.emit_snapshot),
            None => Ok(false),
        }
    }

    /// Syncs the active segment to disk.
    pub fn sync(&self) -> Result<()> {
        let active = { self.active_segment.read().clone() };
        active.sync()
    }

    /// Rebuilds the current key-value state from the index.
    pub fn state_snapshot(&self) -> KvState {
        let index = self.index.read();
        let mut state = KvState::new();
        for (key, entry) in index.iter() {
            if entry.is_tombstone {
                state.apply(&Command::Delete {
                    key: key.clone(),
                    version: entry.version,
                    timestamp: 0,
                });
                continue;
            }
            if let Ok(Some(command)) = self.fetch_command(entry) {
                state.apply(&command);
            }
        }
        state
    }

    /// Returns the highest version number in the index.
    pub fn latest_version(&self) -> u64 {
        self.index
            .read()
            .iter()
            .map(|(_, entry)| entry.version)
            .max()
            .unwrap_or(0)
    }

    /// Loads a snapshot from disk if one exists.
    pub fn load_snapshot(&self) -> Result<Option<(KvState, u64)>> {
        let snapshot = Snapshot::new(&self.snapshot_path);
        snapshot.load()
    }

    /// Replays all commands from all segments in order.
    pub fn replay<F>(&self, mut visitor: F) -> Result<()>
    where
        F: FnMut(Command) -> Result<()>,
    {
        let segments = self.segments.read();
        let mut ordered = segments.clone();
        ordered.sort_by_key(|segment| segment.id());
        for segment in ordered {
            segment.scan(|_, command| visitor(command))?;
        }
        Ok(())
    }

    fn segment_for(&self, id: u64) -> Result<Arc<LogSegment>> {
        let segments = self.segments.read();
        segments
            .iter()
            .find(|segment| segment.id() == id)
            .cloned()
            .ok_or_else(|| Error::Unimplemented("storage::segment_not_found"))
    }

    fn roll_segment(&self) -> Result<()> {
        let mut id_guard = self.next_segment_id.lock();
        let id = *id_guard;
        let dir = PathBuf::from(&self.config.data_dir);
        let segment = Arc::new(open_segment(&dir, id, &self.config)?);
        *id_guard = id
            .checked_add(1)
            .ok_or(Error::Unimplemented("storage::segment_id_overflow"))?;

        let mut segments = self.segments.write();
        segments.push(segment.clone());
        *self.active_segment.write() = segment;
        Ok(())
    }
}

impl Storage {
    fn recover_index_entry(&self, key: &[u8]) -> Result<Option<IndexEntry>> {
        let segments = self.segments.read().clone();
        for segment in segments.iter().rev() {
            if !segment.might_contain(key) {
                continue;
            }
            if let Some((position, command)) = segment.locate(key)? {
                let entry = IndexEntry {
                    segment_id: segment.id(),
                    offset: position.offset,
                    length: position.length,
                    version: command.version(),
                    is_tombstone: matches!(command, Command::Delete { .. }),
                };
                self.index
                    .write()
                    .upsert(command.key().to_vec(), entry.clone());
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }
}

/// Loads all log segments from the data directory.
fn load_segments(dir: &Path, config: &StoreConfig) -> Result<Vec<Arc<LogSegment>>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries: Vec<(u64, PathBuf)> = Vec::new();
    for entry in read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(name) => name,
            None => continue,
        };
        if let Some(id) = parse_segment_id(name) {
            entries.push((id, entry.path()));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut segments = Vec::new();
    for (id, path) in entries {
        let segment = Arc::new(open_segment_at_path(id, path, config)?);
        segments.push(segment);
    }
    Ok(segments)
}

/// Opens a segment with the given ID in the specified directory.
fn open_segment(dir: &Path, id: u64, config: &StoreConfig) -> Result<LogSegment> {
    let path = segment_path(dir, id);
    open_segment_at_path(id, path, config)
}

/// Opens a segment at the specified path with the given ID.
fn open_segment_at_path(id: u64, path: PathBuf, config: &StoreConfig) -> Result<LogSegment> {
    let mut segment_config = SegmentConfig::new(id, path);
    segment_config.sparse_every = 32;
    segment_config.bloom_expected_items = normalized_item_estimate(config.max_segment_size);
    segment_config.bloom_fp_rate = 0.01;
    LogSegment::open(segment_config)
}

/// Constructs the file path for a segment with the given ID.
fn segment_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("{SEGMENT_PREFIX}{id:020}{SEGMENT_SUFFIX}"))
}

/// Extracts the segment ID from a filename if it matches the expected pattern.
fn parse_segment_id(name: &str) -> Option<u64> {
    if !name.starts_with(SEGMENT_PREFIX) || !name.ends_with(SEGMENT_SUFFIX) {
        return None;
    }
    let start = SEGMENT_PREFIX.len();
    let end = name.len() - SEGMENT_SUFFIX.len();
    name[start..end].parse::<u64>().ok()
}

/// Rebuilds the index by scanning all segments.
fn rebuild_index(segments: &[Arc<LogSegment>]) -> Result<Index> {
    let mut builder = crate::index::IndexBuilder::new();
    let mut ordered_segments = segments.to_vec();
    ordered_segments.sort_by_key(|segment| segment.id());

    for segment in ordered_segments {
        let segment_id = segment.id();
        segment.scan(|position, command| {
            let key = command.key().to_vec();
            let entry = IndexEntry {
                segment_id,
                offset: position.offset,
                length: position.length,
                version: command.version(),
                is_tombstone: matches!(command, Command::Delete { .. }),
            };
            builder.insert(key, entry);
            Ok(())
        })?;
    }

    Ok(Index::rebuild(builder))
}

/// Estimates the number of items in a segment based on its max size.
fn normalized_item_estimate(max_segment_size: u64) -> usize {
    let bytes_per_entry = 256u64;
    let estimate = (max_segment_size / bytes_per_entry).max(1);
    estimate.min(usize::MAX as u64) as usize
}

/// A prepared compaction operation ready to execute.
struct SuspendedCompaction<'a> {
    storage: &'a Storage,
    options: CompactionOptions,
    sealed: Vec<Arc<LogSegment>>,
    sealed_ids: HashSet<u64>,
}

impl<'a> SuspendedCompaction<'a> {
    fn prepare(storage: &'a Storage, options: CompactionOptions) -> Result<Option<Self>> {
        let all_sealed = storage.sealed_segments_snapshot();
        if all_sealed.is_empty() {
            return Ok(None);
        }

        let max_segments = options.max_segments;
        let mut selected = Vec::new();
        let mut accumulated_bytes = 0u64;

        for segment in all_sealed.iter() {
            if max_segments != 0 && selected.len() >= max_segments {
                break;
            }
            accumulated_bytes += segment.bytes_written();
            selected.push(segment.clone());
            if options.min_bytes == 0 || accumulated_bytes >= options.min_bytes {
                break;
            }
        }

        if selected.is_empty() {
            return Ok(None);
        }

        if options.min_bytes > 0 && accumulated_bytes < options.min_bytes {
            return Ok(None);
        }

        let sealed_ids = selected.iter().map(|segment| segment.id()).collect();
        Ok(Some(Self {
            storage,
            options,
            sealed: selected,
            sealed_ids,
        }))
    }

    fn execute(self, emit_snapshot: bool) -> Result<bool> {
        let SuspendedCompaction {
            storage,
            options,
            sealed,
            sealed_ids,
        } = self;

        let snapshot = storage.index.read().snapshot();
        let mut latest_versions: HashMap<Vec<u8>, IndexEntry> = HashMap::new();
        for (key, entry) in snapshot.iter() {
            if sealed_ids.contains(&entry.segment_id) {
                latest_versions.insert(key.clone(), entry.clone());
            }
        }
        drop(snapshot);

        if latest_versions.is_empty() {
            return Ok(false);
        }

        let mut id_guard = storage.next_segment_id.lock();
        let new_id = *id_guard;
        *id_guard = new_id
            .checked_add(1)
            .ok_or(Error::Unimplemented("storage::segment_id_overflow"))?;
        drop(id_guard);

        let dir = PathBuf::from(&storage.config.data_dir);
        let new_segment = Arc::new(open_segment(&dir, new_id, &storage.config)?);
        let new_segment_path = new_segment.path().to_path_buf();
        let tombstone_grace = options.tombstone_grace;
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|dur| dur.as_secs())
            .unwrap_or(0);
        let grace_secs = tombstone_grace.as_secs();

        let mut new_entries: Vec<(Vec<u8>, IndexEntry)> = Vec::new();
        let mut evicted_keys: Vec<Vec<u8>> = Vec::new();
        let mut wrote_any = false;

        let old_paths: Vec<PathBuf> = sealed
            .iter()
            .map(|segment| segment.path().to_path_buf())
            .collect();

        for segment in &sealed {
            let segment_id = segment.id();
            segment.scan(|_, command| {
                let entry = match latest_versions.get(command.key()) {
                    Some(entry)
                        if entry.segment_id == segment_id && entry.version == command.version() =>
                    {
                        entry.clone()
                    }
                    _ => return Ok(()),
                };

                latest_versions.remove(command.key());

                if entry.is_tombstone && grace_secs > 0 {
                    let timestamp = command.timestamp().max(0) as u64;
                    if now_secs.saturating_sub(timestamp) >= grace_secs {
                        evicted_keys.push(command.key().to_vec());
                        return Ok(());
                    }
                }

                let position = new_segment.append(&command)?;
                new_entries.push((
                    command.key().to_vec(),
                    IndexEntry {
                        segment_id: new_id,
                        offset: position.offset,
                        length: position.length,
                        version: command.version(),
                        is_tombstone: entry.is_tombstone,
                    },
                ));
                wrote_any = true;
                Ok(())
            })?;
        }

        if !latest_versions.is_empty() {
            let _ = remove_file(&new_segment_path);
            return Ok(false);
        }

        if !wrote_any && evicted_keys.is_empty() {
            let _ = remove_file(&new_segment_path);
            return Ok(false);
        }

        new_segment.sync()?;

        {
            let mut segments_guard = storage.segments.write();
            let sealed_len = sealed.len();
            if segments_guard.len() < sealed_len + 1 {
                drop(segments_guard);
                let _ = remove_file(&new_segment_path);
                return Ok(false);
            }
            let matches_snapshot = segments_guard
                .iter()
                .take(sealed_len)
                .zip(sealed.iter())
                .all(|(current, snapshot)| current.id() == snapshot.id());
            if !matches_snapshot {
                drop(segments_guard);
                let _ = remove_file(&new_segment_path);
                return Ok(false);
            }
            segments_guard.drain(..sealed_len);
            let insert_pos = segments_guard.len().saturating_sub(1);
            segments_guard.insert(insert_pos, new_segment.clone());
        }

        {
            let mut index_guard = storage.index.write();
            for key in evicted_keys {
                index_guard.remove(key.as_slice());
            }
            for (key, entry) in new_entries {
                index_guard.upsert(key, entry.clone());
            }
        }

        for path in old_paths {
            let _ = remove_file(path);
        }

        if emit_snapshot {
            let state = storage.state_snapshot();
            let last_version = storage.latest_version();
            let snapshot = Snapshot::new(&storage.snapshot_path);
            if let Err(err) = snapshot.write(&state, last_version) {
                if !matches!(err, Error::Unimplemented(_)) {
                    return Err(err);
                }
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn temp_config(dir: &Path) -> StoreConfig {
        let mut cfg = StoreConfig::default();
        cfg.data_dir = dir.join("data").to_string_lossy().into_owned();
        cfg
    }

    #[test]
    fn apply_persists_and_indexes_command() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let storage = Storage::new(&cfg).unwrap();

        let command = Command::Set {
            key: b"alpha".to_vec(),
            value: b"value".to_vec(),
            version: 3,
            timestamp: 1,
        };
        storage.apply(&command).unwrap();

        let entry = storage.lookup(b"alpha").unwrap();
        assert!(!entry.is_tombstone);
        assert_eq!(entry.version, 3);
        let stored = storage.fetch_command(&entry).unwrap().unwrap();
        assert_eq!(stored, command);
    }

    #[test]
    fn reopen_rebuilds_index_and_tombstones() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let storage = Storage::new(&cfg).unwrap();

        storage
            .apply(&Command::Set {
                key: b"beta".to_vec(),
                value: b"v1".to_vec(),
                version: 10,
                timestamp: 1,
            })
            .unwrap();
        storage
            .apply(&Command::Delete {
                key: b"beta".to_vec(),
                version: 11,
                timestamp: 2,
            })
            .unwrap();
        drop(storage);

        let reopened = Storage::new(&cfg).unwrap();
        let entry = reopened.lookup(b"beta").unwrap();
        assert!(entry.is_tombstone);
        assert_eq!(entry.version, 11);
        let command = reopened.fetch_command(&entry).unwrap().unwrap();
        assert!(matches!(command, Command::Delete { .. }));
    }

    #[test]
    fn parse_segment_id_recognizes_pattern() {
        assert_eq!(
            parse_segment_id("segment-00000000000000012345.log"),
            Some(12345)
        );
        assert_eq!(parse_segment_id("bad-name"), None);
    }

    #[test]
    fn rolls_segment_when_capacity_exceeded() {
        let temp = tempdir().unwrap();
        let mut cfg = temp_config(temp.path());
        cfg.max_segment_size = 120;
        let storage = Storage::new(&cfg).unwrap();

        let initial_id = storage.active_segment.read().id();
        for i in 0..8 {
            storage
                .apply(&Command::Set {
                    key: format!("key{i}").into_bytes(),
                    value: vec![b'x'; 32],
                    version: i + 1,
                    timestamp: i as i64,
                })
                .unwrap();
        }
        let rolled_id = storage.active_segment.read().id();
        assert!(rolled_id > initial_id, "expected segment rollover");
    }

    #[test]
    fn replay_yields_commands_in_write_order() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let storage = Storage::new(&cfg).unwrap();

        let commands = vec![
            Command::Set {
                key: b"a".to_vec(),
                value: b"1".to_vec(),
                version: 1,
                timestamp: 1,
            },
            Command::Set {
                key: b"b".to_vec(),
                value: b"2".to_vec(),
                version: 2,
                timestamp: 2,
            },
            Command::Delete {
                key: b"a".to_vec(),
                version: 3,
                timestamp: 3,
            },
        ];

        for command in &commands {
            storage.apply(command).unwrap();
        }

        let mut replayed = Vec::new();
        storage
            .replay(|command| {
                replayed.push((command.key().to_vec(), command.version()));
                Ok(())
            })
            .unwrap();

        let expected: Vec<(Vec<u8>, u64)> = commands
            .iter()
            .map(|command| (command.key().to_vec(), command.version()))
            .collect();
        assert_eq!(replayed, expected);
    }

    #[test]
    fn state_snapshot_reflects_latest_index() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let storage = Storage::new(&cfg).unwrap();

        storage
            .apply(&Command::Set {
                key: b"a".to_vec(),
                value: b"1".to_vec(),
                version: 1,
                timestamp: 1,
            })
            .unwrap();
        storage
            .apply(&Command::Delete {
                key: b"a".to_vec(),
                version: 2,
                timestamp: 2,
            })
            .unwrap();
        storage
            .apply(&Command::Set {
                key: b"b".to_vec(),
                value: b"2".to_vec(),
                version: 3,
                timestamp: 3,
            })
            .unwrap();

        let snapshot = storage.state_snapshot();
        assert!(snapshot.get(b"a").is_none());
        assert_eq!(snapshot.get(b"b"), Some(&b"2"[..]));
    }

    #[test]
    fn lookup_recovers_entry_from_segments() {
        let temp = tempdir().unwrap();
        let cfg = temp_config(temp.path());
        let storage = Storage::new(&cfg).unwrap();

        let command = Command::Set {
            key: b"recover".to_vec(),
            value: b"value".to_vec(),
            version: 42,
            timestamp: 1,
        };
        storage.apply(&command).unwrap();

        // Remove from hot index to simulate eviction.
        storage.index.write().remove(b"recover");

        let entry = storage.lookup(b"recover").unwrap();
        assert_eq!(entry.version, 42);
        let fetched = storage.fetch_command(&entry).unwrap().unwrap();
        assert_eq!(fetched, command);
    }
}
