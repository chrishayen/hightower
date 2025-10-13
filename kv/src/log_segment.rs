use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use bloomfilter::Bloom;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::command::Command;
use crate::error::{Error, Result};

/// Position of a command entry within a log segment
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogPosition {
    /// Byte offset from the start of the segment file
    pub offset: u64,
    /// Length of the serialized command in bytes
    pub length: u32,
}

/// Entry in the sparse index that aids in binary search during lookups
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparseIndexEntry {
    /// Key for this index entry
    pub key: Vec<u8>,
    /// Byte offset where this entry starts in the segment
    pub offset: u64,
    /// Version number of the command
    pub version: u64,
}

/// Configuration for creating or opening a log segment
#[derive(Clone, Debug)]
pub struct SegmentConfig {
    /// Unique identifier for this segment
    pub id: u64,
    /// File system path where the segment is stored
    pub path: PathBuf,
    /// How often to record a sparse index entry (every N entries)
    pub sparse_every: usize,
    /// Expected number of items for bloom filter sizing
    pub bloom_expected_items: usize,
    /// False positive rate for bloom filter
    pub bloom_fp_rate: f64,
}

impl SegmentConfig {
    /// Creates a new segment configuration with default settings
    pub fn new(id: u64, path: impl Into<PathBuf>) -> Self {
        Self {
            id,
            path: path.into(),
            sparse_every: 32,
            bloom_expected_items: 1024,
            bloom_fp_rate: 0.01,
        }
    }

    fn normalized_sparse_every(&self) -> usize {
        self.sparse_every.max(1)
    }

    fn normalized_bloom_items(&self) -> usize {
        self.bloom_expected_items.max(1)
    }

    fn normalized_fp_rate(&self) -> f64 {
        let rate = self.bloom_fp_rate;
        if !(0.0..1.0).contains(&rate) {
            0.01
        } else {
            rate
        }
    }
}

#[derive(Debug)]
struct SegmentMetadata {
    bloom: Bloom<Vec<u8>>,
    sparse_index: Vec<SparseIndexEntry>,
    entries_written: u64,
    bytes_written: u64,
}

impl SegmentMetadata {
    fn new(config: &SegmentConfig) -> Self {
        Self {
            bloom: Bloom::new_for_fp_rate(
                config.normalized_bloom_items() as usize,
                config.normalized_fp_rate(),
            ),
            sparse_index: Vec::new(),
            entries_written: 0,
            bytes_written: 0,
        }
    }

    fn record(&mut self, offset: u64, encoded_len: u32, command: &Command, sparse_every: usize) {
        self.entries_written += 1;
        self.bytes_written = offset + 4 + encoded_len as u64;
        let key_vec = command.key().to_vec();
        self.bloom.set(&key_vec);
        if (self.entries_written - 1) % sparse_every as u64 == 0 {
            self.sparse_index.push(SparseIndexEntry {
                key: key_vec,
                offset,
                version: command.version(),
            });
        }
    }
}

/// Append-only log segment that stores serialized commands with bloom filter and sparse index
#[derive(Debug)]
pub struct LogSegment {
    id: u64,
    path: PathBuf,
    file: Mutex<File>,
    metadata: Mutex<SegmentMetadata>,
    sparse_every: usize,
}

impl LogSegment {
    /// Opens or creates a log segment from the given configuration
    pub fn open(config: SegmentConfig) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        let path = config.path.clone();
        let mut file = options.open(&path)?;
        let mut metadata = SegmentMetadata::new(&config);
        rebuild_metadata(&mut file, &mut metadata, config.normalized_sparse_every())?;
        Ok(Self {
            id: config.id,
            path,
            file: Mutex::new(file),
            metadata: Mutex::new(metadata),
            sparse_every: config.normalized_sparse_every(),
        })
    }

    /// Returns the unique identifier for this segment
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Returns the file system path of this segment
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the total number of bytes written to this segment
    pub fn bytes_written(&self) -> u64 {
        self.metadata.lock().bytes_written
    }

    /// Returns the number of entries written to this segment
    pub fn entries(&self) -> u64 {
        self.metadata.lock().entries_written
    }

    /// Returns a clone of the sparse index for this segment
    pub fn sparse_index(&self) -> Vec<SparseIndexEntry> {
        self.metadata.lock().sparse_index.clone()
    }

    /// Checks the bloom filter to see if this segment might contain the given key
    pub fn might_contain(&self, key: &[u8]) -> bool {
        self.metadata.lock().bloom.check(&key.to_vec())
    }

    /// Locates the latest command for the given key, returning its position and value
    pub fn locate(&self, key: &[u8]) -> Result<Option<(LogPosition, Command)>> {
        if !self.might_contain(key) {
            return Ok(None);
        }

        let start_offset = {
            let metadata = self.metadata.lock();
            let sparse = &metadata.sparse_index;
            if sparse.is_empty() {
                0u64
            } else {
                let idx = sparse.binary_search_by(|entry| entry.key.as_slice().cmp(key));
                match idx {
                    Ok(i) => sparse[i].offset,
                    Err(0) => 0,
                    Err(i) => sparse[i - 1].offset,
                }
            }
        };

        let mut file = self.file.lock();
        file.seek(SeekFrom::Start(start_offset))?;

        let mut offset = start_offset;
        let mut latest: Option<(LogPosition, Command)> = None;

        loop {
            let mut len_buf = [0u8; 4];
            match file.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(Error::Io(err)),
            }
            let len = u32::from_le_bytes(len_buf);
            let mut buf = vec![0u8; len as usize];
            file.read_exact(&mut buf)?;
            let command: Command = serde_cbor::from_slice(&buf)
                .map_err(|err| Error::Serialization(err.to_string()))?;
            if command.key() == key {
                latest = Some((
                    LogPosition {
                        offset,
                        length: len,
                    },
                    command,
                ));
            }
            offset = offset
                .checked_add(4 + len as u64)
                .ok_or_else(|| Error::Serialization("log offset overflow during locate".into()))?;
        }

        Ok(latest)
    }

    /// Appends a command to the end of the segment and returns its position
    pub fn append(&self, command: &Command) -> Result<LogPosition> {
        let encoded =
            serde_cbor::to_vec(command).map_err(|err| Error::Serialization(err.to_string()))?;
        if encoded.len() > u32::MAX as usize {
            return Err(Error::Serialization("command too large".into()));
        }
        let len = encoded.len() as u32;
        let mut file = self.file.lock();
        let offset = file.seek(SeekFrom::End(0))?;
        file.write_all(&len.to_le_bytes())?;
        file.write_all(&encoded)?;
        file.flush()?;

        let mut metadata = self.metadata.lock();
        metadata.record(offset, len, command, self.sparse_every);
        Ok(LogPosition {
            offset,
            length: len,
        })
    }

    /// Reads a command from the segment at the specified offset
    pub fn read(&self, offset: u64) -> Result<Option<Command>> {
        let upper_bound = self.metadata.lock().bytes_written;
        if offset >= upper_bound {
            return Ok(None);
        }
        let mut file = self.file.lock();
        file.seek(SeekFrom::Start(offset))?;
        let mut len_buf = [0u8; 4];
        if let Err(err) = file.read_exact(&mut len_buf) {
            return if err.kind() == io::ErrorKind::UnexpectedEof {
                Ok(None)
            } else {
                Err(Error::Io(err))
            };
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        file.read_exact(&mut buf)?;
        let command =
            serde_cbor::from_slice(&buf).map_err(|err| Error::Serialization(err.to_string()))?;
        Ok(Some(command))
    }

    /// Scans all entries in the segment, calling the visitor function for each
    pub fn scan<F>(&self, mut visitor: F) -> Result<()>
    where
        F: FnMut(LogPosition, Command) -> Result<()>,
    {
        let mut file = File::open(&self.path)?;
        scan_file(&mut file, |offset, len, command| {
            visitor(
                LogPosition {
                    offset,
                    length: len,
                },
                command,
            )
        })
    }

    /// Syncs the segment file to disk
    pub fn sync(&self) -> Result<()> {
        let file = self.file.lock();
        file.sync_data().map_err(Error::from)
    }
}

fn rebuild_metadata(
    file: &mut File,
    metadata: &mut SegmentMetadata,
    sparse_every: usize,
) -> Result<()> {
    scan_file(file, |offset, len, command| {
        metadata.record(offset, len, &command, sparse_every);
        Ok(())
    })
}

fn scan_file<F>(file: &mut File, mut visitor: F) -> Result<()>
where
    F: FnMut(u64, u32, Command) -> Result<()>,
{
    file.seek(SeekFrom::Start(0))?;
    let mut offset = 0u64;
    loop {
        let mut len_buf = [0u8; 4];
        match file.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(Error::Io(err)),
        }
        let len = u32::from_le_bytes(len_buf);
        let mut buf = vec![0u8; len as usize];
        file.read_exact(&mut buf)?;
        let command: Command =
            serde_cbor::from_slice(&buf).map_err(|err| Error::Serialization(err.to_string()))?;
        visitor(offset, len, command)?;
        offset += 4 + len as u64;
    }
    file.seek(SeekFrom::Start(offset))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::Command;
    use tempfile::tempdir;

    #[test]
    fn append_and_read_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("segment.log");
        let segment = LogSegment::open(SegmentConfig::new(1, &path)).unwrap();

        let command = Command::Set {
            key: b"key".to_vec(),
            value: b"value".to_vec(),
            version: 42,
            timestamp: 1,
        };
        let position = segment.append(&command).unwrap();
        let read_back = segment.read(position.offset).unwrap().unwrap();
        assert_eq!(read_back, command);
        assert!(segment.might_contain(b"key"));
        assert_eq!(segment.entries(), 1);
    }

    #[test]
    fn rebuild_metadata_from_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("segment.log");
        let cfg = SegmentConfig {
            sparse_every: 1,
            ..SegmentConfig::new(5, &path)
        };
        let segment = LogSegment::open(cfg.clone()).unwrap();
        let command = Command::Delete {
            key: b"alpha".to_vec(),
            version: 7,
            timestamp: 2,
        };
        let position = segment.append(&command).unwrap();
        drop(segment);

        let reopened = LogSegment::open(cfg).unwrap();
        assert_eq!(reopened.entries(), 1);
        let index = reopened.sparse_index();
        assert_eq!(index.len(), 1);
        assert_eq!(index[0].offset, position.offset);
        assert_eq!(index[0].version, 7);
        assert!(reopened.read(position.offset).unwrap().is_some());
    }

    #[test]
    fn read_out_of_bounds_returns_none() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("segment.log");
        let segment = LogSegment::open(SegmentConfig::new(2, &path)).unwrap();
        assert!(segment.read(1024).unwrap().is_none());
    }

    #[test]
    fn locate_finds_latest_entry_for_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("segment.log");
        let mut cfg = SegmentConfig::new(7, &path);
        cfg.sparse_every = 2;
        let segment = LogSegment::open(cfg).unwrap();

        for version in 0..5u64 {
            let command = Command::Set {
                key: b"target".to_vec(),
                value: vec![version as u8],
                version,
                timestamp: version as i64,
            };
            segment.append(&command).unwrap();
        }

        let command = Command::Set {
            key: b"other".to_vec(),
            value: b"value".to_vec(),
            version: 9,
            timestamp: 9,
        };
        segment.append(&command).unwrap();

        let located = segment.locate(b"target").unwrap().unwrap();
        assert_eq!(located.1.version(), 4);
        assert_eq!(located.1.key(), b"target");

        assert!(segment.locate(b"missing").unwrap().is_none());
    }
}
