use hashbrown::HashMap;
use std::sync::Arc;

/// Entry in the index pointing to a command in a log segment
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    /// ID of the segment containing this entry
    pub segment_id: u64,
    /// Byte offset within the segment
    pub offset: u64,
    /// Length of the serialized command
    pub length: u32,
    /// Version number of the command
    pub version: u64,
    /// Whether this entry represents a tombstone (delete)
    pub is_tombstone: bool,
}

/// Copy-on-write index mapping keys to their latest log positions
#[derive(Clone, Default, Debug)]
pub struct Index {
    inner: Arc<HashMap<Vec<u8>, IndexEntry>>,
}

impl Index {
    /// Creates a new empty index
    pub fn new() -> Self {
        Self {
            inner: Arc::new(HashMap::new()),
        }
    }

    /// Returns the number of entries in the index
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the index contains no entries
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns an iterator over all key-entry pairs in the index
    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &IndexEntry)> {
        self.inner.iter()
    }

    /// Gets the index entry for the given key
    pub fn get(&self, key: &[u8]) -> Option<&IndexEntry> {
        self.inner.get(key)
    }

    /// Inserts or updates an entry in the index, returning the previous entry if any
    pub fn upsert(&mut self, key: Vec<u8>, entry: IndexEntry) -> Option<IndexEntry> {
        Arc::make_mut(&mut self.inner).insert(key, entry)
    }

    /// Removes an entry from the index and returns it
    pub fn remove(&mut self, key: &[u8]) -> Option<IndexEntry> {
        Arc::make_mut(&mut self.inner).remove(key)
    }

    /// Creates a read-only snapshot of the index
    pub fn snapshot(&self) -> IndexSnapshot {
        IndexSnapshot {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Rebuilds an index from a builder
    pub fn rebuild(builder: IndexBuilder) -> Self {
        Self {
            inner: Arc::new(builder.entries),
        }
    }
}

/// Immutable snapshot of an index for consistent reads
pub struct IndexSnapshot {
    inner: Arc<HashMap<Vec<u8>, IndexEntry>>,
}

impl IndexSnapshot {
    /// Gets the index entry for the given key
    pub fn get(&self, key: &[u8]) -> Option<&IndexEntry> {
        self.inner.get(key)
    }

    /// Returns an iterator over all key-entry pairs in the snapshot
    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &IndexEntry)> {
        self.inner.iter()
    }

    /// Returns the number of entries in the snapshot
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

/// Builder for constructing a new index
#[derive(Default)]
pub struct IndexBuilder {
    entries: HashMap<Vec<u8>, IndexEntry>,
}

impl IndexBuilder {
    /// Creates a new empty index builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts an entry into the builder
    pub fn insert(&mut self, key: Vec<u8>, entry: IndexEntry) {
        self.entries.insert(key, entry);
    }

    /// Builds the final index from the accumulated entries
    pub fn build(self) -> Index {
        Index {
            inner: Arc::new(self.entries),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(segment_id: u64, version: u64) -> IndexEntry {
        IndexEntry {
            segment_id,
            offset: 0,
            length: 1,
            version,
            is_tombstone: false,
        }
    }

    #[test]
    fn upsert_tracks_latest_entry() {
        let mut index = Index::new();
        let first = sample_entry(1, 1);
        let second = sample_entry(2, 2);
        assert!(index.upsert(b"key".to_vec(), first.clone()).is_none());
        let prev = index.upsert(b"key".to_vec(), second.clone()).unwrap();
        assert_eq!(prev, first);
        let current = index.get(b"key").unwrap();
        assert_eq!(current, &second);
    }

    #[test]
    fn len_reports_entry_count() {
        let mut index = Index::new();
        index.upsert(b"a".to_vec(), sample_entry(1, 1));
        index.upsert(
            b"b".to_vec(),
            IndexEntry {
                is_tombstone: true,
                ..sample_entry(1, 2)
            },
        );
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn snapshot_is_unchanged_after_mutation() {
        let mut index = Index::new();
        index.upsert(b"key".to_vec(), sample_entry(1, 1));
        let snapshot = index.snapshot();
        assert_eq!(snapshot.get(b"key").unwrap().segment_id, 1);

        index.upsert(b"key".to_vec(), sample_entry(2, 2));
        assert_eq!(snapshot.get(b"key").unwrap().segment_id, 1);
        assert_eq!(index.get(b"key").unwrap().segment_id, 2);
    }

    #[test]
    fn builder_constructs_index() {
        let mut builder = IndexBuilder::new();
        builder.insert(b"key".to_vec(), sample_entry(3, 3));
        let index = builder.build();
        assert_eq!(index.get(b"key").unwrap().segment_id, 3);
    }
}
