use hashbrown::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub segment_id: u64,
    pub offset: u64,
    pub length: u32,
    pub version: u64,
    pub is_tombstone: bool,
}

#[derive(Clone, Default, Debug)]
pub struct Index {
    inner: Arc<HashMap<Vec<u8>, IndexEntry>>,
}

impl Index {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(HashMap::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &IndexEntry)> {
        self.inner.iter()
    }

    pub fn get(&self, key: &[u8]) -> Option<&IndexEntry> {
        self.inner.get(key)
    }

    pub fn upsert(&mut self, key: Vec<u8>, entry: IndexEntry) -> Option<IndexEntry> {
        Arc::make_mut(&mut self.inner).insert(key, entry)
    }

    pub fn remove(&mut self, key: &[u8]) -> Option<IndexEntry> {
        Arc::make_mut(&mut self.inner).remove(key)
    }

    pub fn snapshot(&self) -> IndexSnapshot {
        IndexSnapshot {
            inner: Arc::clone(&self.inner),
        }
    }

    pub fn rebuild(builder: IndexBuilder) -> Self {
        Self {
            inner: Arc::new(builder.entries),
        }
    }
}

pub struct IndexSnapshot {
    inner: Arc<HashMap<Vec<u8>, IndexEntry>>,
}

impl IndexSnapshot {
    pub fn get(&self, key: &[u8]) -> Option<&IndexEntry> {
        self.inner.get(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &IndexEntry)> {
        self.inner.iter()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

#[derive(Default)]
pub struct IndexBuilder {
    entries: HashMap<Vec<u8>, IndexEntry>,
}

impl IndexBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: Vec<u8>, entry: IndexEntry) {
        self.entries.insert(key, entry);
    }

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
