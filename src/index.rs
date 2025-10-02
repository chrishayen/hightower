use hashbrown::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub segment_id: u64,
    pub offset: u64,
    pub length: u32,
    pub version: u64,
    pub is_tombstone: bool,
}

#[derive(Debug, Default)]
pub struct Index {
    entries: HashMap<Vec<u8>, IndexEntry>,
}

impl Index {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, key: Vec<u8>, entry: IndexEntry) -> Option<IndexEntry> {
        self.entries.insert(key, entry)
    }

    pub fn get(&self, key: &[u8]) -> Option<&IndexEntry> {
        self.entries.get(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn remove(&mut self, key: &[u8]) -> Option<IndexEntry> {
        self.entries.remove(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &IndexEntry)> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_tracks_latest_entry() {
        let mut index = Index::new();
        let first = IndexEntry {
            segment_id: 1,
            offset: 10,
            length: 5,
            version: 1,
            is_tombstone: false,
        };
        let second = IndexEntry {
            segment_id: 2,
            offset: 20,
            length: 5,
            version: 2,
            is_tombstone: false,
        };
        assert!(index.upsert(b"key".to_vec(), first.clone()).is_none());
        let prev = index.upsert(b"key".to_vec(), second.clone()).unwrap();
        assert_eq!(prev, first);
        let current = index.get(b"key").unwrap();
        assert_eq!(current, &second);
    }

    #[test]
    fn len_reports_entry_count() {
        let mut index = Index::new();
        index.upsert(
            b"a".to_vec(),
            IndexEntry {
                segment_id: 1,
                offset: 0,
                length: 1,
                version: 1,
                is_tombstone: false,
            },
        );
        index.upsert(
            b"b".to_vec(),
            IndexEntry {
                segment_id: 1,
                offset: 1,
                length: 1,
                version: 1,
                is_tombstone: true,
            },
        );
        assert_eq!(index.len(), 2);
    }
}
