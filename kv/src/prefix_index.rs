use hashbrown::HashMap;
use std::sync::Arc;

use crate::index::IndexEntry;

/// A radix trie node for efficient prefix queries
#[derive(Clone, Debug)]
struct TrieNode {
    /// Entry at this node (if this is a terminal node)
    entry: Option<IndexEntry>,
    /// Child nodes indexed by byte value
    children: HashMap<u8, Box<TrieNode>>,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            entry: None,
            children: HashMap::new(),
        }
    }
}

/// Prefix index using a radix trie for efficient prefix queries
#[derive(Clone, Debug)]
pub struct PrefixIndex {
    root: Arc<TrieNode>,
}

impl Default for PrefixIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl PrefixIndex {
    /// Creates a new empty prefix index
    pub fn new() -> Self {
        Self {
            root: Arc::new(TrieNode::new()),
        }
    }

    /// Inserts a key-entry pair into the trie
    pub fn insert(&mut self, key: Vec<u8>, entry: IndexEntry) {
        let root = Arc::make_mut(&mut self.root);
        let mut current = root;

        for &byte in &key {
            current = current
                .children
                .entry(byte)
                .or_insert_with(|| Box::new(TrieNode::new()));
        }

        current.entry = Some(entry);
    }

    /// Removes a key from the trie
    pub fn remove(&mut self, key: &[u8]) -> Option<IndexEntry> {
        let root = Arc::make_mut(&mut self.root);
        Self::remove_recursive(root, key, 0)
    }

    fn remove_recursive(node: &mut TrieNode, key: &[u8], depth: usize) -> Option<IndexEntry> {
        if depth == key.len() {
            return node.entry.take();
        }

        let byte = key[depth];
        let child = node.children.get_mut(&byte)?;
        let result = Self::remove_recursive(child, key, depth + 1);

        // Remove empty children
        if child.entry.is_none() && child.children.is_empty() {
            node.children.remove(&byte);
        }

        result
    }

    /// Gets all key-entry pairs with the given prefix
    pub fn get_prefix(&self, prefix: &[u8]) -> Vec<(Vec<u8>, IndexEntry)> {
        let mut results = Vec::new();
        let mut current = &*self.root;

        // Navigate to the prefix node
        for &byte in prefix {
            match current.children.get(&byte) {
                Some(child) => current = child,
                None => return results,
            }
        }

        // Collect all entries under this prefix
        let mut prefix_vec = prefix.to_vec();
        Self::collect_all(current, &mut prefix_vec, &mut results);
        results
    }

    fn collect_all(
        node: &TrieNode,
        current_key: &mut Vec<u8>,
        results: &mut Vec<(Vec<u8>, IndexEntry)>,
    ) {
        // If this node has an entry, add it to results
        if let Some(entry) = &node.entry {
            results.push((current_key.clone(), entry.clone()));
        }

        // Recursively collect from all children
        for (&byte, child) in &node.children {
            current_key.push(byte);
            Self::collect_all(child, current_key, results);
            current_key.pop();
        }
    }

    /// Returns the number of keys in the index
    pub fn len(&self) -> usize {
        Self::count_entries(&self.root)
    }

    fn count_entries(node: &TrieNode) -> usize {
        let mut count = if node.entry.is_some() { 1 } else { 0 };
        for child in node.children.values() {
            count += Self::count_entries(child);
        }
        count
    }

    /// Returns true if the index is empty
    pub fn is_empty(&self) -> bool {
        self.root.entry.is_none() && self.root.children.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(version: u64) -> IndexEntry {
        IndexEntry {
            segment_id: 1,
            offset: 0,
            length: 1,
            version,
            is_tombstone: false,
        }
    }

    #[test]
    fn insert_and_get_prefix() {
        let mut index = PrefixIndex::new();
        index.insert(b"app:user:1".to_vec(), sample_entry(1));
        index.insert(b"app:user:2".to_vec(), sample_entry(2));
        index.insert(b"app:session:1".to_vec(), sample_entry(3));
        index.insert(b"other".to_vec(), sample_entry(4));

        let results = index.get_prefix(b"app:user:");
        assert_eq!(results.len(), 2);

        let keys: Vec<Vec<u8>> = results.iter().map(|(k, _)| k.clone()).collect();
        assert!(keys.contains(&b"app:user:1".to_vec()));
        assert!(keys.contains(&b"app:user:2".to_vec()));
    }

    #[test]
    fn get_prefix_returns_empty_for_nonexistent_prefix() {
        let mut index = PrefixIndex::new();
        index.insert(b"key1".to_vec(), sample_entry(1));

        let results = index.get_prefix(b"nonexistent");
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn remove_deletes_key() {
        let mut index = PrefixIndex::new();
        index.insert(b"key".to_vec(), sample_entry(1));
        assert_eq!(index.len(), 1);

        let removed = index.remove(b"key");
        assert!(removed.is_some());
        assert_eq!(index.len(), 0);

        let results = index.get_prefix(b"key");
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn get_prefix_with_empty_prefix() {
        let mut index = PrefixIndex::new();
        index.insert(b"a".to_vec(), sample_entry(1));
        index.insert(b"b".to_vec(), sample_entry(2));

        let results = index.get_prefix(b"");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn len_counts_all_entries() {
        let mut index = PrefixIndex::new();
        assert_eq!(index.len(), 0);

        index.insert(b"a".to_vec(), sample_entry(1));
        index.insert(b"b".to_vec(), sample_entry(2));
        index.insert(b"c".to_vec(), sample_entry(3));

        assert_eq!(index.len(), 3);
    }

    #[test]
    fn update_existing_key() {
        let mut index = PrefixIndex::new();
        index.insert(b"key".to_vec(), sample_entry(1));
        index.insert(b"key".to_vec(), sample_entry(2));

        let results = index.get_prefix(b"key");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1.version, 2);
    }
}
