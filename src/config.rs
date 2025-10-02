use std::time::Duration;

#[derive(Clone, Debug)]
pub struct StoreConfig {
    pub data_dir: String,
    pub max_segment_size: u64,
    pub compaction_interval: Duration,
    pub fsync_interval: Duration,
    pub emit_snapshot_after_compaction: bool,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            data_dir: ".hightower".to_string(),
            max_segment_size: 64 * 1024 * 1024,
            compaction_interval: Duration::from_secs(60),
            fsync_interval: Duration::from_millis(25),
            emit_snapshot_after_compaction: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values_are_reasonable() {
        let cfg = StoreConfig::default();
        assert_eq!(cfg.data_dir, ".hightower");
        assert!(cfg.max_segment_size >= 4 * 1024 * 1024);
        assert!(cfg.compaction_interval >= Duration::from_secs(1));
        assert!(cfg.fsync_interval <= Duration::from_millis(100));
        assert!(cfg.emit_snapshot_after_compaction);
    }
}
