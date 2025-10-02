use std::thread;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct StoreConfig {
    pub data_dir: String,
    pub max_segment_size: u64,
    pub compaction_interval: Duration,
    pub fsync_interval: Duration,
    pub emit_snapshot_after_compaction: bool,
    pub worker_threads: usize,
}

impl Default for StoreConfig {
    fn default() -> Self {
        let default_workers = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .max(1);
        Self {
            data_dir: ".hightower".to_string(),
            max_segment_size: 64 * 1024 * 1024,
            compaction_interval: Duration::from_secs(60),
            fsync_interval: Duration::from_millis(25),
            emit_snapshot_after_compaction: true,
            worker_threads: default_workers,
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
        assert!(cfg.worker_threads >= 1);
    }
}
