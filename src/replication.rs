use std::sync::Arc;

use crate::command::Command;
use crate::engine::{KvEngine, SnapshotEngine};
use crate::error::{Error, Result};
use crate::state::{ApplyOutcome, KvState};

pub trait CommandSubmitter: Send + Sync {
    fn submit(&self, command: Command) -> Result<ApplyOutcome>;

    fn submit_batch<I>(&self, commands: I) -> Result<Vec<ApplyOutcome>>
    where
        I: IntoIterator<Item = Command>;
}

pub trait SnapshotProvider: Send + Sync {
    fn snapshot_state(&self) -> Result<KvState>;
    fn latest_version(&self) -> Result<u64>;
}

pub trait ReplicationHandle: CommandSubmitter + SnapshotProvider {}

impl<T> ReplicationHandle for T where T: CommandSubmitter + SnapshotProvider {}

#[derive(Debug)]
pub struct NullReplication;

impl CommandSubmitter for NullReplication {
    fn submit(&self, _command: Command) -> Result<ApplyOutcome> {
        Err(Error::Unimplemented("replication::submit"))
    }

    fn submit_batch<I>(&self, _commands: I) -> Result<Vec<ApplyOutcome>>
    where
        I: IntoIterator<Item = Command>,
    {
        Err(Error::Unimplemented("replication::submit_batch"))
    }
}

impl SnapshotProvider for NullReplication {
    fn snapshot_state(&self) -> Result<KvState> {
        Err(Error::Unimplemented("replication::latest_snapshot"))
    }

    fn latest_version(&self) -> Result<u64> {
        Err(Error::Unimplemented("replication::latest_version"))
    }
}

#[derive(Debug, Clone)]
pub struct LocalReplication<E>
where
    E: KvEngine + SnapshotEngine,
{
    engine: Arc<E>,
}

impl<E> LocalReplication<E>
where
    E: KvEngine + SnapshotEngine,
{
    pub fn new(engine: Arc<E>) -> Self {
        Self { engine }
    }
}

impl<E> CommandSubmitter for LocalReplication<E>
where
    E: KvEngine + SnapshotEngine,
{
    fn submit(&self, command: Command) -> Result<ApplyOutcome> {
        self.engine.submit(command)
    }

    fn submit_batch<I>(&self, commands: I) -> Result<Vec<ApplyOutcome>>
    where
        I: IntoIterator<Item = Command>,
    {
        self.engine.submit_batch(commands)
    }
}

impl<E> SnapshotProvider for LocalReplication<E>
where
    E: KvEngine + SnapshotEngine,
{
    fn snapshot_state(&self) -> Result<KvState> {
        Ok(self.engine.snapshot_state())
    }

    fn latest_version(&self) -> Result<u64> {
        Ok(self.engine.latest_version())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoreConfig;
    use crate::engine::{SingleNodeEngine, SnapshotEngine};
    use tempfile::tempdir;

    #[test]
    fn submit_returns_unimplemented() {
        let repl = NullReplication;
        let err = repl
            .submit(Command::Delete {
                key: b"k".to_vec(),
                version: 0,
                timestamp: 0,
            })
            .unwrap_err();
        assert!(matches!(err, Error::Unimplemented("replication::submit")));
    }

    #[test]
    fn local_replication_forwards_calls() {
        let temp = tempdir().unwrap();
        let mut cfg = StoreConfig::default();
        cfg.data_dir = temp.path().join("repl").to_string_lossy().into_owned();
        let engine = Arc::new(SingleNodeEngine::with_config(cfg).unwrap());
        let repl = LocalReplication::new(Arc::clone(&engine));

        repl.submit(Command::Set {
            key: b"k".to_vec(),
            value: b"v".to_vec(),
            version: engine.latest_version() + 1,
            timestamp: 1,
        })
        .unwrap();

        let snapshot = repl.snapshot_state().unwrap();
        assert_eq!(snapshot.get(b"k"), Some(&b"v"[..]));
    }
}
