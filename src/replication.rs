use crate::command::Command;
use crate::error::{Error, Result};
use crate::state::ApplyOutcome;

pub trait CommandSubmitter: Send + Sync {
    fn submit(&self, command: Command) -> Result<ApplyOutcome>;
}

pub trait SnapshotProvider: Send + Sync {
    fn latest_snapshot(&self) -> Result<Vec<u8>>;
}

#[derive(Debug)]
pub struct NullReplication;

impl CommandSubmitter for NullReplication {
    fn submit(&self, _command: Command) -> Result<ApplyOutcome> {
        Err(Error::Unimplemented("replication::submit"))
    }
}

impl SnapshotProvider for NullReplication {
    fn latest_snapshot(&self) -> Result<Vec<u8>> {
        Err(Error::Unimplemented("replication::latest_snapshot"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
