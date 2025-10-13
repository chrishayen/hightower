use serde::{Deserialize, Serialize};

/// Commands that can be applied to the key-value store
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    /// Sets a key to a value with version and timestamp
    Set {
        /// The key to set
        key: Vec<u8>,
        /// The value to store
        value: Vec<u8>,
        /// Version number for conflict resolution
        version: u64,
        /// Timestamp when the command was created
        timestamp: i64,
    },
    /// Deletes a key with version and timestamp
    Delete {
        /// The key to delete
        key: Vec<u8>,
        /// Version number for conflict resolution
        version: u64,
        /// Timestamp when the command was created
        timestamp: i64,
    },
}

impl Command {
    /// Returns the key referenced by this command
    pub fn key(&self) -> &[u8] {
        match self {
            Command::Set { key, .. } | Command::Delete { key, .. } => key,
        }
    }

    /// Returns the version number of this command
    pub fn version(&self) -> u64 {
        match self {
            Command::Set { version, .. } | Command::Delete { version, .. } => *version,
        }
    }

    /// Returns the timestamp of this command
    pub fn timestamp(&self) -> i64 {
        match self {
            Command::Set { timestamp, .. } | Command::Delete { timestamp, .. } => *timestamp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_serialization() {
        let cmd = Command::Set {
            key: b"k".to_vec(),
            value: b"v".to_vec(),
            version: 7,
            timestamp: 42,
        };
        let bytes = serde_cbor::to_vec(&cmd).expect("serialize");
        let decoded: Command = serde_cbor::from_slice(&bytes).expect("deserialize");
        assert_eq!(decoded, cmd);
    }

    #[test]
    fn key_accessor_returns_expected_slice() {
        let cmd = Command::Delete {
            key: b"alpha".to_vec(),
            version: 1,
            timestamp: 5,
        };
        assert_eq!(cmd.key(), b"alpha");
        assert_eq!(cmd.version(), 1);
        assert_eq!(cmd.timestamp(), 5);
    }
}
