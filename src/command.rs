use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    Set {
        key: Vec<u8>,
        value: Vec<u8>,
        version: u64,
        timestamp: i64,
    },
    Delete {
        key: Vec<u8>,
        version: u64,
        timestamp: i64,
    },
}

impl Command {
    pub fn key(&self) -> &[u8] {
        match self {
            Command::Set { key, .. } | Command::Delete { key, .. } => key,
        }
    }

    pub fn version(&self) -> u64 {
        match self {
            Command::Set { version, .. } | Command::Delete { version, .. } => *version,
        }
    }

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
