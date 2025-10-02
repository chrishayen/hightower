use crate::error::{Error, Result};
use crate::state::KvState;

#[derive(Debug)]
pub struct Snapshot;

impl Snapshot {
    pub fn create(_state: &KvState) -> Result<Self> {
        Err(Error::Unimplemented("snapshot::create"))
    }

    pub fn restore(&self) -> Result<KvState> {
        Err(Error::Unimplemented("snapshot::restore"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_is_unimplemented() {
        let state = KvState::new();
        let err = Snapshot::create(&state).unwrap_err();
        assert!(matches!(err, Error::Unimplemented("snapshot::create")));
    }
}
