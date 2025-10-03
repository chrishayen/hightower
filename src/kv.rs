use hightower_kv::{Error as KvError, SingleNodeEngine, StoreConfig};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::{Builder as TempDirBuilder, TempDir};
use tracing::debug;

#[derive(Debug)]
pub enum KvInitError {
    TempDir(std::io::Error),
    CreateDir(std::io::Error),
    Store(KvError),
}

impl fmt::Display for KvInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KvInitError::TempDir(err) => write!(f, "failed to create temporary directory: {}", err),
            KvInitError::CreateDir(err) => write!(f, "failed to create data directory: {}", err),
            KvInitError::Store(err) => write!(f, "failed to start key-value engine: {}", err),
        }
    }
}

impl Error for KvInitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            KvInitError::TempDir(err) => Some(err),
            KvInitError::CreateDir(err) => Some(err),
            KvInitError::Store(err) => Some(err),
        }
    }
}

#[derive(Debug)]
pub struct KvHandle {
    _engine: SingleNodeEngine,
    data_dir: PathBuf,
    temp_dir: Option<TempDir>,
}

impl KvHandle {
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    #[cfg(test)]
    pub fn temp_dir_path(&self) -> Option<&Path> {
        self.temp_dir.as_ref().map(|dir| dir.path())
    }
}

pub fn initialize(dir: Option<&Path>) -> Result<KvHandle, KvInitError> {
    let (data_dir, temp_dir) = match dir {
        Some(path) => {
            fs::create_dir_all(path).map_err(KvInitError::CreateDir)?;
            (path.to_path_buf(), None)
        }
        None => {
            let temp = TempDirBuilder::new()
                .prefix("hightower-kv")
                .tempdir()
                .map_err(KvInitError::TempDir)?;
            (temp.path().to_path_buf(), Some(temp))
        }
    };

    let mut config = StoreConfig::default();
    config.data_dir = data_dir.to_string_lossy().into_owned();

    let engine = SingleNodeEngine::with_config(config).map_err(KvInitError::Store)?;
    let temporary = temp_dir.is_some();
    debug!(path = %data_dir.display(), temporary, "Initialized key-value store");

    Ok(KvHandle {
        _engine: engine,
        data_dir,
        temp_dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_uses_provided_directory() {
        let temp_root = TempDirBuilder::new()
            .prefix("hightower-test")
            .tempdir()
            .unwrap();
        let target = temp_root.path().join("kv-store");

        let handle = initialize(Some(&target)).expect("kv init succeeds");

        assert_eq!(handle.data_dir(), target.as_path());
        assert!(target.exists());
        assert!(handle.temp_dir_path().is_none());
    }

    #[test]
    fn initialize_falls_back_to_temp_directory() {
        let handle = initialize(None).expect("kv init succeeds");

        let temp_dir = handle.temp_dir_path().expect("temp dir is retained");
        assert!(temp_dir.exists());
        assert!(handle.data_dir().starts_with(temp_dir));
    }
}
