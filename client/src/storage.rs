use crate::error::ClientError;
use kv::{KvEngine, SingleNodeEngine, StoreConfig};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

const CONN_KEY: &[u8] = b"connection";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredConnection {
    pub endpoint_id: String,
    pub token: String,
    pub gateway_url: String,
    pub assigned_ip: String,
    pub private_key_hex: String,
    pub public_key_hex: String,
    pub gateway_public_key_hex: String,
    pub created_at: u64,
    pub last_connected_at: u64,
}

#[derive(Clone)]
pub struct ConnectionStorage {
    engine: Arc<SingleNodeEngine>,
}

impl ConnectionStorage {
    /// Create a new storage instance for the given gateway URL
    pub fn for_gateway(gateway_url: &str) -> Result<Self, ClientError> {
        let data_dir = Self::gateway_data_dir(gateway_url)?;
        Self::new(data_dir)
    }

    /// Create a new storage instance with the given data directory
    pub(crate) fn new(data_dir: impl Into<PathBuf>) -> Result<Self, ClientError> {
        let data_dir: PathBuf = data_dir.into();

        // Create directory if it doesn't exist
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| ClientError::Storage(format!("failed to create storage directory: {}", e)))?;

        let mut config = StoreConfig::default();
        config.data_dir = data_dir.to_string_lossy().to_string();
        config.worker_threads = 0; // Use inline mode for simplicity

        let engine = SingleNodeEngine::with_config(config)
            .map_err(|e| ClientError::Storage(format!("failed to initialize storage: {}", e)))?;

        debug!(data_dir = ?data_dir, "Initialized connection storage");

        Ok(Self {
            engine: Arc::new(engine),
        })
    }

    /// Get the storage directory for a specific gateway: ~/.hightower/gateway/<gateway>/
    fn gateway_data_dir(gateway_url: &str) -> Result<PathBuf, ClientError> {
        let home = std::env::var("HOME")
            .map_err(|_| ClientError::Storage("HOME environment variable not set".into()))?;

        let gateway_dirname = Self::sanitize_gateway_url(gateway_url);

        Ok(PathBuf::from(home)
            .join(".hightower")
            .join("gateway")
            .join(gateway_dirname))
    }

    /// Convert a gateway URL to a filesystem-safe directory name
    fn sanitize_gateway_url(gateway_url: &str) -> String {
        // Remove scheme (http://, https://)
        let without_scheme = gateway_url
            .strip_prefix("https://")
            .or_else(|| gateway_url.strip_prefix("http://"))
            .unwrap_or(gateway_url);

        // Replace problematic characters with underscores
        without_scheme
            .chars()
            .map(|c| match c {
                '/' | ':' | '?' | '#' | '[' | ']' | '@' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=' => '_',
                c if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' => c,
                _ => '_',
            })
            .collect()
    }

    /// Store a connection
    pub fn store_connection(&self, conn: &StoredConnection) -> Result<(), ClientError> {
        let value = serde_json::to_vec(conn)
            .map_err(|e| ClientError::Storage(format!("failed to serialize connection: {}", e)))?;

        self.engine
            .put(CONN_KEY.to_vec(), value)
            .map_err(|e| ClientError::Storage(format!("failed to store connection: {}", e)))?;

        self.engine
            .flush()
            .map_err(|e| ClientError::Storage(format!("failed to flush storage: {}", e)))?;

        debug!(gateway_url = %conn.gateway_url, endpoint_id = %conn.endpoint_id, "Stored connection");

        Ok(())
    }

    /// Retrieve the stored connection
    pub fn get_connection(&self) -> Result<Option<StoredConnection>, ClientError> {
        let value = self.engine
            .get(CONN_KEY)
            .map_err(|e| ClientError::Storage(format!("failed to retrieve connection: {}", e)))?;

        match value {
            Some(bytes) => {
                let conn: StoredConnection = serde_json::from_slice(&bytes)
                    .map_err(|e| ClientError::Storage(format!("failed to deserialize connection: {}", e)))?;
                debug!(gateway_url = %conn.gateway_url, endpoint_id = %conn.endpoint_id, "Retrieved stored connection");
                Ok(Some(conn))
            }
            None => {
                debug!("No stored connection found");
                Ok(None)
            }
        }
    }

    /// Delete the stored connection
    pub fn delete_connection(&self) -> Result<(), ClientError> {
        self.engine
            .delete(CONN_KEY.to_vec())
            .map_err(|e| ClientError::Storage(format!("failed to delete connection: {}", e)))?;

        self.engine
            .flush()
            .map_err(|e| ClientError::Storage(format!("failed to flush storage: {}", e)))?;

        debug!("Deleted stored connection");

        Ok(())
    }

    /// Update the last_connected_at timestamp for the stored connection
    pub fn update_last_connected(&self) -> Result<(), ClientError> {
        if let Some(mut conn) = self.get_connection()? {
            conn.last_connected_at = current_timestamp();
            self.store_connection(&conn)?;
        }
        Ok(())
    }
}

/// Get current Unix timestamp in seconds
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_storage() -> (ConnectionStorage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage = ConnectionStorage::new(temp_dir.path()).unwrap();
        (storage, temp_dir)
    }

    fn create_test_connection() -> StoredConnection {
        StoredConnection {
            endpoint_id: "test-endpoint-123".into(),
            token: "test-token-456".into(),
            gateway_url: "http://127.0.0.1:8008".into(),
            assigned_ip: "10.0.0.5".into(),
            private_key_hex: "deadbeef".into(),
            public_key_hex: "cafebabe".into(),
            gateway_public_key_hex: "feedface".into(),
            created_at: 1234567890,
            last_connected_at: 1234567890,
        }
    }

    #[test]
    fn test_sanitize_gateway_url() {
        assert_eq!(
            ConnectionStorage::sanitize_gateway_url("http://127.0.0.1:8008"),
            "127.0.0.1_8008"
        );
        assert_eq!(
            ConnectionStorage::sanitize_gateway_url("https://gateway.example.com:8443"),
            "gateway.example.com_8443"
        );
        assert_eq!(
            ConnectionStorage::sanitize_gateway_url("http://localhost:9000/api"),
            "localhost_9000_api"
        );
    }

    #[test]
    fn test_store_and_retrieve_connection() {
        let (storage, _temp_dir) = create_test_storage();
        let conn = create_test_connection();

        storage.store_connection(&conn).unwrap();

        let retrieved = storage
            .get_connection()
            .unwrap()
            .expect("connection should exist");

        assert_eq!(retrieved.endpoint_id, conn.endpoint_id);
        assert_eq!(retrieved.token, conn.token);
        assert_eq!(retrieved.gateway_url, conn.gateway_url);
        assert_eq!(retrieved.assigned_ip, conn.assigned_ip);
    }

    #[test]
    fn test_get_nonexistent_connection() {
        let (storage, _temp_dir) = create_test_storage();

        let result = storage.get_connection().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_delete_connection() {
        let (storage, _temp_dir) = create_test_storage();
        let conn = create_test_connection();

        storage.store_connection(&conn).unwrap();
        assert!(storage.get_connection().unwrap().is_some());

        storage.delete_connection().unwrap();
        assert!(storage.get_connection().unwrap().is_none());
    }

    #[test]
    fn test_update_last_connected() {
        let (storage, _temp_dir) = create_test_storage();
        let conn = create_test_connection();

        storage.store_connection(&conn).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));
        storage.update_last_connected().unwrap();

        let updated = storage
            .get_connection()
            .unwrap()
            .expect("connection should exist");

        assert!(updated.last_connected_at > conn.last_connected_at);
    }

    #[test]
    fn test_different_gateways_separate_storage() {
        let temp_dir = TempDir::new().unwrap();

        let conn1 = create_test_connection();
        let mut conn2 = create_test_connection();
        conn2.gateway_url = "http://other-gateway:8008".into();
        conn2.endpoint_id = "other-endpoint-789".into();

        // Create separate storage for each gateway
        let storage1 = ConnectionStorage::new(temp_dir.path().join("gateway1")).unwrap();
        let storage2 = ConnectionStorage::new(temp_dir.path().join("gateway2")).unwrap();

        storage1.store_connection(&conn1).unwrap();
        storage2.store_connection(&conn2).unwrap();

        let retrieved1 = storage1.get_connection().unwrap().unwrap();
        let retrieved2 = storage2.get_connection().unwrap().unwrap();

        assert_eq!(retrieved1.endpoint_id, "test-endpoint-123");
        assert_eq!(retrieved2.endpoint_id, "other-endpoint-789");
    }
}
