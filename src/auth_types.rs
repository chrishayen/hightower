use serde::{Deserialize, Serialize};

use crate::crypto::{EncryptedBlob, SecretHash};
use crate::error::{Error, Result};

/// Unix timestamp type alias
pub type Timestamp = i64;

/// Record representing a user account
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRecord {
    /// Unique user identifier
    pub user_id: String,
    /// Username for login
    pub username: String,
    /// Hashed password
    pub password_hash: SecretHash,
    /// Optional encrypted metadata
    pub metadata: Option<EncryptedBlob>,
    /// Unix timestamp when the user was created
    pub created_at: Timestamp,
    /// Unix timestamp of the last successful login
    pub last_login: Option<Timestamp>,
    /// Number of consecutive failed login attempts
    pub failed_attempts: u32,
}

impl UserRecord {
    /// Validates the user record, checking required fields
    pub fn validate(&self) -> Result<()> {
        if self.username.trim().is_empty() {
            return Err(Error::Validation("username cannot be empty"));
        }
        Ok(())
    }
}

/// Record representing an API key
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiKeyRecord {
    /// Unique key identifier
    pub key_id: String,
    /// User ID that owns this key
    pub owner_id: String,
    /// Hashed API key token
    pub token_hash: SecretHash,
    /// Optional human-readable label
    pub label: Option<String>,
    /// Optional encrypted metadata
    pub metadata: Option<EncryptedBlob>,
    /// Unix timestamp when the key was created
    pub created_at: Timestamp,
    /// Unix timestamp when the key was last used
    pub last_used: Option<Timestamp>,
}

impl ApiKeyRecord {
    /// Validates the API key record, checking required fields
    pub fn validate(&self) -> Result<()> {
        if self.owner_id.is_empty() {
            return Err(Error::Validation("owner_id cannot be empty"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::EncryptedBlob;

    fn sample_hash() -> SecretHash {
        SecretHash::from("hash".to_string())
    }

    #[test]
    fn user_validation_rejects_blank_username() {
        let user = UserRecord {
            user_id: "u1".into(),
            username: "   ".into(),
            password_hash: sample_hash(),
            metadata: None,
            created_at: 0,
            last_login: None,
            failed_attempts: 0,
        };
        assert!(user.validate().is_err());
    }

    #[test]
    fn api_key_validation_requires_owner() {
        let record = ApiKeyRecord {
            key_id: "k1".into(),
            owner_id: String::new(),
            token_hash: sample_hash(),
            label: None,
            metadata: Some(EncryptedBlob {
                nonce: [0u8; 12],
                ciphertext: vec![],
            }),
            created_at: 0,
            last_used: None,
        };
        assert!(record.validate().is_err());
    }
}
