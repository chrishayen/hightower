use serde::{Deserialize, Serialize};

use crate::crypto::{EncryptedBlob, SecretHash};
use crate::error::{Error, Result};

pub type Timestamp = i64;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRecord {
    pub user_id: String,
    pub username: String,
    pub password_hash: SecretHash,
    pub metadata: Option<EncryptedBlob>,
    pub created_at: Timestamp,
    pub last_login: Option<Timestamp>,
    pub failed_attempts: u32,
}

impl UserRecord {
    pub fn validate(&self) -> Result<()> {
        if self.username.trim().is_empty() {
            return Err(Error::Validation("username cannot be empty"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiKeyRecord {
    pub key_id: String,
    pub owner_id: String,
    pub token_hash: SecretHash,
    pub label: Option<String>,
    pub metadata: Option<EncryptedBlob>,
    pub created_at: Timestamp,
    pub last_used: Option<Timestamp>,
}

impl ApiKeyRecord {
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
