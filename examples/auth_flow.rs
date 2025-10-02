use hightower_kv::crypto::{AesGcmEncryptor, Argon2SecretHasher};
use hightower_kv::{AuthService, SingleNodeEngine, StoreConfig};
use std::error::Error;
use std::path::PathBuf;
use tempfile::TempDir;

fn main() -> Result<(), Box<dyn Error>> {
    let tempdir = TempDir::new()?;
    let data_dir = tempdir.path().join("auth-data");

    let mut config = StoreConfig::default();
    config.data_dir = path_to_string(data_dir);
    config.worker_threads = 2;

    let engine = SingleNodeEngine::with_config(config)?;
    let hasher = Argon2SecretHasher::default();
    let encryptor = AesGcmEncryptor::new([0u8; 32]);
    let auth = AuthService::new(engine, hasher, encryptor);

    // Create a user with an optional metadata blob.
    let user = auth
        .create_user_with_metadata(
            "captain",
            "it-doesnt-take-much",
            Some(b"{\"role\":\"ops\"}".as_slice()),
        )?
        .user_id;
    println!("created user {user}");

    // Verify the password in the happy path and for a typo.
    assert!(auth.verify_password("captain", "it-doesnt-take-much")?);
    assert!(!auth.verify_password("captain", "nope")?);

    // Generate and authenticate an API key tied to the same user.
    let (key_record, token) = auth.create_api_key(&user, None)?;
    println!("issued key {} with token {}", key_record.key_id, token);
    let hydrated = auth
        .authenticate_api_key(&token)?
        .expect("token should resolve");
    println!("token resolved to user {}", hydrated.owner_id);

    Ok(())
}

fn path_to_string(path: PathBuf) -> String {
    path.to_string_lossy().into_owned()
}
