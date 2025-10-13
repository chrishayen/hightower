use crate::context::NamespacedKv;
use instant_acme::{
    Account, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus,
};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

const ACME_ACCOUNT_PREFIX: &[u8] = b"acme/account";
const ACME_CERT_PREFIX: &[u8] = b"acme/certs";
const CERT_RENEWAL_DAYS: u64 = 30; // Renew 30 days before expiration

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeCertificate {
    pub cert_pem: String,
    pub key_pem: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AcmeAccountData {
    credentials: String, // JSON serialized account credentials
}

#[derive(Debug)]

pub struct AcmeClient {
    kv: Arc<RwLock<NamespacedKv>>,
    email: Option<String>,
    challenges: Arc<RwLock<std::collections::HashMap<String, String>>>,
}

impl AcmeClient {
    pub fn new(kv: Arc<RwLock<NamespacedKv>>, email: Option<String>) -> Self {
        Self {
            kv,
            email,
            challenges: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub fn get_challenge(&self, token: &str) -> Option<String> {
        let challenges = self.challenges.read().expect("challenge lock");
        challenges.get(token).cloned()
    }

    pub async fn obtain_certificate(&self, domain: &str) -> Result<AcmeCertificate, String> {
        info!(domain = %domain, "Requesting Let's Encrypt certificate");

        // Check if we have a cached certificate that's still valid
        info!(domain = %domain, "Checking for cached certificate");
        if let Some(cached) = self.load_cached_cert(domain)? {
            if !self.needs_renewal(&cached) {
                debug!(domain = %domain, "Using cached Let's Encrypt certificate");
                return Ok(cached);
            }
            info!(domain = %domain, "Cached certificate needs renewal");
        }

        // Get or create ACME account
        info!(domain = %domain, "Getting or creating ACME account");
        let account = self.get_or_create_account().await?;
        info!(domain = %domain, "ACME account ready");

        // Create new order for the domain (no wildcard - HTTP-01 doesn't support wildcards)
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &[Identifier::Dns(domain.to_string())],
            })
            .await
            .map_err(|e| format!("Failed to create ACME order: {:?}", e))?;

        debug!(domain = %domain, "ACME order created");

        // Get authorizations
        let authorizations = order
            .authorizations()
            .await
            .map_err(|e| format!("Failed to get authorizations: {:?}", e))?;

        // Process challenges
        for authz in &authorizations {
            info!(domain = %domain, identifier = ?authz.identifier, "Processing authorization");

            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .ok_or_else(|| "No HTTP-01 challenge found".to_string())?;

            let token = challenge.token.as_str();
            let key_auth = order
                .key_authorization(challenge)
                .as_str()
                .to_string();

            info!(domain = %domain, token = %token, key_auth = %key_auth,
                  challenge_url = %challenge.url, "Setting up HTTP-01 challenge");

            // Store challenge response
            {
                let mut challenges = self.challenges.write().expect("challenge lock");
                challenges.insert(token.to_string(), key_auth.clone());
                info!(domain = %domain, token = %token, "Stored challenge in memory (total: {})", challenges.len());
            }

            info!(domain = %domain, "Notifying Let's Encrypt that challenge is ready");

            // Tell Let's Encrypt we're ready
            order
                .set_challenge_ready(&challenge.url)
                .await
                .map_err(|e| format!("Failed to set challenge ready: {:?}", e))?;

            info!(domain = %domain, "Challenge ready notification sent");
        }

        // Give Let's Encrypt time to fetch the challenge before we start polling
        info!(domain = %domain, "Waiting for Let's Encrypt to verify challenges");
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Wait for order to be ready
        let mut attempts = 0;
        let max_attempts = 60; // Increased from 30 to 60 (120 seconds total)
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            attempts += 1;

            order
                .refresh()
                .await
                .map_err(|e| format!("Failed to refresh order: {:?}", e))?;

            match order.state().status {
                OrderStatus::Ready => {
                    info!(domain = %domain, "Order ready for finalization");
                    break;
                }
                OrderStatus::Invalid => {
                    // Get authorization details to see why it failed
                    if let Ok(authz_list) = order.authorizations().await {
                        for authz in authz_list {
                            error!(domain = %domain, identifier = ?authz.identifier, status = ?authz.status,
                                   "Authorization details");
                            for challenge in &authz.challenges {
                                if challenge.r#type == ChallengeType::Http01 {
                                    error!(domain = %domain, challenge_status = ?challenge.status,
                                           error = ?challenge.error, "HTTP-01 challenge failed");
                                }
                            }
                        }
                    }

                    // Clear challenges
                    {
                        let mut challenges = self.challenges.write().expect("challenge lock");
                        challenges.clear();
                    }
                    return Err(format!("Order became invalid for domain: {}", domain));
                }
                OrderStatus::Valid => {
                    info!(domain = %domain, "Order already valid");
                    break;
                }
                _ => {
                    if attempts >= max_attempts {
                        return Err(format!(
                            "Timeout waiting for order to be ready for domain: {}",
                            domain
                        ));
                    }
                    if attempts % 10 == 0 {
                        info!(domain = %domain, attempt = attempts, status = ?order.state().status, "Waiting for order to be ready");
                    }
                }
            }
        }

        // Generate key pair
        let key_pair = rcgen::KeyPair::generate().map_err(|e| format!("{:?}", e))?;
        let key_pem = key_pair.serialize_pem();

        // Create CSR (only base domain - no wildcard for HTTP-01)
        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| format!("Failed to create cert params: {:?}", e))?;

        // Set the common name to the domain (required for Let's Encrypt)
        let mut distinguished_name = rcgen::DistinguishedName::new();
        distinguished_name.push(rcgen::DnType::CommonName, domain);
        params.distinguished_name = distinguished_name;

        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| format!("Failed to create CSR: {:?}", e))?;

        // Finalize order
        order
            .finalize(csr.der())
            .await
            .map_err(|e| format!("Failed to finalize order: {:?}", e))?;

        // Wait for certificate
        let mut attempts = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            attempts += 1;

            order
                .refresh()
                .await
                .map_err(|e| format!("Failed to refresh order: {:?}", e))?;

            if order.state().status == OrderStatus::Valid {
                break;
            }

            if attempts >= 30 {
                return Err(format!(
                    "Timeout waiting for certificate for domain: {}",
                    domain
                ));
            }
        }

        // Download certificate
        let cert_chain = order
            .certificate()
            .await
            .map_err(|e| format!("Failed to download certificate: {:?}", e))?
            .ok_or_else(|| "No certificate returned".to_string())?;

        // Clear challenges
        {
            let mut challenges = self.challenges.write().expect("challenge lock");
            challenges.clear();
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        let acme_cert = AcmeCertificate {
            cert_pem: cert_chain,
            key_pem,
            created_at: now,
            expires_at: now + (90 * 24 * 60 * 60), // Let's Encrypt certs expire in 90 days
        };

        // Cache the certificate
        self.cache_cert(domain, &acme_cert)?;

        info!(domain = %domain, "Successfully obtained Let's Encrypt certificate");
        Ok(acme_cert)
    }

    async fn get_or_create_account(&self) -> Result<Account, String> {
        let kv = self.kv.read().expect("kv read lock");
        let acme_kv = kv.clone_with_additional_prefix(ACME_ACCOUNT_PREFIX);

        // Try to load existing account
        if let Ok(Some(account_bytes)) = acme_kv.get_bytes(b"credentials") {
            if let Ok(account_data) = serde_json::from_slice::<AcmeAccountData>(&account_bytes) {
                if let Ok(credentials) = serde_json::from_str(&account_data.credentials) {
                    debug!("Using existing ACME account");
                    return Ok(Account::from_credentials(credentials)
                        .await
                        .map_err(|e| format!("Failed to restore ACME account: {:?}", e))?);
                }
            }
        }

        // Create new account
        info!("Creating new ACME account");
        let email_string = self.email.as_ref().map(|e| format!("mailto:{}", e));
        let contact: Vec<&str> = email_string.as_ref().map(|s| vec![s.as_str()]).unwrap_or_default();

        let (account, credentials) = Account::create(
            &NewAccount {
                contact: &contact,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            LetsEncrypt::Production.url(),
            None,
        )
        .await
        .map_err(|e| format!("Failed to create ACME account: {:?}", e))?;

        // Save credentials
        let account_data = AcmeAccountData {
            credentials: serde_json::to_string(&credentials)
                .map_err(|e| format!("Failed to serialize credentials: {}", e))?,
        };

        let account_bytes = serde_json::to_vec(&account_data)
            .map_err(|e| format!("Failed to serialize account data: {}", e))?;

        acme_kv
            .put_bytes(b"credentials", &account_bytes)
            .map_err(|e| format!("Failed to save ACME credentials: {}", e))?;

        info!("ACME account created and saved");
        Ok(account)
    }

    fn load_cached_cert(&self, domain: &str) -> Result<Option<AcmeCertificate>, String> {
        let kv = self.kv.read().expect("kv read lock");
        let certs_kv = kv.clone_with_additional_prefix(ACME_CERT_PREFIX);

        match certs_kv.get_bytes(domain.as_bytes()) {
            Ok(Some(cert_bytes)) => {
                match serde_json::from_slice::<AcmeCertificate>(&cert_bytes) {
                    Ok(cert) => Ok(Some(cert)),
                    Err(err) => {
                        warn!(domain = %domain, ?err, "Failed to deserialize cached certificate");
                        Ok(None)
                    }
                }
            }
            Ok(None) => Ok(None),
            Err(err) => Err(format!("Failed to read cached certificate: {}", err)),
        }
    }

    fn cache_cert(&self, domain: &str, cert: &AcmeCertificate) -> Result<(), String> {
        let kv = self.kv.read().expect("kv read lock");
        let certs_kv = kv.clone_with_additional_prefix(ACME_CERT_PREFIX);

        let cert_bytes = serde_json::to_vec(cert)
            .map_err(|e| format!("Failed to serialize certificate: {}", e))?;

        certs_kv
            .put_bytes(domain.as_bytes(), &cert_bytes)
            .map_err(|e| format!("Failed to cache certificate: {}", e))?;

        Ok(())
    }

    fn needs_renewal(&self, cert: &AcmeCertificate) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        let renewal_threshold = cert.expires_at.saturating_sub(CERT_RENEWAL_DAYS * 24 * 60 * 60);
        now >= renewal_threshold
    }

    pub fn load_certified_key(&self, cert: &AcmeCertificate) -> Result<CertifiedKey, String> {
        // Parse certificate chain
        let cert_der = rustls_pemfile::certs(&mut cert.cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse certificate PEM: {:?}", e))?;

        if cert_der.is_empty() {
            return Err("No certificates found in PEM".to_string());
        }

        // Parse private key
        let key_der = rustls_pemfile::private_key(&mut cert.key_pem.as_bytes())
            .map_err(|e| format!("Failed to parse private key PEM: {:?}", e))?
            .ok_or_else(|| "No private key found in PEM".to_string())?;

        // Create signing key
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| format!("Failed to create signing key: {:?}", e))?;

        Ok(CertifiedKey::new(cert_der, signing_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::initialize_kv;
    use tempfile::TempDir;

    #[test]
    fn acme_client_initializes() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let namespaced_kv = crate::context::NamespacedKv::from_handle(kv);
        let client = AcmeClient::new(
            Arc::new(RwLock::new(namespaced_kv)),
            Some("test@example.com".to_string()),
        );

        assert!(client.email.is_some());
    }

    #[test]
    fn needs_renewal_detects_expiring_certs() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let namespaced_kv = crate::context::NamespacedKv::from_handle(kv);
        let client = AcmeClient::new(Arc::new(RwLock::new(namespaced_kv)), None);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Certificate expiring in 29 days (should renew)
        let expiring_cert = AcmeCertificate {
            cert_pem: String::new(),
            key_pem: String::new(),
            created_at: now - (61 * 24 * 60 * 60),
            expires_at: now + (29 * 24 * 60 * 60),
        };

        assert!(client.needs_renewal(&expiring_cert));

        // Certificate expiring in 31 days (should not renew yet)
        let valid_cert = AcmeCertificate {
            cert_pem: String::new(),
            key_pem: String::new(),
            created_at: now - (59 * 24 * 60 * 60),
            expires_at: now + (31 * 24 * 60 * 60),
        };

        assert!(!client.needs_renewal(&valid_cert));
    }
}
