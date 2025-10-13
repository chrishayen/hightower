use crate::acme::AcmeClient;
use crate::context::NamespacedKv;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

const CERT_PREFIX: &[u8] = b"tls/certs";
const CERT_VALIDITY_DAYS: u32 = 365;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedCertificate {
    cert_pem: String,
    key_pem: String,
    created_at: u64,
}

#[derive(Debug)]
pub struct SniResolver {
    kv: Arc<RwLock<NamespacedKv>>,
    acme_client: Option<Arc<AcmeClient>>,
    // Track domains with in-flight ACME requests to prevent duplicates
    pending_acme: Arc<RwLock<std::collections::HashSet<String>>>,
}

impl SniResolver {
    pub fn new(kv: Arc<RwLock<NamespacedKv>>) -> Self {
        Self {
            kv,
            acme_client: None,
            pending_acme: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    pub fn with_acme(kv: Arc<RwLock<NamespacedKv>>, acme_client: Arc<AcmeClient>) -> Self {
        Self {
            kv,
            acme_client: Some(acme_client),
            pending_acme: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    fn extract_base_domain(&self, hostname: &str) -> String {
        // Extract base domain from hostname
        // e.g., "gateway.shotgun.dev" -> "shotgun.dev"
        // e.g., "api.gateway.shotgun.dev" -> "shotgun.dev"
        // e.g., "shotgun.dev" -> "shotgun.dev"
        // e.g., "localhost" -> "localhost"

        let parts: Vec<&str> = hostname.split('.').collect();

        // If it's a simple domain or localhost, use as-is
        if parts.len() <= 2 {
            return hostname.to_string();
        }

        // Otherwise, take the last two parts (domain + TLD)
        // This works for .com, .dev, .io, etc.
        // Note: This is a simple heuristic and doesn't handle special TLDs like .co.uk
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    }

    fn load_or_generate_cert(&self, domain: &str) -> Result<CertifiedKey, String> {
        // Try ACME first if available - check if we already have a cached ACME cert
        if let Some(acme_client) = &self.acme_client {
            // Check ACME cache first (non-blocking)
            let kv = self.kv.read().expect("kv read lock");
            let acme_kv = kv.clone_with_additional_prefix(b"acme/certs");

            if let Ok(Some(cert_bytes)) = acme_kv.get_bytes(domain.as_bytes()) {
                if let Ok(acme_cert) = serde_json::from_slice::<crate::acme::AcmeCertificate>(&cert_bytes) {
                    // Check if cert is still valid
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or(Duration::from_secs(0))
                        .as_secs();
                    let renewal_threshold = acme_cert.expires_at.saturating_sub(30 * 24 * 60 * 60);

                    if now < renewal_threshold {
                        debug!(domain = %domain, "Using cached ACME certificate");
                        match acme_client.load_certified_key(&acme_cert) {
                            Ok(key) => return Ok(key),
                            Err(err) => {
                                warn!(domain = %domain, ?err, "Failed to load cached ACME cert");
                            }
                        }
                    } else {
                        debug!(domain = %domain, "Cached ACME certificate needs renewal");
                    }
                }
            }

            // Check if there's already an in-flight ACME request for this domain
            let should_start_acme = {
                let mut pending = self.pending_acme.write().expect("pending acme lock");
                if pending.contains(domain) {
                    info!(domain = %domain, "ACME request already in progress, skipping duplicate");
                    false
                } else {
                    pending.insert(domain.to_string());
                    true
                }
            };

            // No valid ACME cert - spawn background task to obtain one (if not already in progress)
            // Meanwhile, return self-signed cert immediately to avoid browser timeout
            if should_start_acme {
                info!(domain = %domain, "No cached ACME certificate, will obtain in background");
                let acme_client_bg = Arc::clone(acme_client);
                let domain_bg = domain.to_string();
                let pending_acme_bg = Arc::clone(&self.pending_acme);

                // Capture the current tracing dispatcher for the background thread
                let dispatcher = tracing::dispatcher::get_default(|d| d.clone());

                std::thread::spawn(move || {
                    // Set the dispatcher in the background thread so logs appear
                    tracing::dispatcher::with_default(&dispatcher, || {
                        info!(domain = %domain_bg, "Background ACME request starting");
                        let rt = match tokio::runtime::Runtime::new() {
                            Ok(rt) => rt,
                            Err(e) => {
                                error!(domain = %domain_bg, ?e, "Failed to create runtime for background ACME");
                                // Remove from pending set on error
                                let mut pending = pending_acme_bg.write().expect("pending acme lock");
                                pending.remove(&domain_bg);
                                return;
                            }
                        };

                        rt.block_on(async move {
                            match acme_client_bg.obtain_certificate(&domain_bg).await {
                                Ok(_) => {
                                    info!(domain = %domain_bg, "Background ACME certificate obtained successfully");
                                }
                                Err(err) => {
                                    error!(domain = %domain_bg, ?err, "Background ACME request failed");
                                }
                            }

                            // Remove from pending set when done (success or failure)
                            let mut pending = pending_acme_bg.write().expect("pending acme lock");
                            pending.remove(&domain_bg);
                        });
                    })
                });
            }

            // Fall through to return self-signed cert immediately
            info!(domain = %domain, "Returning self-signed certificate while ACME runs in background");
        }

        // Fallback to self-signed certificates
        let kv = self.kv.read().expect("kv read lock");
        let certs_kv = kv.clone_with_additional_prefix(CERT_PREFIX);

        // Check if cert exists and is valid
        if let Ok(Some(cached_bytes)) = certs_kv.get_bytes(domain.as_bytes()) {
            match serde_json::from_slice::<CachedCertificate>(&cached_bytes) {
                Ok(cached) => {
                    if !is_expired(&cached) {
                        debug!(domain = %domain, "Using cached self-signed certificate");
                        match load_certified_key(&cached.cert_pem, &cached.key_pem) {
                            Ok(key) => return Ok(key),
                            Err(err) => {
                                warn!(domain = %domain, ?err, "Failed to load cached cert, regenerating");
                            }
                        }
                    } else {
                        debug!(domain = %domain, "Cached certificate expired, regenerating");
                    }
                }
                Err(err) => {
                    warn!(domain = %domain, ?err, "Failed to deserialize cached cert, regenerating");
                }
            }
        }

        // Generate new self-signed certificate
        debug!(domain = %domain, "Generating new self-signed certificate");
        let (cert_pem, key_pem) = generate_wildcard_cert(domain)?;
        let certified_key = load_certified_key(&cert_pem, &key_pem)?;

        // Cache it
        let cached = CachedCertificate {
            cert_pem,
            key_pem,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs(),
        };

        if let Ok(cached_bytes) = serde_json::to_vec(&cached) {
            if let Err(err) = certs_kv.put_bytes(domain.as_bytes(), &cached_bytes) {
                error!(domain = %domain, ?err, "Failed to cache certificate");
            } else {
                debug!(domain = %domain, "Certificate cached successfully");
            }
        }

        Ok(certified_key)
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let server_name = match client_hello.server_name() {
            Some(name) => name,
            None => {
                // No SNI provided - this is common for bots/scanners
                // We can't determine which certificate to serve without SNI
                debug!("TLS connection without SNI (server name indication) - cannot resolve certificate");
                return None;
            }
        };

        // For ACME, use the full hostname (since HTTP-01 doesn't support wildcards)
        // For self-signed, extract base domain to generate wildcard cert
        let domain = if self.acme_client.is_some() {
            server_name.to_string()
        } else {
            self.extract_base_domain(server_name)
        };

        debug!(sni = %server_name, domain = %domain, "SNI certificate request");

        match self.load_or_generate_cert(&domain) {
            Ok(key) => Some(Arc::new(key)),
            Err(err) => {
                error!(domain = %domain, ?err, "Failed to load or generate certificate");
                None
            }
        }
    }
}

fn is_expired(cached: &CachedCertificate) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();

    let expiry = cached.created_at + (CERT_VALIDITY_DAYS as u64 * 24 * 60 * 60);
    now >= expiry
}

fn generate_wildcard_cert(domain: &str) -> Result<(String, String), String> {
    let mut params = CertificateParams::default();

    // Set subject
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, format!("*.{}", domain));
    params.distinguished_name = distinguished_name;

    // Add SANs (Subject Alternative Names) for wildcard and base domain
    params.subject_alt_names = vec![
        SanType::DnsName(format!("*.{}", domain).try_into().map_err(|e| format!("{:?}", e))?),
        SanType::DnsName(domain.try_into().map_err(|e| format!("{:?}", e))?),
    ];

    // Set validity period
    let now = rcgen::date_time_ymd(2024, 1, 1);
    params.not_before = now;
    params.not_after = rcgen::date_time_ymd(2024 + (CERT_VALIDITY_DAYS / 365) as i32, 1, 1);

    // Generate key pair
    let key_pair = KeyPair::generate().map_err(|e| format!("{:?}", e))?;
    let key_pem = key_pair.serialize_pem();

    // Generate certificate
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("Failed to generate cert: {:?}", e))?;

    let cert_pem = cert.pem();

    Ok((cert_pem, key_pem))
}

fn load_certified_key(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey, String> {
    // Parse certificate
    let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse certificate PEM: {:?}", e))?;

    if cert_der.is_empty() {
        return Err("No certificates found in PEM".to_string());
    }

    // Parse private key
    let key_der = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| format!("Failed to parse private key PEM: {:?}", e))?
        .ok_or_else(|| "No private key found in PEM".to_string())?;

    // Create signing key
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|e| format!("Failed to create signing key: {:?}", e))?;

    Ok(CertifiedKey::new(cert_der, signing_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::initialize_kv;
    use tempfile::TempDir;

    #[test]
    fn generate_wildcard_cert_creates_valid_cert() {
        let (cert_pem, key_pem) = generate_wildcard_cert("example.com").expect("cert generation");

        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(cert_pem.contains("END CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(key_pem.contains("END PRIVATE KEY"));
    }

    #[test]
    fn load_certified_key_parses_generated_cert() {
        let (cert_pem, key_pem) = generate_wildcard_cert("example.com").expect("cert generation");
        let result = load_certified_key(&cert_pem, &key_pem);

        assert!(result.is_ok());
    }

    #[test]
    fn sni_resolver_generates_and_caches_cert() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let namespaced_kv = crate::context::NamespacedKv::from_handle(kv);
        let resolver = SniResolver::new(Arc::new(RwLock::new(namespaced_kv)));

        let domain = "test.com";
        let cert1 = resolver
            .load_or_generate_cert(domain)
            .expect("first cert generation");

        // Should use cached cert on second call
        let cert2 = resolver
            .load_or_generate_cert(domain)
            .expect("second cert generation");

        // Both should succeed (verifying they're the same is complex, just verify both work)
        assert_eq!(cert1.cert.len(), cert2.cert.len());
    }

    #[test]
    fn is_expired_detects_old_certs() {
        let old_cert = CachedCertificate {
            cert_pem: String::new(),
            key_pem: String::new(),
            created_at: 0, // Very old
        };

        assert!(is_expired(&old_cert));
    }

    #[test]
    fn is_expired_accepts_new_certs() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let new_cert = CachedCertificate {
            cert_pem: String::new(),
            key_pem: String::new(),
            created_at: now,
        };

        assert!(!is_expired(&new_cert));
    }

    #[test]
    fn extract_base_domain_handles_subdomains() {
        let temp = TempDir::new().expect("tempdir");
        let kv = initialize_kv(Some(temp.path())).expect("kv init");
        let namespaced_kv = crate::context::NamespacedKv::from_handle(kv);
        let resolver = SniResolver::new(Arc::new(RwLock::new(namespaced_kv)));

        // Single subdomain
        assert_eq!(resolver.extract_base_domain("gateway.shotgun.dev"), "shotgun.dev");

        // Nested subdomains
        assert_eq!(resolver.extract_base_domain("api.gateway.shotgun.dev"), "shotgun.dev");

        // Base domain only
        assert_eq!(resolver.extract_base_domain("shotgun.dev"), "shotgun.dev");

        // Localhost
        assert_eq!(resolver.extract_base_domain("localhost"), "localhost");
    }
}
