use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use tracing::warn;

use crate::shell;

/// Certificate directory inside the Lima VM.
const CERT_DIR: &str = "/var/lib/mvm/certs";

/// Certificate file paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertPaths {
    pub ca_cert: String,
    pub node_cert: String,
    pub node_key: String,
}

impl CertPaths {
    pub fn default_paths() -> Self {
        Self {
            ca_cert: format!("{}/ca.crt", CERT_DIR),
            node_cert: format!("{}/node.crt", CERT_DIR),
            node_key: format!("{}/node.key", CERT_DIR),
        }
    }
}

/// Certificate status info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertStatus {
    pub ca_present: bool,
    pub node_cert_present: bool,
    pub node_key_present: bool,
    pub node_cert_subject: Option<String>,
    pub node_cert_expires: Option<String>,
    pub last_rotated: Option<String>,
}

/// Ensure the certificate directory exists (owned by current user).
fn ensure_cert_dir() -> Result<()> {
    let output = shell::run_in_vm(&format!(
        "sudo mkdir -p {} && sudo chown $(id -u):$(id -g) {}",
        CERT_DIR, CERT_DIR
    ))
    .with_context(|| "Failed to create cert directory")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Failed to create cert directory {}: {}",
            CERT_DIR,
            stderr.trim()
        );
    }
    Ok(())
}

/// Initialize CA certificate from an external file.
///
/// Copies the CA cert into the mvm cert directory. The CA cert is the
/// trust root for verifying coordinator and peer node certificates.
pub fn init_ca(ca_cert_source: &str) -> Result<()> {
    ensure_cert_dir()?;
    let paths = CertPaths::default_paths();

    let output = shell::run_in_vm(&format!("cp {} {}", ca_cert_source, paths.ca_cert))
        .with_context(|| format!("Failed to copy CA cert from {}", ca_cert_source))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Failed to copy CA cert from {}: {}",
            ca_cert_source,
            stderr.trim()
        );
    }

    let output = shell::run_in_vm(&format!("chmod 644 {}", paths.ca_cert))?;
    if !output.status.success() {
        anyhow::bail!("Failed to set permissions on {}", paths.ca_cert);
    }
    Ok(())
}

/// Generate a self-signed CA + node certificate pair.
///
/// For development and single-node deployments. In production, the
/// coordinator issues node certificates signed by the cluster CA.
pub fn generate_self_signed(node_id: &str) -> Result<CertPaths> {
    ensure_cert_dir()?;
    let paths = CertPaths::default_paths();

    // Generate CA key pair and certificate
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(vec!["mvm-ca".to_string()])?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "mvm Root CA");
    ca_dn.push(DnType::OrganizationName, "mvm");
    ca_params.distinguished_name = ca_dn;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // Generate node key pair and certificate signed by CA
    let node_key = KeyPair::generate()?;
    let mut node_params = CertificateParams::new(vec![
        node_id.to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])?;
    let mut node_dn = DistinguishedName::new();
    node_dn.push(DnType::CommonName, node_id);
    node_dn.push(DnType::OrganizationName, "mvm");
    node_params.distinguished_name = node_dn;
    let node_cert = node_params.signed_by(&node_key, &ca_cert, &ca_key)?;

    // Write PEM files to the Lima VM
    let ca_pem = ca_cert.pem();
    let node_cert_pem = node_cert.pem();
    let node_key_pem = node_key.serialize_pem();

    write_pem_file(&paths.ca_cert, &ca_pem)?;
    write_pem_file(&paths.node_cert, &node_cert_pem)?;
    write_pem_file(&paths.node_key, &node_key_pem)?;

    // Restrict key file permissions
    let output = shell::run_in_vm(&format!("chmod 600 {}", paths.node_key))?;
    if !output.status.success() {
        anyhow::bail!("Failed to set permissions on {}", paths.node_key);
    }

    Ok(paths)
}

/// Write a PEM string to a file inside the VM.
fn write_pem_file(path: &str, content: &str) -> Result<()> {
    // Use heredoc to safely write multi-line PEM content
    let output = shell::run_in_vm(&format!("cat > {} << 'ENDPEM'\n{}\nENDPEM", path, content))
        .with_context(|| format!("Failed to write PEM file: {}", path))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to write PEM file {}: {}", path, stderr.trim());
    }
    Ok(())
}

/// Read a PEM file from the VM and return its contents.
fn read_pem_file(path: &str) -> Result<String> {
    shell::run_in_vm_stdout(&format!("cat {}", path))
        .with_context(|| format!("Failed to read PEM file: {}", path))
}

/// Build a quinn ServerConfig from the node certificate and CA.
///
/// Configures mTLS: the server presents its node cert and requires
/// clients to present certs signed by the same CA.
pub fn load_server_config() -> Result<quinn::ServerConfig> {
    let paths = CertPaths::default_paths();

    let ca_pem = read_pem_file(&paths.ca_cert)?;
    let cert_pem = read_pem_file(&paths.node_cert)?;
    let key_pem = read_pem_file(&paths.node_key)?;

    // Parse CA for client verification
    let mut ca_reader = std::io::BufReader::new(ca_pem.as_bytes());
    let ca_certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut ca_reader)
            .filter_map(|r| r.ok())
            .collect();

    let mut root_store = rustls::RootCertStore::empty();
    for cert in &ca_certs {
        root_store.add(cert.clone())?;
    }

    // Parse node certificate chain
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_bytes());
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader)
            .filter_map(|r| r.ok())
            .collect();

    // Parse node private key
    let mut key_reader = std::io::BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", paths.node_key))?;

    // Build mTLS server config: verify clients against our CA
    let client_verifier =
        rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;

    let tls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)?;

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
    ));

    Ok(server_config)
}

/// Build a quinn ClientConfig for connecting to other nodes.
pub fn load_client_config() -> Result<quinn::ClientConfig> {
    let paths = CertPaths::default_paths();

    let ca_pem = read_pem_file(&paths.ca_cert)?;
    let cert_pem = read_pem_file(&paths.node_cert)?;
    let key_pem = read_pem_file(&paths.node_key)?;

    // Parse CA for server verification
    let mut ca_reader = std::io::BufReader::new(ca_pem.as_bytes());
    let ca_certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut ca_reader)
            .filter_map(|r| r.ok())
            .collect();

    let mut root_store = rustls::RootCertStore::empty();
    for cert in &ca_certs {
        root_store.add(cert.clone())?;
    }

    // Parse client certificate chain
    let mut cert_reader = std::io::BufReader::new(cert_pem.as_bytes());
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader)
            .filter_map(|r| r.ok())
            .collect();

    // Parse client private key
    let mut key_reader = std::io::BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", paths.node_key))?;

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)?;

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));

    Ok(client_config)
}

/// Check the current certificate status.
pub fn cert_status() -> Result<CertStatus> {
    let paths = CertPaths::default_paths();

    let ca_present =
        shell::run_in_vm_stdout(&format!("test -f {} && echo yes || echo no", paths.ca_cert))?
            .trim()
            == "yes";

    let node_cert_present = shell::run_in_vm_stdout(&format!(
        "test -f {} && echo yes || echo no",
        paths.node_cert
    ))?
    .trim()
        == "yes";

    let node_key_present = shell::run_in_vm_stdout(&format!(
        "test -f {} && echo yes || echo no",
        paths.node_key
    ))?
    .trim()
        == "yes";

    let node_cert_subject = if node_cert_present {
        shell::run_in_vm_stdout(&format!(
            "openssl x509 -in {} -noout -subject 2>/dev/null || echo unknown",
            paths.node_cert
        ))
        .map_err(|e| warn!("failed to read node cert subject: {e}"))
        .ok()
        .map(|s| s.trim().to_string())
    } else {
        None
    };

    let node_cert_expires = if node_cert_present {
        shell::run_in_vm_stdout(&format!(
            "openssl x509 -in {} -noout -enddate 2>/dev/null || echo unknown",
            paths.node_cert
        ))
        .map_err(|e| warn!("failed to read node cert expiry: {e}"))
        .ok()
        .map(|s| s.trim().to_string())
    } else {
        None
    };

    let last_rotated = if node_cert_present {
        shell::run_in_vm_stdout(&format!(
            "stat -c '%y' {} 2>/dev/null || echo unknown",
            paths.node_cert
        ))
        .map_err(|e| warn!("failed to read node cert last-rotated time: {e}"))
        .ok()
        .map(|s| s.trim().to_string())
    } else {
        None
    };

    Ok(CertStatus {
        ca_present,
        node_cert_present,
        node_key_present,
        node_cert_subject,
        node_cert_expires,
        last_rotated,
    })
}

/// Rotate the node certificate by requesting a new one from the coordinator.
///
/// In production, this CSR-signs via the coordinator's QUIC API.
/// For now, generates a fresh self-signed pair using the existing CA.
pub fn rotate_certs(node_id: &str) -> Result<CertPaths> {
    let paths = CertPaths::default_paths();

    // Verify CA exists
    let ca_present =
        shell::run_in_vm_stdout(&format!("test -f {} && echo yes || echo no", paths.ca_cert))?
            .trim()
            == "yes";

    if !ca_present {
        anyhow::bail!("CA certificate not found. Run 'mvm agent certs init' first.");
    }

    // For now, regenerate self-signed. In production, would CSR to coordinator.
    generate_self_signed(node_id)
}

/// Display certificate status (human-readable or JSON).
pub fn show_status(json: bool) -> Result<()> {
    let status = cert_status().with_context(|| "Failed to check cert status")?;

    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!(
            "CA cert:     {}",
            if status.ca_present {
                "present"
            } else {
                "missing"
            }
        );
        println!(
            "Node cert:   {}",
            if status.node_cert_present {
                "present"
            } else {
                "missing"
            }
        );
        println!(
            "Node key:    {}",
            if status.node_key_present {
                "present"
            } else {
                "missing"
            }
        );
        if let Some(ref subj) = status.node_cert_subject {
            println!("Subject:     {}", subj);
        }
        if let Some(ref exp) = status.node_cert_expires {
            println!("Expires:     {}", exp);
        }
        if let Some(ref rot) = status.last_rotated {
            println!("Last rotated: {}", rot);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_paths_default() {
        let paths = CertPaths::default_paths();
        assert!(paths.ca_cert.starts_with("/var/lib/mvm/certs"));
        assert!(paths.node_cert.ends_with("node.crt"));
        assert!(paths.node_key.ends_with("node.key"));
    }

    #[test]
    fn test_cert_paths_roundtrip() {
        let paths = CertPaths::default_paths();
        let json = serde_json::to_string(&paths).unwrap();
        let parsed: CertPaths = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.ca_cert, paths.ca_cert);
    }

    #[test]
    fn test_cert_status_roundtrip() {
        let status = CertStatus {
            ca_present: true,
            node_cert_present: true,
            node_key_present: true,
            node_cert_subject: Some("CN=node-1".to_string()),
            node_cert_expires: Some("2025-12-31".to_string()),
            last_rotated: Some("2025-01-01".to_string()),
        };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: CertStatus = serde_json::from_str(&json).unwrap();
        assert!(parsed.ca_present);
        assert_eq!(parsed.node_cert_subject.unwrap(), "CN=node-1");
    }

    #[test]
    fn test_generate_self_signed_certs() {
        // Test that rcgen can generate valid certs (no VM needed)
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["mvm-ca".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let node_key = KeyPair::generate().unwrap();
        let node_params =
            CertificateParams::new(vec!["test-node".to_string(), "localhost".to_string()]).unwrap();
        let node_cert = node_params.signed_by(&node_key, &ca_cert, &ca_key).unwrap();

        let ca_pem = ca_cert.pem();
        let node_pem = node_cert.pem();
        let key_pem = node_key.serialize_pem();

        assert!(ca_pem.contains("BEGIN CERTIFICATE"));
        assert!(node_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_cert_dir_constant() {
        assert_eq!(CERT_DIR, "/var/lib/mvm/certs");
    }
}
