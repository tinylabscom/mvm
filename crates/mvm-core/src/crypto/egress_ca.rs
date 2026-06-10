//! Plan 129 Stage 2 (ADR-006) — the per-VM **name-constrained** egress CA.
//!
//! Transparent `https` substitution terminates TLS at the host for **bound
//! hosts only**. To do that without the rejected blanket-MITM, each VM gets a
//! freshly-minted **intermediate** CA whose X.509 `nameConstraints permitted`
//! is exactly the plan's bound hosts. The guest trusts only that per-run
//! intermediate cert (never the host CA, never any private key); the terminator
//! holds the intermediate key and mints a leaf per SNI on the fly.
//!
//! Trust chain: long-lived **host CA** (`<dir>/ca.crt` + `ca.key`, key mode
//! 0400) → per-VM **intermediate** (`CA:TRUE, pathlen:0`, name-constrained) →
//! per-SNI **leaf**.
//!
//! **Honest boundary (ADR-006 §rationale):** Python `ssl` and older Node do not
//! enforce X.509 `nameConstraints` client-side, so the in-guest cert constraint
//! is defense-in-depth, NOT the egress control. The real boundary stays the
//! host-side allow-list check in `prepare_request` (claim 12). The constraint
//! only bounds blast radius if a per-VM intermediate key ever leaked.

use std::fs;
use std::io;
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, GeneralSubtree, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, NameConstraints,
};

/// Errors minting or loading egress CA material. Opaque strings around the
/// `rcgen`/IO causes; no key bytes ever appear in an error.
#[derive(Debug, thiserror::Error)]
pub enum EgressCaError {
    #[error("egress CA io: {0}")]
    Io(String),
    #[error("egress CA cert generation: {0}")]
    Gen(String),
    #[error("egress CA parse: {0}")]
    Parse(String),
}

impl From<io::Error> for EgressCaError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.to_string())
    }
}
impl From<rcgen::Error> for EgressCaError {
    fn from(e: rcgen::Error) -> Self {
        Self::Gen(e.to_string())
    }
}

const CA_CERT_FILE: &str = "ca.crt";
const CA_KEY_FILE: &str = "ca.key";

/// The long-lived host egress CA. Self-signed `CA:TRUE`; signs each VM's
/// name-constrained intermediate. The key lives only in this process's address
/// space + on disk at mode 0400 — it never reaches a guest.
pub struct EgressCa {
    cert_pem: String,
    key: KeyPair,
}

// allow(secret-debug): the keypair is a private key; never derive Debug/Display.
impl std::fmt::Debug for EgressCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressCa")
            .field("cert_pem", &"<ca cert>")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl EgressCa {
    /// Load the host CA from `<dir>/{ca.crt,ca.key}`, or mint + persist a fresh
    /// one if absent. The key file is written mode 0400 (owner read-only).
    pub fn load_or_init_at(dir: &Path) -> Result<Self, EgressCaError> {
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        if cert_path.is_file() && key_path.is_file() {
            let cert_pem = fs::read_to_string(&cert_path)?;
            let key_pem = fs::read_to_string(&key_path)?;
            let key =
                KeyPair::from_pem(&key_pem).map_err(|e| EgressCaError::Parse(e.to_string()))?;
            return Ok(Self { cert_pem, key });
        }
        fs::create_dir_all(dir)?;
        let (cert_pem, key) = mint_host_ca()?;
        write_private(&key_path, key.serialize_pem().as_bytes())?;
        write_atomic(&cert_path, cert_pem.as_bytes())?;
        Ok(Self { cert_pem, key })
    }

    /// The host CA's PEM cert (no key). Safe to log/inspect.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Mint a fresh per-VM intermediate (`CA:TRUE, pathlen:0`) whose
    /// `nameConstraints permitted` is exactly `bound_hosts` (DNS). Only the
    /// returned cert ever leaves the host; the key stays in [`VmIntermediate`].
    pub fn mint_vm_intermediate(
        &self,
        bound_hosts: &[&str],
    ) -> Result<VmIntermediate, EgressCaError> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params
            .distinguished_name
            .push(DnType::CommonName, "mvm per-VM egress intermediate");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: bound_hosts.iter().map(|h| dns_subtree(h)).collect(),
            excluded_subtrees: Vec::new(),
        });
        // The host CA signs this intermediate (issuer DN + key from the
        // persisted CA PEM + key).
        let cert = params.signed_by(&key, &self.issuer()?)?;
        Ok(VmIntermediate {
            cert_pem: cert.pem(),
            key,
        })
    }

    fn issuer(&self) -> Result<Issuer<'static, KeyPair>, EgressCaError> {
        let key = KeyPair::from_pem(&self.key.serialize_pem())
            .map_err(|e| EgressCaError::Parse(e.to_string()))?;
        Issuer::from_ca_cert_pem(&self.cert_pem, key).map_err(EgressCaError::from)
    }
}

/// A per-VM intermediate CA: its cert goes to the guest's trust bundle, its key
/// stays host-side (in the terminator endpoint) to mint per-SNI leaves.
pub struct VmIntermediate {
    cert_pem: String,
    key: KeyPair,
}

impl std::fmt::Debug for VmIntermediate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmIntermediate")
            .field("cert_pem", &"<intermediate cert>")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl VmIntermediate {
    /// The intermediate's PEM cert — the only piece delivered to the guest.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The intermediate's private key PEM — terminator-side only, never to a
    /// guest. Caller treats this as a secret (mode 0400 if persisted).
    pub fn key_pem(&self) -> String {
        self.key.serialize_pem()
    }

    /// Mint a leaf cert for `sni`, signed by this intermediate. Refused by a
    /// conforming verifier when `sni` is outside the intermediate's
    /// `nameConstraints` (defense in depth — claim 12 is the real boundary).
    pub fn mint_leaf(&self, sni: &str) -> Result<Leaf, EgressCaError> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![sni.to_string()])?;
        params.is_ca = IsCa::ExplicitNoCa;
        params
            .distinguished_name
            .push(DnType::CommonName, sni.to_string());
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        // Signed by this intermediate (issuer DN + key from the delivered
        // intermediate cert, so the leaf chains to it).
        let cert = params.signed_by(&key, &self.issuer()?)?;
        Ok(Leaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        })
    }

    fn issuer(&self) -> Result<Issuer<'static, KeyPair>, EgressCaError> {
        let key = KeyPair::from_pem(&self.key.serialize_pem())
            .map_err(|e| EgressCaError::Parse(e.to_string()))?;
        Issuer::from_ca_cert_pem(&self.cert_pem, key).map_err(EgressCaError::from)
    }
}

/// A per-SNI leaf the terminator presents to the guest's TLS client.
pub struct Leaf {
    pub cert_pem: String,
    pub key_pem: String,
}

impl std::fmt::Debug for Leaf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Leaf")
            .field("cert_pem", &"<leaf cert>")
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

fn dns_subtree(host: &str) -> GeneralSubtree {
    GeneralSubtree::DnsName(host.to_string())
}

fn mint_host_ca() -> Result<(String, KeyPair), EgressCaError> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "mvm egress root CA");
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key))
}

/// Write a private key file at mode 0400 (owner read-only) on Unix, via
/// tmp-and-rename so a reader never sees a partial key.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), EgressCaError> {
    let tmp = path.with_extension("tmp");
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o400)
                .open(&tmp)?;
            io::Write::write_all(&mut f, bytes)?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&tmp, bytes)?;
        }
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), EgressCaError> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn host_ca_is_self_signed_ca_true() {
        let dir = tempdir().unwrap();
        let ca = EgressCa::load_or_init_at(dir.path()).unwrap();
        assert!(dir.path().join(CA_CERT_FILE).is_file());
        assert!(dir.path().join(CA_KEY_FILE).is_file());
        // Reload reuses the same persisted cert (deterministic identity).
        let ca2 = EgressCa::load_or_init_at(dir.path()).unwrap();
        assert_eq!(ca.cert_pem(), ca2.cert_pem());
        // It is a CA cert (CA:TRUE basic-constraint present).
        let (_, parsed) = x509_parser::pem::parse_x509_pem(ca.cert_pem().as_bytes()).unwrap();
        let cert = parsed.parse_x509().unwrap();
        assert!(cert.tbs_certificate.is_ca());
    }

    #[cfg(unix)]
    #[test]
    fn ca_key_is_mode_0400() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        EgressCa::load_or_init_at(dir.path()).unwrap();
        let mode = fs::metadata(dir.path().join(CA_KEY_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o400, "CA key must be owner-read-only");
    }

    #[test]
    fn intermediate_is_name_constrained_to_bound_hosts() {
        let dir = tempdir().unwrap();
        let ca = EgressCa::load_or_init_at(dir.path()).unwrap();
        let inter = ca.mint_vm_intermediate(&["api.openai.com"]).unwrap();
        let (_, parsed) = x509_parser::pem::parse_x509_pem(inter.cert_pem().as_bytes()).unwrap();
        let cert = parsed.parse_x509().unwrap();
        assert!(cert.tbs_certificate.is_ca());
        // The intermediate's nameConstraints permits exactly api.openai.com.
        let nc = cert
            .tbs_certificate
            .name_constraints()
            .unwrap()
            .expect("intermediate must carry nameConstraints");
        let permitted: Vec<String> = nc
            .value
            .permitted_subtrees
            .as_ref()
            .unwrap()
            .iter()
            .filter_map(|s| match &s.base {
                x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(permitted, vec!["api.openai.com".to_string()]);
    }

    #[test]
    fn intermediate_refuses_to_sign_a_leaf_for_an_unbound_host() {
        // A conforming verifier (webpki) must reject a leaf for a host outside
        // the intermediate's nameConstraints. Build: host CA → intermediate
        // (permits api.openai.com) → leaf for evil.example.com → verify path.
        let dir = tempdir().unwrap();
        let ca = EgressCa::load_or_init_at(dir.path()).unwrap();
        let inter = ca.mint_vm_intermediate(&["api.openai.com"]).unwrap();
        let bad_leaf = inter.mint_leaf("evil.example.com").unwrap();
        let good_leaf = inter.mint_leaf("api.openai.com").unwrap();
        assert!(
            !verify_leaf_against_intermediate(
                &bad_leaf.cert_pem,
                inter.cert_pem(),
                "evil.example.com"
            ),
            "a leaf for an unbound host must fail name-constraint validation"
        );
        assert!(
            verify_leaf_against_intermediate(
                &good_leaf.cert_pem,
                inter.cert_pem(),
                "api.openai.com"
            ),
            "a leaf for the bound host must validate"
        );
    }

    /// Verify `leaf_pem` chains to `inter_pem` for `sni`, enforcing
    /// nameConstraints — via rustls/webpki path validation (the real verifier,
    /// not field inspection).
    fn verify_leaf_against_intermediate(leaf_pem: &str, inter_pem: &str, sni: &str) -> bool {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use std::time::{SystemTime, UNIX_EPOCH};
        let leaf = der_from_pem(leaf_pem);
        let inter = der_from_pem(inter_pem);
        let mut roots = rustls::RootCertStore::empty();
        if roots.add(CertificateDer::from(inter)).is_err() {
            return false;
        }
        let verifier = match rustls::client::WebPkiServerVerifier::builder_with_provider(
            roots.into(),
            rustls::crypto::ring::default_provider().into(),
        )
        .build()
        {
            Ok(v) => v,
            Err(_) => return false,
        };
        let end_entity = CertificateDer::from(leaf);
        let server_name = ServerName::try_from(sni.to_string()).unwrap();
        let now = UnixTime::since_unix_epoch(SystemTime::now().duration_since(UNIX_EPOCH).unwrap());
        verifier
            .verify_server_cert(&end_entity, &[], &server_name, &[], now)
            .is_ok()
    }

    fn der_from_pem(pem: &str) -> Vec<u8> {
        let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        p.contents
    }
}
