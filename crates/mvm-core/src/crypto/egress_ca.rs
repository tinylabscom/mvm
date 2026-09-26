//! The per-VM **name-constrained** egress CA.
//!
//! Transparent `https` substitution terminates TLS at the host for **bound
//! hosts only**. To do that without the rejected blanket-MITM, each VM gets a
//! freshly-minted CA whose X.509 `nameConstraints permitted` is exactly the
//! plan's bound hosts, a `*.suffix` wildcard carried as the `suffix` subtree.
//! The guest trusts only that per-run certificate (never
//! any private key); the terminator holds the key and mints a leaf per SNI on
//! the fly.
//!
//! The per-VM CA is **self-signed**, so the certificate the guest is handed is
//! a complete trust anchor. A CA chained to a longer-lived root would make the
//! guest's cert a partial chain, and a client whose verifier terminates a chain
//! only at a self-signed certificate — which older OpenSSL builds do unless
//! `X509_V_FLAG_PARTIAL_CHAIN` is set — would reject every terminated flow.
//! The whole point is that an unmodified client works, so the anchor is the
//! thing delivered.
//!
//! Trust chain: per-VM **self-signed CA** (`CA:TRUE, pathlen:0`,
//! name-constrained) → per-SNI **leaf**.
//!
//! **What the constraint is for:** it bounds the blast radius of a leaked
//! per-VM key, and the guest's own verifier does enforce it — OpenSSL's
//! `X509_verify_cert` applies `nameConstraints` from a self-signed trust anchor
//! (a leaf outside the permitted subtrees fails with "permitted subtree
//! violation"), and curl, Python's `ssl` and Node all reach that code. It is
//! still **not** the egress control: whether a flow is admitted at all is
//! decided host-side by the allow-list check in `prepare_request` (claim 12),
//! before any certificate is minted.

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
    #[error(
        "egress CA name constraint: `{0}` is a wildcard over a single DNS label, \
         which would permit a whole top-level domain"
    )]
    TopLevelWildcard(String),
}

impl From<std::io::Error> for EgressCaError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}
impl From<rcgen::Error> for EgressCaError {
    fn from(e: rcgen::Error) -> Self {
        Self::Gen(e.to_string())
    }
}

/// Subject CN of every per-VM CA.
const VM_CA_CN: &str = "mvm per-VM egress CA";

/// Rebuild the signer identity for a certificate this module minted.
///
/// `Issuer` carries exactly three things out of `CertificateParams` — the
/// distinguished name, the key-identifier method, and the key usages — so the
/// signer is fully determined by the values the cert was minted with. Rebuilding
/// them is what `Issuer::from_ca_cert_pem` does the long way round: it re-parses
/// a PEM we just serialized in order to recover those same three fields, and it
/// costs rcgen's entire `x509-parser` ASN.1 stack. Nothing here reads the
/// serial, the validity window, or the name constraints, because a leaf inherits
/// none of them — the constraints live in the CA's own certificate, which is
/// minted once and delivered verbatim.
fn ca_issuer_params(common_name: &str) -> Result<CertificateParams, EgressCaError> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Ok(params)
}

/// A per-VM egress CA: its cert goes to the guest's trust bundle, its key stays
/// host-side (in the terminator endpoint) to mint per-SNI leaves.
pub struct VmEgressCa {
    cert_pem: String,
    key: KeyPair,
}

// allow(secret-debug): the keypair is a private key; never derive Debug/Display.
impl std::fmt::Debug for VmEgressCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmEgressCa")
            .field("cert_pem", &"<egress ca cert>")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl VmEgressCa {
    /// Mint a fresh self-signed per-VM CA (`CA:TRUE, pathlen:0`) whose
    /// `nameConstraints permitted` holds one DNS subtree per distinct
    /// `bound_hosts` entry — see [`dns_subtrees`] for how a `*.` pattern
    /// lowers. Only the certificate ever leaves the host; the key stays in
    /// this value.
    ///
    /// Refuses a wildcard over a single label (`*`, `*.com`) rather than mint
    /// a CA that could speak for a whole top-level domain.
    pub fn mint(bound_hosts: &[&str]) -> Result<Self, EgressCaError> {
        let permitted_subtrees = dns_subtrees(bound_hosts)?;
        let key = KeyPair::generate()?;
        let mut params = ca_issuer_params(VM_CA_CN)?;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees,
            excluded_subtrees: Vec::new(),
        });
        let cert = params.self_signed(&key)?;
        Ok(Self {
            cert_pem: cert.pem(),
            key,
        })
    }

    /// Reconstruct a CA from its delivered PEMs. The transparent `https`
    /// terminator rebuilds the minter from `EndpointConfig.tls_intermediate`
    /// (cert+key) at admission to mint per-SNI leaves — the key never left the
    /// host. `cert_pem` is retained verbatim so minted leaves chain to exactly
    /// the cert the guest trusts.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, EgressCaError> {
        let key = KeyPair::from_pem(key_pem).map_err(|e| EgressCaError::Parse(e.to_string()))?;
        Ok(Self {
            cert_pem: cert_pem.to_string(),
            key,
        })
    }

    /// The CA's PEM cert — the only piece delivered to the guest.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA's private key PEM — terminator-side only, never to a guest.
    /// Caller treats this as a secret (owner-only mode if persisted).
    pub fn key_pem(&self) -> String {
        self.key.serialize_pem()
    }

    /// Mint a leaf cert for `sni`, signed by this CA. Refused by a conforming
    /// verifier when `sni` is outside the CA's `nameConstraints` (defense in
    /// depth — claim 12 is the real boundary).
    pub fn mint_leaf(&self, sni: &str) -> Result<Leaf, EgressCaError> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![sni.to_string()])?;
        params.is_ca = IsCa::ExplicitNoCa;
        params
            .distinguished_name
            .push(DnType::CommonName, sni.to_string());
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        // Signed by this CA (issuer DN + key from the delivered cert, so the
        // leaf chains to it).
        let cert = params.signed_by(&key, &self.issuer()?)?;
        Ok(Leaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        })
    }

    fn issuer(&self) -> Result<Issuer<'static, KeyPair>, EgressCaError> {
        let key = KeyPair::from_pem(&self.key.serialize_pem())
            .map_err(|e| EgressCaError::Parse(e.to_string()))?;
        Ok(Issuer::new(ca_issuer_params(VM_CA_CN)?, key))
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

/// The permitted `dNSName` subtrees for a set of binding patterns, one per
/// distinct subtree, in first-seen order.
///
/// A `*.example.com` pattern lowers to the `example.com` subtree: a `dNSName`
/// constraint cannot carry a wildcard label, and verifiers reject one that
/// does as malformed. The `example.com` subtree permits every depth of left
/// label, exactly as the pattern does, and additionally the apex
/// `example.com`, which the pattern does not. That is the same looseness an
/// exact host already has — the `api.openai.com` subtree also permits
/// `x.api.openai.com`. The certificate is therefore not the boundary: a flow
/// is terminated only for a destination the binding itself admits, and that
/// check still excludes the apex. The certificate limits what a leaked per-VM
/// key could impersonate.
fn dns_subtrees(bound_hosts: &[&str]) -> Result<Vec<GeneralSubtree>, EgressCaError> {
    let mut names: Vec<&str> = Vec::with_capacity(bound_hosts.len());
    for pattern in bound_hosts {
        if mvm_contract::ir::host_pattern_is_single_label_wildcard(pattern) {
            return Err(EgressCaError::TopLevelWildcard((*pattern).to_string()));
        }
        let name = mvm_contract::ir::host_pattern_subtree(pattern);
        if !names.iter().any(|seen| seen.eq_ignore_ascii_case(name)) {
            names.push(name);
        }
    }
    Ok(names
        .into_iter()
        .map(|name| GeneralSubtree::DnsName(name.to_string()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_ca_is_self_signed_and_ca_true() {
        let ca = VmEgressCa::mint(&["api.openai.com"]).expect("mint");
        let (_, parsed) = x509_parser::pem::parse_x509_pem(ca.cert_pem().as_bytes()).expect("pem");
        let cert = parsed.parse_x509().expect("x509");
        assert!(cert.tbs_certificate.is_ca());
        assert_eq!(
            cert.tbs_certificate.issuer().to_string(),
            cert.tbs_certificate.subject().to_string(),
            "the certificate handed to the guest must be a complete trust anchor"
        );
    }

    #[test]
    fn debug_redacts_ca_key_and_cert() {
        let ca = VmEgressCa::mint(&["api.openai.com"]).expect("mint");
        let dbg = format!("{ca:?}");
        // The private key PEM must never reach a `{:?}` site.
        assert!(
            !dbg.contains("PRIVATE KEY") && !dbg.contains(&ca.key.serialize_pem()),
            "VmEgressCa Debug leaked private key material: {dbg}"
        );
        // The cert PEM is redacted too (it's not secret, but Debug should stay
        // terse rather than dump a multi-line PEM).
        assert!(!dbg.contains("BEGIN CERTIFICATE"));
        assert!(dbg.contains("<redacted>"), "expected key redaction: {dbg}");
    }

    #[test]
    fn each_mint_draws_a_fresh_ca() {
        let a = VmEgressCa::mint(&["api.openai.com"]).expect("mint");
        let b = VmEgressCa::mint(&["api.openai.com"]).expect("mint");
        assert_ne!(
            a.cert_pem(),
            b.cert_pem(),
            "one VM's terminator must not be able to impersonate another's"
        );
    }

    #[test]
    fn from_pem_reconstructs_a_minter_that_mints_leaves() {
        // The terminator endpoint rebuilds the CA from its delivered PEMs
        // (EndpointConfig.tls_intermediate) and must still mint leaves that
        // chain to the same cert the guest trusts.
        let ca = VmEgressCa::mint(&["api.openai.com"]).expect("mint");

        let rebuilt = VmEgressCa::from_pem(ca.cert_pem(), &ca.key_pem()).expect("rebuild");
        assert_eq!(rebuilt.cert_pem(), ca.cert_pem());
        let leaf = rebuilt.mint_leaf("api.openai.com").expect("mint leaf");
        assert!(leaf.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(leaf.key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn the_ca_is_name_constrained_to_bound_hosts() {
        let ca = VmEgressCa::mint(&["api.openai.com", "api.anthropic.com"]).expect("mint");
        assert_eq!(
            permitted_dns_names(ca.cert_pem()),
            vec![
                "api.openai.com".to_string(),
                "api.anthropic.com".to_string()
            ]
        );
    }

    /// The DNS names a minted CA's `nameConstraints permitted` carries.
    fn permitted_dns_names(cert_pem: &str) -> Vec<String> {
        let (_, parsed) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).expect("pem");
        let cert = parsed.parse_x509().expect("x509");
        let nc = cert
            .tbs_certificate
            .name_constraints()
            .expect("name constraints parse")
            .expect("a per-VM CA must carry nameConstraints");
        nc.value
            .permitted_subtrees
            .as_ref()
            .expect("permitted subtrees")
            .iter()
            .filter_map(|s| match &s.base {
                x509_parser::extensions::GeneralName::DNSName(d) => Some((*d).to_string()),
                _ => None,
            })
            .collect()
    }

    /// The constraint set is not written by hand anywhere: it is whatever the
    /// admitted plan's secret bindings admit, read out of the operator's binding
    /// store. Walk that path rather than passing a literal, so a change to
    /// either end shows up as a certificate that permits the wrong names.
    #[test]
    fn the_name_constraints_cover_exactly_the_plans_bound_hosts() {
        use crate::crypto::secret_binding::{BindingStore, FileBindingStore, SecretBindingMeta};
        use crate::plan::{SecretBinding, SecretSource};

        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileBindingStore::with_dir(dir.path());
        let bind = |name: &str, hosts: Vec<String>| {
            store
                .put(
                    "local",
                    name,
                    &SecretBindingMeta {
                        auth_type: mvm_contract::ir::AuthType::Bearer,
                        allowed_hosts: hosts,
                        sigv4: None,
                        provider: None,
                        approve: Default::default(),
                    },
                )
                .expect("seed the binding store");
        };
        bind("openai", vec!["api.openai.com".into()]);
        bind(
            "anthropic",
            // The duplicate is deliberate: two secrets may name one host, and a
            // certificate that repeats a subtree says the same thing twice.
            vec!["api.anthropic.com".into(), "api.openai.com".into()],
        );
        // A wildcard lowers to its parent's subtree, and an exact host inside
        // that subtree still gets its own entry — only an identical subtree is
        // collapsed.
        bind(
            "search",
            vec![
                "*.search.example.com".into(),
                "api.search.example.com".into(),
                "*.SEARCH.example.com".into(),
            ],
        );
        // Bound by the operator but not named by this plan, so it must not widen
        // the certificate.
        bind("unused", vec!["files.example.com".into()]);

        let plan_secrets = [
            SecretBinding {
                name: "OPENAI_API_KEY".into(),
                source: SecretSource::Keystore {
                    address: "openai".into(),
                },
                destinations: Vec::new(),
            },
            SecretBinding {
                name: "ANTHROPIC_API_KEY".into(),
                source: SecretSource::Keystore {
                    address: "anthropic".into(),
                },
                destinations: Vec::new(),
            },
            SecretBinding {
                name: "SEARCH_API_KEY".into(),
                source: SecretSource::Keystore {
                    address: "search".into(),
                },
                destinations: Vec::new(),
            },
            // Resolved elsewhere, so it contributes no destination here.
            SecretBinding {
                name: "VAULT_TOKEN".into(),
                source: SecretSource::External {
                    provider: "vault".into(),
                    path: "kv/token".into(),
                },
                destinations: Vec::new(),
            },
        ];

        let hosts = crate::crypto::secret_binding::bound_hosts(&plan_secrets, "local", &store)
            .expect("resolve the plan's bound hosts");
        let borrowed: Vec<&str> = hosts.iter().map(String::as_str).collect();
        let ca = VmEgressCa::mint(&borrowed).expect("mint");

        assert_eq!(
            permitted_dns_names(ca.cert_pem()),
            vec![
                "api.openai.com".to_string(),
                "api.anthropic.com".to_string(),
                "search.example.com".to_string(),
                "api.search.example.com".to_string(),
            ],
            "the certificate must permit exactly the subtrees of the destinations \
             the plan's secrets are bound to — no more, no fewer, no repeats"
        );
    }

    #[test]
    fn a_wildcard_binding_lowers_to_its_parent_subtree() {
        let ca = VmEgressCa::mint(&["*.example.com", "api.openai.com"]).expect("mint");
        assert_eq!(
            permitted_dns_names(ca.cert_pem()),
            vec!["example.com".to_string(), "api.openai.com".to_string()],
            "a `*.` label is not a valid dNSName constraint; its parent is the subtree"
        );

        // And a real verifier agrees the subtree covers the wildcard's depth.
        for sni in ["api.example.com", "a.b.example.com"] {
            let leaf = ca.mint_leaf(sni).expect("mint leaf");
            assert!(
                verify_leaf_against_ca(&leaf.cert_pem, ca.cert_pem(), sni),
                "{sni} is under the lowered subtree"
            );
        }
        let outside = ca.mint_leaf("example.org").expect("mint leaf");
        assert!(!verify_leaf_against_ca(
            &outside.cert_pem,
            ca.cert_pem(),
            "example.org"
        ));
    }

    #[test]
    fn a_single_label_wildcard_is_refused_rather_than_constrained_to_a_tld() {
        for pattern in ["*", "*.", "*.com"] {
            let refused = VmEgressCa::mint(&["api.openai.com", pattern])
                .expect_err("a single-label wildcard must not become a constraint");
            assert!(
                refused.to_string().contains(&format!("`{pattern}`")),
                "the refusal names the pattern: {refused}"
            );
        }
    }

    #[test]
    fn the_ca_refuses_to_sign_a_leaf_for_an_unbound_host() {
        // A conforming verifier (webpki) must reject a leaf for a host outside
        // the CA's nameConstraints. Build: CA (permits api.openai.com) → leaf
        // for evil.example.com → verify path.
        let ca = VmEgressCa::mint(&["api.openai.com"]).expect("mint");
        let bad_leaf = ca.mint_leaf("evil.example.com").expect("mint leaf");
        let good_leaf = ca.mint_leaf("api.openai.com").expect("mint leaf");
        assert!(
            !verify_leaf_against_ca(&bad_leaf.cert_pem, ca.cert_pem(), "evil.example.com"),
            "a leaf for an unbound host must fail name-constraint validation"
        );
        assert!(
            verify_leaf_against_ca(&good_leaf.cert_pem, ca.cert_pem(), "api.openai.com"),
            "a leaf for the bound host must validate"
        );
    }

    /// Verify `leaf_pem` chains to `ca_pem` for `sni`, enforcing
    /// nameConstraints — via rustls/webpki path validation (the real verifier,
    /// not field inspection).
    fn verify_leaf_against_ca(leaf_pem: &str, ca_pem: &str, sni: &str) -> bool {
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use std::time::{SystemTime, UNIX_EPOCH};
        let leaf = der_from_pem(leaf_pem);
        let ca = der_from_pem(ca_pem);
        let mut roots = rustls::RootCertStore::empty();
        if roots.add(CertificateDer::from(ca)).is_err() {
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
        let server_name = ServerName::try_from(sni.to_string()).expect("sni parses");
        let now = UnixTime::since_unix_epoch(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock is after the unix epoch"),
        );
        verifier
            .verify_server_cert(&end_entity, &[], &server_name, &[], now)
            .is_ok()
    }

    fn der_from_pem(pem: &str) -> Vec<u8> {
        let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("pem");
        p.contents
    }
}
