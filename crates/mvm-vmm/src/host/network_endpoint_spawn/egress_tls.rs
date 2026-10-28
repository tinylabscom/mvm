//! Per-VM egress CA delivery and private persistence for warm claims.

use anyhow::{Context, Result, anyhow};
use mvm_core::atomic_io::write_private;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

/// The cert/key split the egress CA exists to enforce. The guest receives only
/// the certificate, so it can trust host-terminated bound-host TLS; the
/// terminator endpoint receives the certificate **and** the key to mint per-SNI
/// leaves. The key never enters a guest — the same claim-13 "no key on the
/// guest" invariant the substitution channel upholds.
///
/// Deliberately **not** `Serialize`. It holds a private key, and a derived
/// `Serialize` would mean any future struct that embeds this one writes that key
/// wherever it is written. The one durable sink is
/// [`persist_egress_tls_delivery`], which converts to a private record of its
/// own; a second sink has to be written on purpose.
#[derive(Clone, PartialEq, Eq)]
pub struct EgressTlsDelivery {
    /// The binding patterns the certificate was minted from — the exact slice,
    /// `*.` wildcards included, whose subtrees its `nameConstraints permitted`
    /// carries. Recorded so a later boot can ask what this CA is allowed to
    /// speak for without re-parsing X.509, using the same matching the binding
    /// check uses.
    bound_hosts: Vec<String>,
    /// The CA cert PEM: delivered to the guest's trust bundle, and what the
    /// endpoint's minted leaves chain to.
    cert_pem: String,
    /// The CA key PEM — terminator-side only, NEVER to a guest. Zeroized when
    /// the last copy drops.
    key_pem: Zeroizing<String>,
}

// Manual redacted Debug: this struct carries the CA private key, so its `Debug`
// must never print key bytes (xtask check-no-display-on-secret-types parity
// with `VmEgressCa`).
// allow(secret-debug): hand-written and redacted below.
impl std::fmt::Debug for EgressTlsDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressTlsDelivery")
            .field("bound_hosts", &self.bound_hosts)
            .field("cert_pem", &"<egress ca cert>")
            .field("key_pem", &"<redacted>")
            .finish()
    }
}

impl EgressTlsDelivery {
    /// The certificate — the only half a guest is ever handed.
    #[must_use]
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The key the terminator mints leaves under.
    #[must_use]
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// The destinations this certificate permits.
    #[must_use]
    pub fn bound_hosts(&self) -> &[String] {
        &self.bound_hosts
    }

    /// The first entry of `wanted` this certificate does not permit, if any.
    ///
    /// Decided by the binding allow-list's own matching over the patterns the
    /// certificate was minted from, so `api.example.com` — or `*.api.example.com`
    /// — is covered by a `*.example.com` mint. Every name that matching admits
    /// lies inside the subtrees the mint wrote, which also hold each wildcard's
    /// apex; the apex is still reported here, because the binding does not
    /// admit it. A conservative answer costs a refusal; a generous one costs a
    /// leaf the guest's own TLS stack rejects, after the flow was admitted.
    #[must_use]
    pub fn first_unpermitted<'a>(&self, wanted: &'a [String]) -> Option<&'a str> {
        wanted
            .iter()
            .find(|host| !mvm_contract::ir::host_is_bound(&self.bound_hosts, host))
            .map(String::as_str)
    }
}

/// The on-disk shape of [`EgressTlsDelivery`].
///
/// Separate from the live value precisely so the key has exactly one
/// serialization site. Private to this module: nothing outside it can name this
/// type, so nothing outside it can grow a second place the key is written.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedEgressCa {
    bound_hosts: Vec<String>,
    cert_pem: String,
    key_pem: String,
}

/// Filename the per-VM egress CA is persisted under, inside the VM's own state
/// dir. Mode 0600: it carries the key.
///
/// A warm child restores its parent's `/run/mvm` out of the parent's memory
/// image and therefore trusts the **parent's** certificate. Its endpoint has to
/// terminate under that same identity, and there is no path back into a running
/// guest's memory to replace the trust bundle — so the parent's CA is persisted
/// here for the claim path to read, exactly as the FlowMux identity is.
pub const EGRESS_CA_STATE_FILE: &str = "egress-ca.json";

/// Mint a fresh per-VM egress CA, name-constrained to `bound_hosts`.
///
/// `bound_hosts` are the destinations the plan's secret bindings admit — the
/// CA's `nameConstraints permitted` is exactly that set, so a leaked per-VM key
/// cannot be used to impersonate any other name to its own guest.
pub fn build_egress_tls_delivery(bound_hosts: &[&str]) -> Result<EgressTlsDelivery> {
    let ca = mvm_core::crypto::egress_ca::VmEgressCa::mint(bound_hosts)
        .map_err(|e| anyhow!("mint the per-VM egress CA: {e}"))?;
    Ok(EgressTlsDelivery {
        // The same slice the certificate's permitted subtrees were built from,
        // so the record and the extension cannot describe different sets.
        bound_hosts: bound_hosts.iter().map(|h| (*h).to_string()).collect(),
        cert_pem: ca.cert_pem().to_string(),
        key_pem: Zeroizing::new(ca.key_pem()),
    })
}

/// Persist this boot's egress CA in the VM's state dir at mode 0600.
///
/// The serialized buffer holds the key, so it is zeroized when it drops, and it
/// reaches disk through [`write_private`] — a mode set at creation on a fresh
/// inode, then renamed into place.
pub fn persist_egress_tls_delivery(state_dir: &Path, delivery: &EgressTlsDelivery) -> Result<()> {
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating {}", state_dir.display()))?;
    let path = state_dir.join(EGRESS_CA_STATE_FILE);
    let record = PersistedEgressCa {
        bound_hosts: delivery.bound_hosts.clone(),
        cert_pem: delivery.cert_pem.clone(),
        key_pem: delivery.key_pem.to_string(),
    };
    let json = Zeroizing::new(
        serde_json::to_vec_pretty(&record).context("serializing the per-VM egress CA")?,
    );
    drop(record);
    write_private(&path, &json).with_context(|| format!("writing {}", path.display()))
}

/// Forget the persisted egress CA. Called when the VM stops, at which point
/// nothing can claim it and the key has no further use.
pub fn forget_egress_tls_delivery(state_dir: &Path) {
    let _ = std::fs::remove_file(state_dir.join(EGRESS_CA_STATE_FILE));
}

/// Load the egress CA a previous boot persisted in `state_dir`.
///
/// `None` when that boot had no bound destination to terminate for; a claim
/// from such a parent inherits nothing and its endpoint stays unterminating.
pub fn load_egress_tls_delivery(state_dir: &Path) -> Result<Option<EgressTlsDelivery>> {
    let path = state_dir.join(EGRESS_CA_STATE_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::Error::from(e).context(format!("reading {}", path.display()))),
    };
    let record: PersistedEgressCa =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(EgressTlsDelivery {
        bound_hosts: record.bound_hosts,
        cert_pem: record.cert_pem,
        // Moving the `String` keeps its allocation, so wrapping it here zeroizes
        // the buffer serde parsed into rather than a copy of it.
        key_pem: Zeroizing::new(record.key_pem),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_delivery_debug_redacts_the_private_key() {
        let delivery = EgressTlsDelivery {
            bound_hosts: vec!["api.openai.com".to_string()],
            cert_pem: "endpoint certificate".to_string(),
            key_pem: Zeroizing::new("never-print-this-private-key".to_string()),
        };

        let rendered = format!("{delivery:?}");
        assert!(rendered.contains("<egress ca cert>"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("never-print-this-private-key"));
    }

    // The whole point of the egress CA: the guest may trust the per-VM cert (to
    // accept host-terminated bound-host TLS), but the KEY must never reach the
    // guest — same claim-13 "no key on the guest" invariant the substitution
    // channel already upholds. Assert the split holds by construction.
    #[test]
    fn egress_tls_delivery_gives_cert_to_guest_key_to_endpoint() {
        let d = build_egress_tls_delivery(&["api.openai.com"]).expect("mint");

        // The endpoint gets BOTH halves (it serves leaves under this CA).
        assert!(d.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(d.key_pem().contains("PRIVATE KEY"));

        // INVARIANT: no private-key material rides along with the certificate,
        // which is the only half a guest is ever handed.
        assert!(
            !d.cert_pem().contains("PRIVATE KEY"),
            "the egress CA key leaked into the guest-delivered certificate"
        );
    }

    /// The recorded host set is the same slice the certificate's permitted
    /// subtrees were built from, so `first_unpermitted` answers for the
    /// certificate without re-parsing it. `mvm-core`'s
    /// `the_name_constraints_cover_exactly_the_plans_bound_hosts` is the other
    /// half: that the extension really carries what `mint` was handed.
    #[test]
    fn the_delivery_records_exactly_the_hosts_it_was_minted_for() {
        let d = build_egress_tls_delivery(&["api.openai.com", "api.anthropic.com"]).expect("mint");
        assert_eq!(d.bound_hosts(), ["api.openai.com", "api.anthropic.com"]);
        assert_eq!(
            d.first_unpermitted(&["api.anthropic.com".to_string()]),
            None,
            "a destination the certificate was minted for is permitted"
        );
        assert_eq!(
            d.first_unpermitted(&[
                "api.openai.com".to_string(),
                "files.example.com".to_string(),
            ]),
            Some("files.example.com"),
            "and one it was not is named"
        );
    }

    // The key-carrying delivery struct must not expose secret bytes via Debug
    // (xtask check-no-display-on-secret-types parity).
    #[test]
    fn egress_tls_delivery_debug_is_redacted() {
        let d = build_egress_tls_delivery(&["api.openai.com"]).expect("mint");
        let dbg = format!("{d:?}");
        assert!(
            !dbg.contains("PRIVATE KEY"),
            "key bytes leaked via Debug: {dbg}"
        );
    }

    #[test]
    fn a_persisted_egress_ca_round_trips_and_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let minted = build_egress_tls_delivery(&["api.openai.com"]).expect("mint");
        persist_egress_tls_delivery(dir.path(), &minted).expect("persist");

        let mode = std::fs::metadata(dir.path().join(EGRESS_CA_STATE_FILE))
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the persisted egress CA carries its key");

        let loaded = load_egress_tls_delivery(dir.path())
            .expect("load")
            .expect("a persisted CA is there");
        assert_eq!(loaded, minted);
    }

    #[test]
    fn persisting_over_a_world_readable_predecessor_leaves_the_key_owner_only() {
        // `OpenOptions::mode()` applies at creation, so a plain write through an
        // existing 0644 file leaves the key at 0644. Rewriting a state dir
        // happens on every warm claim, so this is the common path, not an edge.
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(EGRESS_CA_STATE_FILE);
        std::fs::write(&path, b"{}").expect("seed a predecessor");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("seed its mode");

        let minted = build_egress_tls_delivery(&["api.openai.com"]).expect("mint");
        persist_egress_tls_delivery(dir.path(), &minted).expect("persist");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a rewritten egress CA must not stay readable");
        assert_eq!(
            load_egress_tls_delivery(dir.path())
                .expect("load")
                .expect("a persisted CA is there"),
            minted
        );
    }

    #[test]
    fn a_state_dir_without_a_persisted_egress_ca_loads_as_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(
            load_egress_tls_delivery(dir.path())
                .expect("absence is not an error")
                .is_none()
        );
    }
}
