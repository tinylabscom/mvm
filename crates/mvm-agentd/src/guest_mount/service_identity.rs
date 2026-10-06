//! Fixed identities for the long-lived helpers the guest init starts as root.

/// The identity a long-lived helper runs under once the root init hands it
/// off: a non-root uid and gid, no supplementary groups, `no_new_privs`, and
/// exactly `capabilities` in its permitted, effective, inheritable, ambient and
/// bounding sets.
///
/// Fields are private and the constructor is visible only to `guest_mount`, so
/// every identity a helper can be given is declared beside the others, where
/// the tests that keep them apart can see them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceIdentity {
    uid: u32,
    gid: u32,
    capabilities: u32,
}

impl ServiceIdentity {
    /// Refuses uid 0 and gid 0. Every identity is a `const` item, so a root
    /// identity is a compile error rather than a guest that boots one.
    pub(super) const fn new(uid: u32, gid: u32, capabilities: u32) -> Self {
        assert!(uid != 0, "a service identity cannot be uid 0");
        assert!(gid != 0, "a service identity cannot be gid 0");
        Self {
            uid,
            gid,
            capabilities,
        }
    }

    /// The uid the helper runs as.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// The gid the helper runs as.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    /// The capability mask the helper keeps.
    #[must_use]
    pub const fn capabilities(&self) -> u32 {
        self.capabilities
    }

    /// Become this identity from root. Async-signal-safe, so it can run in a
    /// `pre_exec` hook between fork and exec.
    #[cfg(target_os = "linux")]
    pub fn assume(&self) -> std::io::Result<()> {
        super::assume_identity_retaining(self.uid, self.gid, self.capabilities)
    }
}

/// Identity of the vsock egress client.
///
/// The egress client parses every SOCKS, HTTP-proxy and DNS request the
/// workload sends and holds the FlowMux signing key, so it gets a uid of its
/// own: the workload cannot signal it, trace it, or read the key, and a
/// compromise of its parsers yields that uid rather than root. It keeps only
/// `CAP_NET_BIND_SERVICE`, for the DNS stub on port 53; the proxy and ICMP
/// mediator ports are above 1024 and vsock needs no capability. mkGuest images
/// reserve the same number.
pub const EGRESS_CLIENT_IDENTITY: ServiceIdentity =
    ServiceIdentity::new(989, 989, 1u32 << super::CAP_NET_BIND_SERVICE);
