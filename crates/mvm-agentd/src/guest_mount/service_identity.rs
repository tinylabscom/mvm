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
    capabilities: u64,
}

impl ServiceIdentity {
    /// Refuses uid 0 and gid 0. Every identity is a `const` item, so a root
    /// identity is a compile error rather than a guest that boots one.
    pub(super) const fn new(uid: u32, gid: u32, capabilities: u64) -> Self {
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
    pub const fn capabilities(&self) -> u64 {
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
    ServiceIdentity::new(989, 989, 1u64 << super::CAP_NET_BIND_SERVICE);

/// Identity of the declared-command tool helper.
///
/// Linux-only: every consumer (the installer, the helper, the agent's
/// decision socket, the shim's listener check) is Linux-only, and keeping
/// the constant off other targets avoids a dead-code lint that an `allow`
/// would only paper over.
///
/// The helper owns the root-only stash of substituted tool binaries and
/// answers the in-guest shim, so it gets a uid of its own: the workload
/// cannot signal it, pose as it on the agent's decision socket, or read the
/// stash through its credentials. It keeps exactly `CAP_SETUID` and
/// `CAP_SETGID` — the two transitions a mediated tool invocation needs onto
/// [`super::TOOL_UID`] and [`super::TOOL_GID`] — and nothing else.
#[cfg(any(target_os = "linux", test))]
pub const TOOL_HELPER_IDENTITY: ServiceIdentity = ServiceIdentity::new(
    906,
    906,
    (1u64 << super::CAP_SETUID) | (1u64 << super::CAP_SETGID),
);

/// Identity of the local-addon resolver (`mvm-addon-dns`).
///
/// It parses every DNS query the workload sends, so it gets a uid of its own
/// for the same reason the egress client does, and keeps only
/// `CAP_NET_BIND_SERVICE` for its port-53 listener. It holds no key.
pub const ADDON_DNS_IDENTITY: ServiceIdentity =
    ServiceIdentity::new(987, 987, 1u64 << super::CAP_NET_BIND_SERVICE);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tool_helper_keeps_exactly_the_uid_gid_transition_capabilities() {
        let identity = TOOL_HELPER_IDENTITY;
        assert_eq!(identity.uid(), 906);
        assert_eq!(identity.gid(), 906);
        assert_eq!(
            identity.capabilities(),
            (1u64 << super::super::CAP_SETUID) | (1u64 << super::super::CAP_SETGID)
        );
        assert_ne!(identity.uid(), super::super::WORKLOAD_UID);
        assert_ne!(identity.uid(), super::EGRESS_CLIENT_IDENTITY.uid());
        assert_ne!(identity.uid(), super::ADDON_DNS_IDENTITY.uid());
    }

    #[test]
    fn identity_preserves_low_and_high_capability_bits() {
        let mask = (1u64 << super::super::CAP_NET_BIND_SERVICE) | (1u64 << 38) | (1u64 << 39);
        assert_eq!(ServiceIdentity::new(989, 989, mask).capabilities(), mask);
    }
}
