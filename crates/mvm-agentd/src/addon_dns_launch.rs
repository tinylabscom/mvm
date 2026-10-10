//! How PID 1 starts the local-addon resolver (`mvm-addon-dns`).
//!
//! An image declares local addons by baking a zone at [`BAKED_ZONE`]. When it
//! does, the initramfs agent starts the resolver from the runtime overlay and
//! points `/etc/resolv.conf` at it; an image without a zone gets nothing, and
//! its resolver configuration stays exactly as built.
//!
//! The resolver listens on a loopback address of its own, [`LISTEN`], rather
//! than `127.0.0.1:53`. On a boot that admitted egress, the egress client's DNS
//! stub already owns `127.0.0.1:53`, and two listeners on one address means
//! whichever binds second has no port. With its own address the resolver
//! answers addon names itself and forwards everything else to that stub, so a
//! guest gets both. A boot without egress forwards to the resolvers the image
//! itself declared, snapshotted before `/etc/resolv.conf` is replaced so the
//! resolver never forwards to itself.
//!
//! This module holds the decisions. The Linux side that copies files, binds
//! mounts and spawns the process lives in `guest_bootstrap`.

/// Where an image bakes its addon zone.
pub const BAKED_ZONE: &str = "/etc/mvm/addon_dns_zone.json";

/// The resolver binary on the runtime overlay. There is no baked fallback.
pub const OVERLAY_BINARY: &str = "/mvm/runtime/addon-dns";

/// The zone copy the resolver reads, on tmpfs so a reload never needs a
/// writable root.
pub const RUN_ZONE: &str = "/run/mvm/addon_dns_zone.json";

/// The image's own resolvers, captured before `/etc/resolv.conf` is replaced.
pub const UPSTREAM_RESOLV: &str = "/run/mvm/upstream-resolv.conf";

/// The resolver configuration bind-mounted over `/etc/resolv.conf`.
pub const RESOLV_CONF: &str = "/run/mvm/resolv.conf";

/// The resolver's listening address: loopback, and not the egress stub's.
pub const LISTEN: &str = "127.0.0.2:53";

/// Where the resolver sends a name it does not own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upstream {
    /// The egress client's DNS stub, which resolves through the host.
    EgressStub,
    /// The resolvers the image declared in its own `/etc/resolv.conf`.
    ImageResolvers,
}

impl Upstream {
    /// The upstream a boot uses: the egress stub whenever the boot runs one.
    #[must_use]
    pub fn for_boot(vsock_egress: bool) -> Self {
        if vsock_egress {
            Self::EgressStub
        } else {
            Self::ImageResolvers
        }
    }

    /// Whether the image's resolvers must be captured before the rewrite.
    #[must_use]
    pub fn needs_snapshot(self) -> bool {
        self == Self::ImageResolvers
    }
}

/// The environment the resolver is started with. Every path and address is
/// passed explicitly, so the binary's own defaults never decide where it
/// listens.
#[must_use]
pub fn launch_env(upstream: Upstream) -> Vec<(&'static str, String)> {
    let mut env = vec![
        ("MVM_ADDON_DNS_BIND_ADDRS", LISTEN.to_string()),
        ("MVM_ADDON_DNS_ZONE_PATH", RUN_ZONE.to_string()),
    ];
    match upstream {
        Upstream::EgressStub => env.push((
            "MVM_ADDON_DNS_UPSTREAM_ADDRS",
            mvm_core::guest_netd::DEFAULT_DNS_STUB_LISTEN.to_string(),
        )),
        Upstream::ImageResolvers => {
            env.push((
                "MVM_ADDON_DNS_UPSTREAM_RESOLV_PATH",
                UPSTREAM_RESOLV.to_string(),
            ));
        }
    }
    env
}

/// The `/etc/resolv.conf` a guest with addons sees.
#[must_use]
pub fn resolv_conf_body() -> String {
    let host = LISTEN.rsplit_once(':').map_or(LISTEN, |(host, _)| host);
    format!("nameserver {host}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn the_listener_is_loopback_and_not_the_egress_stub() {
        let listen: SocketAddr = LISTEN.parse().unwrap();
        let stub: SocketAddr = mvm_core::guest_netd::DEFAULT_DNS_STUB_LISTEN
            .parse()
            .unwrap();
        assert!(listen.ip().is_loopback());
        assert_eq!(listen.port(), 53, "resolv.conf cannot name a port");
        assert_ne!(listen, stub);
    }

    #[test]
    fn an_egress_boot_forwards_to_the_stub_and_snapshots_nothing() {
        let upstream = Upstream::for_boot(true);
        assert_eq!(upstream, Upstream::EgressStub);
        assert!(!upstream.needs_snapshot());
        let env = launch_env(upstream);
        assert!(env.contains(&(
            "MVM_ADDON_DNS_UPSTREAM_ADDRS",
            mvm_core::guest_netd::DEFAULT_DNS_STUB_LISTEN.to_string()
        )));
        assert!(
            !env.iter()
                .any(|(k, _)| *k == "MVM_ADDON_DNS_UPSTREAM_RESOLV_PATH")
        );
    }

    #[test]
    fn a_boot_without_egress_forwards_to_the_image_resolvers() {
        let upstream = Upstream::for_boot(false);
        assert!(upstream.needs_snapshot());
        let env = launch_env(upstream);
        assert!(env.contains(&(
            "MVM_ADDON_DNS_UPSTREAM_RESOLV_PATH",
            UPSTREAM_RESOLV.to_string()
        )));
        assert!(
            !env.iter()
                .any(|(k, _)| *k == "MVM_ADDON_DNS_UPSTREAM_ADDRS")
        );
    }

    /// The server refuses an upstream equal to its own listener; the two
    /// addresses it is handed must never be that pair.
    #[test]
    fn neither_upstream_is_the_resolver_itself() {
        for upstream in [Upstream::EgressStub, Upstream::ImageResolvers] {
            let env = launch_env(upstream);
            let bind = env
                .iter()
                .find(|(k, _)| *k == "MVM_ADDON_DNS_BIND_ADDRS")
                .map(|(_, v)| v.clone())
                .unwrap();
            assert_eq!(bind, LISTEN);
            if let Some((_, up)) = env
                .iter()
                .find(|(k, _)| *k == "MVM_ADDON_DNS_UPSTREAM_ADDRS")
            {
                assert_ne!(up, &bind);
            }
        }
    }

    #[test]
    fn resolv_conf_names_the_listener() {
        assert_eq!(resolv_conf_body(), "nameserver 127.0.0.2\n");
    }
}
