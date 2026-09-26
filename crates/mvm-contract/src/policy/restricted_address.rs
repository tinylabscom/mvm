//! Which destination addresses a workload may not reach by default.
//!
//! One classifier, used by every place that decides whether an address is
//! safe to connect to or to hand back in a DNS answer: the egress decision
//! ([`crate::policy::projection::CanonicalEgress::permits`]), the DNS-answer
//! guard, and the host tools' SSRF guard. Before this there were three lists
//! and they disagreed — one blocked RFC1918, one did not, none looked inside
//! NAT64 or 6to4 addresses.
//!
//! Two tiers:
//!
//! - **Absolute.** Cloud metadata services, loopback, the unspecified and
//!   "this network" block, link-local and carrier-grade NAT. No grant can
//!   re-admit these: there is no workload reason to reach the host's own
//!   services or an instance metadata endpoint, and every one of them is a
//!   classic SSRF target. `0.0.0.0` belongs here because a connect to it
//!   reaches the local host on Linux.
//! - **Private.** RFC1918, IPv6 unique-local, multicast, and the reserved
//!   `240.0.0.0/4` block (broadcast included). Denied by default, and
//!   re-admitted only by a grant that names that address specifically — a
//!   literal IP or CIDR inside the private range, or a host name the operator
//!   allow-listed. A broad grant such as `0.0.0.0/0` or an unrestricted
//!   policy does not name it, so it does not re-admit it.
//!
//! An IPv6 address that embeds an IPv4 one is classified by the IPv4 address
//! it reaches: IPv4-mapped and IPv4-compatible forms, NAT64 (`64:ff9b::/96`
//! and `64:ff9b:1::/48`), 6to4 (`2002::/16`) and Teredo (`2001::/32`). An
//! embedded restricted address is always treated as absolute: nothing names a
//! private host through a translation prefix on purpose.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

/// Why an address is restricted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RestrictedClass {
    /// A cloud instance-metadata endpoint.
    CloudMetadata,
    /// Loopback (`127.0.0.0/8`, `::1`).
    Loopback,
    /// `0.0.0.0/8` or `::` — reaches the local host on Linux.
    Unspecified,
    /// Link-local (`169.254.0.0/16`, `fe80::/10`).
    LinkLocal,
    /// Carrier-grade NAT shared address space (`100.64.0.0/10`).
    SharedAddressSpace,
    /// RFC1918 (`10/8`, `172.16/12`, `192.168/16`).
    Private,
    /// IPv6 unique-local (`fc00::/7`).
    UniqueLocal,
    /// Multicast (`224.0.0.0/4`, `ff00::/8`).
    Multicast,
    /// Reserved (`240.0.0.0/4`), including limited broadcast.
    Reserved,
    /// An IPv4 address carried inside an IPv6 translation or tunnelling
    /// prefix, whose embedded address is itself restricted.
    Embedded,
}

impl RestrictedClass {
    /// Whether an explicit grant naming the address can re-admit it.
    #[must_use]
    pub const fn readmittable(self) -> bool {
        matches!(
            self,
            Self::Private | Self::UniqueLocal | Self::Multicast | Self::Reserved
        )
    }

    /// Stable audit label, one per class. Host-chosen, so a chain entry
    /// carrying it carries nothing the workload sent.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CloudMetadata => "cloud_metadata",
            Self::Loopback => "loopback",
            Self::Unspecified => "unspecified",
            Self::LinkLocal => "link_local",
            Self::SharedAddressSpace => "shared_address_space",
            Self::Private => "private_range",
            Self::UniqueLocal => "unique_local",
            Self::Multicast => "multicast",
            Self::Reserved => "reserved",
            Self::Embedded => "embedded_restricted",
        }
    }

    /// One line for an operator.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::CloudMetadata => "a cloud instance-metadata endpoint",
            Self::Loopback => "loopback",
            Self::Unspecified => "the unspecified / this-network block",
            Self::LinkLocal => "link-local",
            Self::SharedAddressSpace => "carrier-grade NAT shared address space",
            Self::Private => "an RFC1918 private range",
            Self::UniqueLocal => "IPv6 unique-local",
            Self::Multicast => "multicast",
            Self::Reserved => "reserved or broadcast",
            Self::Embedded => "a restricted IPv4 address embedded in an IPv6 prefix",
        }
    }
}

/// The restricted class `ip` falls in, or `None` for an ordinary public
/// address.
#[must_use]
pub fn classify(ip: IpAddr) -> Option<RestrictedClass> {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// Whether `ip` is restricted and no grant can re-admit it.
#[must_use]
pub fn is_absolute(ip: IpAddr) -> bool {
    classify(ip).is_some_and(|class| !class.readmittable())
}

/// Whether a grant for `net` names the restricted address `ip` specifically
/// enough to re-admit it: `ip` is re-admittable, and `net` lies wholly inside
/// the restricted range `ip` belongs to. `10.0.0.5/32` and `10.0.0.0/8` name
/// `10.0.0.5`; `0.0.0.0/0` does not.
#[must_use]
pub fn grant_readmits(net: &IpNet, ip: IpAddr) -> bool {
    let Some(class) = classify(ip) else {
        return true;
    };
    if !class.readmittable() || !net.contains(&ip) {
        return false;
    }
    readmittable_range_of(ip).is_some_and(|range| range.contains(net))
}

/// Whether a grant for `net` lies wholly inside a re-admittable private
/// range, and so re-admits the addresses it covers.
#[must_use]
pub fn names_readmittable_range(net: &IpNet) -> bool {
    readmittable_ranges().any(|range| range.contains(net))
}

/// The re-admittable range `ip` sits in, for [`grant_readmits`].
fn readmittable_range_of(ip: IpAddr) -> Option<IpNet> {
    readmittable_ranges().find(|range| range.contains(&ip))
}

fn readmittable_ranges() -> impl Iterator<Item = IpNet> {
    const RANGES: &[&str] = &[
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "fc00::/7",
        "ff00::/8",
    ];
    RANGES
        .iter()
        .filter_map(|range| range.parse::<IpNet>().ok())
}

fn classify_v4(ip: Ipv4Addr) -> Option<RestrictedClass> {
    let [a, b, ..] = ip.octets();
    // Metadata first: its label is the loudest one a reader can get.
    if is_v4_metadata(ip) {
        return Some(RestrictedClass::CloudMetadata);
    }
    Some(match (a, b) {
        (0, _) => RestrictedClass::Unspecified,
        (127, _) => RestrictedClass::Loopback,
        (169, 254) => RestrictedClass::LinkLocal,
        (100, 64..=127) => RestrictedClass::SharedAddressSpace,
        (10, _) | (172, 16..=31) | (192, 168) => RestrictedClass::Private,
        (224..=239, _) => RestrictedClass::Multicast,
        (240..=255, _) => RestrictedClass::Reserved,
        _ => return None,
    })
}

/// Instance-metadata endpoints reached by IPv4: AWS, GCP, Azure and Oracle
/// (`169.254.169.254`), AWS ECS task metadata (`169.254.170.2`), and Alibaba
/// (`100.100.100.200`).
fn is_v4_metadata(ip: Ipv4Addr) -> bool {
    matches!(
        ip.octets(),
        [169, 254, 169, 254] | [169, 254, 170, 2] | [100, 100, 100, 200]
    )
}

/// AWS's IPv6 instance-metadata endpoint, `fd00:ec2::254`.
const AWS_METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

fn classify_v6(ip: Ipv6Addr) -> Option<RestrictedClass> {
    if ip == AWS_METADATA_V6 {
        return Some(RestrictedClass::CloudMetadata);
    }
    if ip.is_unspecified() {
        return Some(RestrictedClass::Unspecified);
    }
    if ip.is_loopback() {
        return Some(RestrictedClass::Loopback);
    }
    // A mapped address is the IPv4 address itself on a dual-stack socket, so
    // it keeps that address's class — including re-admittability.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    if let Some(v4) = embedded_v4(ip) {
        return classify_v4(v4).map(|_| RestrictedClass::Embedded);
    }
    let first = ip.segments()[0];
    if first & 0xffc0 == 0xfe80 {
        return Some(RestrictedClass::LinkLocal);
    }
    if first & 0xfe00 == 0xfc00 {
        return Some(RestrictedClass::UniqueLocal);
    }
    if first & 0xff00 == 0xff00 {
        return Some(RestrictedClass::Multicast);
    }
    None
}

/// The IPv4 address an IPv6 translation or tunnelling form reaches, if any.
/// The mapped form is handled by the caller.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let low = || Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
    // IPv4-compatible `::a.b.c.d` (deprecated, still routed by some stacks).
    if s[..6] == [0, 0, 0, 0, 0, 0] {
        return Some(low());
    }
    // NAT64 well-known prefix `64:ff9b::/96`.
    if s[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        return Some(low());
    }
    // NAT64 local-use prefix `64:ff9b:1::/48`, with the IPv4 address in the
    // low 32 bits as the common /96 layout places it.
    if s[..3] == [0x0064, 0xff9b, 0x0001] {
        return Some(low());
    }
    // 6to4 `2002:AABB:CCDD::/48`.
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::new(
            (s[1] >> 8) as u8,
            s[1] as u8,
            (s[2] >> 8) as u8,
            s[2] as u8,
        ));
    }
    // Teredo `2001:0000::/32`: the client address is the low 32 bits,
    // bit-inverted.
    if s[0] == 0x2001 && s[1] == 0 {
        let inverted = !((u32::from(s[6]) << 16) | u32::from(s[7]));
        return Some(Ipv4Addr::from(inverted));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn every_required_range_is_classified() {
        use RestrictedClass::*;
        for (addr, class) in [
            ("169.254.169.254", CloudMetadata),
            ("169.254.170.2", CloudMetadata),
            ("100.100.100.200", CloudMetadata),
            ("fd00:ec2::254", CloudMetadata),
            ("127.0.0.1", Loopback),
            ("127.255.0.9", Loopback),
            ("::1", Loopback),
            ("0.0.0.0", Unspecified),
            ("0.1.2.3", Unspecified),
            ("::", Unspecified),
            ("169.254.1.1", LinkLocal),
            ("fe80::1", LinkLocal),
            ("100.64.0.1", SharedAddressSpace),
            ("100.127.255.254", SharedAddressSpace),
            ("10.1.2.3", Private),
            ("172.16.0.1", Private),
            ("172.31.255.255", Private),
            ("192.168.1.1", Private),
            ("fc00::1", UniqueLocal),
            ("fd12:3456::1", UniqueLocal),
            ("224.0.0.1", Multicast),
            ("239.255.255.250", Multicast),
            ("ff02::1", Multicast),
            ("240.0.0.1", Reserved),
            ("255.255.255.255", Reserved),
        ] {
            assert_eq!(classify(ip(addr)), Some(class), "{addr}");
        }
    }

    #[test]
    fn public_addresses_are_not_restricted() {
        for addr in [
            "1.1.1.1",
            "93.184.216.34",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "169.253.255.255",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:93.184.216.34",
            "64:ff9b::5db8:d822",
            "2002:5db8:d822::1",
        ] {
            assert_eq!(classify(ip(addr)), None, "{addr}");
        }
    }

    #[test]
    fn an_embedded_ipv4_form_is_classified_by_the_address_it_reaches() {
        // Mapped keeps the IPv4 class, so a mapped private address can still
        // be named by a grant; the translation forms are absolute.
        assert_eq!(
            classify(ip("::ffff:169.254.169.254")),
            Some(RestrictedClass::CloudMetadata)
        );
        assert_eq!(
            classify(ip("::ffff:10.0.0.1")),
            Some(RestrictedClass::Private)
        );
        for addr in [
            "::169.254.169.254",
            "::127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::7f00:1",
            "64:ff9b:1::a00:1",
            "2002:a9fe:a9fe::1",
            "2002:0a00:0001::",
            // Teredo whose client is 127.0.0.1 (bits inverted).
            "2001:0:4136:e378:8000:63bf:80ff:fffe",
        ] {
            assert_eq!(
                classify(ip(addr)),
                Some(RestrictedClass::Embedded),
                "{addr}"
            );
            assert!(is_absolute(ip(addr)), "{addr}");
        }
    }

    #[test]
    fn metadata_and_loopback_are_absolute_and_private_ranges_are_not() {
        for addr in [
            "169.254.169.254",
            "fd00:ec2::254",
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
            "100.64.0.1",
        ] {
            assert!(is_absolute(ip(addr)), "{addr}");
        }
        for addr in ["10.0.0.1", "192.168.1.1", "fd00::5", "224.0.0.1"] {
            assert!(!is_absolute(ip(addr)), "{addr}");
        }
    }

    #[test]
    fn only_a_grant_inside_the_private_range_readmits_an_address_in_it() {
        let target = ip("10.0.0.5");
        assert!(grant_readmits(&net("10.0.0.5/32"), target));
        assert!(grant_readmits(&net("10.0.0.0/24"), target));
        assert!(grant_readmits(&net("10.0.0.0/8"), target));
        assert!(
            !grant_readmits(&net("0.0.0.0/0"), target),
            "a supernet names nothing"
        );
        assert!(!grant_readmits(&net("8.0.0.0/5"), target));
        assert!(
            !grant_readmits(&net("10.0.1.0/24"), target),
            "must contain it"
        );

        let ula = ip("fd12::1");
        assert!(grant_readmits(&net("fd12::/16"), ula));
        assert!(!grant_readmits(&net("::/0"), ula));

        // Metadata inside ULA and link-local stay out whatever the grant.
        assert!(!grant_readmits(
            &net("fd00:ec2::254/128"),
            ip("fd00:ec2::254")
        ));
        assert!(!grant_readmits(
            &net("169.254.169.254/32"),
            ip("169.254.169.254")
        ));

        // A public address needs no re-admission.
        assert!(grant_readmits(&net("0.0.0.0/0"), ip("1.1.1.1")));
    }
}
