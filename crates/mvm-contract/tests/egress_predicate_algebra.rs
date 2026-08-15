//! What the egress policy algebra actually is, pinned.
//!
//! Three properties are worth stating in one place with tests: deny-wins
//! within a grant, union across grants, and default-deny absent any admitting
//! grant. Two of those describe a grammar this repository does not have — `NetworkPolicy` is `Preset | AllowList`, with no negation
//! and no multi-grant composition, and `policy::resolver`'s own documentation
//! says deny-wins "comes online once the sub-policy types grow allow/deny
//! pairs". There is nothing to pin there yet.
//!
//! What *is* real, and was unpinned, is the third property and the one that
//! matters most: **an input the parser does not recognise must refuse, never
//! fall through to a permissive default.** That is the direction a policy
//! parser fails badly in, and the direction nothing was testing.
//!
//! These pin the decision, not merely today's behaviour. An implementation
//! that resolves an unknown preset to anything other than an error is wrong,
//! however reasonable the fallback looks.

use mvm_contract::policy::network_policy::{NetworkPolicy, NetworkPreset};
use std::str::FromStr;

/// An unrecognised preset name raises. It does not fall through to
/// `Unrestricted`, which is the first-declared variant and the one a
/// careless `Default` derive would select.
#[test]
fn an_unknown_preset_refuses_rather_than_falling_through_to_allow() {
    for unknown in ["wide-open", "", "UNRESTRICTED", "all", "default", "any"] {
        let parsed = NetworkPreset::from_str(unknown);
        assert!(
            parsed.is_err(),
            "preset {unknown:?} is not recognised and must refuse, not resolve to a default"
        );
    }
}

/// The same holds through serde, which is the path a signed plan or a policy
/// bundle actually arrives on. A parser that is strict at the CLI and lenient
/// on the wire is strict nowhere that matters.
#[test]
fn serde_also_refuses_an_unknown_preset() {
    for unknown in ["\"wide-open\"", "\"all\"", "\"\""] {
        let parsed: Result<NetworkPreset, _> = serde_json::from_str(unknown);
        assert!(
            parsed.is_err(),
            "preset {unknown} must be refused on the wire as well as at the CLI"
        );
    }
}

/// Case matters. `UNRESTRICTED` is not `unrestricted`; accepting it would mean
/// the set of names that grant network access is larger than the set written
/// down.
#[test]
fn preset_names_are_case_sensitive() {
    assert!(NetworkPreset::from_str("Unrestricted").is_err());
    assert!(NetworkPreset::from_str("None").is_err());
    assert!(NetworkPreset::from_str("unrestricted").is_ok());
    assert!(NetworkPreset::from_str("none").is_ok());
}

/// Every recognised name still resolves, so the refusals above are about an
/// input being unrecognised rather than a parser that rejects everything.
#[test]
fn every_declared_preset_round_trips() {
    for (name, expected) in [
        ("unrestricted", NetworkPreset::Unrestricted),
        ("none", NetworkPreset::None),
        ("registries", NetworkPreset::Registries),
        ("dev", NetworkPreset::Dev),
        ("agent", NetworkPreset::Agent),
    ] {
        assert_eq!(NetworkPreset::from_str(name).unwrap(), expected);
        assert_eq!(
            expected.to_string(),
            name,
            "Display must round-trip FromStr"
        );
    }
}

/// Default-deny, stated as a property of the constructors rather than of a
/// call site. `deny_all` is the safe default and `unrestricted` is not
/// reachable by accident: there is no `Default` impl that could select it.
#[test]
fn deny_all_is_the_restrictive_constructor_and_unrestricted_is_explicit() {
    let deny = NetworkPolicy::deny_all();
    assert!(!deny.is_unrestricted(), "deny_all must not be unrestricted");

    let open = NetworkPolicy::unrestricted();
    assert!(
        open.is_unrestricted(),
        "unrestricted must report itself as such, so a caller can gate on it"
    );

    // An empty allow-list admits nothing. This is the case where a
    // "union across grants" implementation would be tempted to treat the
    // empty set as "unconstrained".
    let empty = NetworkPolicy::allow_list(vec![]);
    assert!(
        !empty.is_unrestricted(),
        "an empty allow-list admits nothing; it is not an absent constraint"
    );
}

/// `trusted_build_egress` is unrestricted, and that is deliberate — but it is
/// a *separate named constructor* so every broad-egress grant is greppable and
/// cannot be confused with a workload policy.
///
/// Pinned because the two being the same value is exactly what would let the
/// distinction quietly disappear in a refactor.
#[test]
fn trusted_build_egress_is_unrestricted_but_separately_named() {
    assert!(NetworkPolicy::trusted_build_egress().is_unrestricted());
    assert_eq!(
        NetworkPolicy::trusted_build_egress(),
        NetworkPolicy::unrestricted(),
        "if these diverge, every caller of the build constructor changes meaning"
    );
}
