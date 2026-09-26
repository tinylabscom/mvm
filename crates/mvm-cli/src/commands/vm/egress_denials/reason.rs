//! Why the host refused a workload's egress, and what — if anything — the
//! person running it can do about that.
//!
//! The reason is the fixed label the endpoint wrote into the chain-signed
//! entry. The destination only refines it where the label is the generic
//! `policy_denied` and the destination is an address literal in a restricted
//! range — see [`restricted_class`]. For a destination no grant can ever
//! admit — cloud metadata, loopback, link-local, the SSH port — there is no
//! remedy to offer: naming a flag would suggest the refusal is a missing
//! permission when it is the boundary working.

use mvm_contract::policy::restricted_address::{RestrictedClass, classify as classify_address};
use serde::{Deserialize, Serialize};

/// Refusal labels that are not a decision about the destination: a flow that
/// was admitted and then failed to connect. Shown nowhere as a denial.
const NOT_A_DENIAL: &[&str] = &["connect_failed"];

/// TCP/22 is refused whatever the policy says; SSH never reaches a workload.
const SSH_PORT: u16 = 22;

/// The restricted-address class of `host` when it is an address literal, by
/// the same classifier the egress gate decides with.
///
/// The gate records a restricted address under its own class label, and that
/// label is what [`DenialKind::classify`] reads first. A refusal recorded under
/// the generic `policy_denied` says nothing the remedy can rely on, so the
/// address itself decides: a notice must never offer an allow for the
/// metadata service because the recorded word was not specific enough.
pub(in crate::commands) fn restricted_class(host: &str) -> Option<RestrictedClass> {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    classify_address(host.parse().ok()?)
}

/// What the host decided, in terms of what can be done about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) enum DenialKind {
    /// The network policy does not admit the destination.
    NotAllowed,
    /// A restricted address: never reachable, or denied unless a grant names
    /// it exactly, as its class says.
    Restricted(RestrictedClass),
    /// The SSH port, banned outright.
    SshPort,
    /// More connection attempts than this VM's rate limit allows.
    RateLimited,
    /// A destination the host could not parse.
    Malformed,
    /// A secret-bound destination reached by a flow the host cannot read.
    TypedTransformRequired,
    /// A secret-bound destination the host could not terminate.
    TerminationUnavailable,
    /// Too many host-terminated connections at once.
    TerminationBusy,
    /// Too many concurrent flows for this VM.
    FlowLimit,
    /// A peer name sent through the HTTP substitution path.
    PeerDestination,
    /// A secret placeholder outside a request header.
    PlaceholderMisplaced,
    /// A secret placeholder sent to a destination its secret is not bound to.
    PlaceholderUnbound,
    /// A request the host could not frame as HTTP/1.1.
    Unframeable,
    /// An endpoint route's rule refused the request.
    RouteDenied { route: String },
    /// An endpoint route refused an ambiguous request path.
    AmbiguousPath,
    /// A destination with endpoint rules the host could not inspect.
    RulesUnenforceable,
    /// An `ask` rule nobody was able to answer.
    ApprovalUnavailable,
    /// A refused ICMP echo, with the gate's own wording.
    EchoRefused { detail: String },
    /// A label this build does not know. Shown verbatim, with no remedy.
    Unrecognised { label: String },
}

/// Inputs that decide a [`DenialKind`]: the recorded reason label, the
/// destination's port when it has one, and the route context an endpoint-rule
/// refusal carries.
#[derive(Debug, Clone, Default)]
pub(in crate::commands) struct ReasonInputs<'a> {
    pub label: &'a str,
    /// The destination's host when it has one: an address literal there can
    /// make a generic refusal specific.
    pub host: Option<&'a str>,
    pub port: Option<u16>,
    pub route: Option<&'a str>,
    pub detail: Option<&'a str>,
}

impl DenialKind {
    /// Classify a recorded reason. `None` for a label that records something
    /// other than a refusal.
    pub(in crate::commands) fn classify(inputs: &ReasonInputs<'_>) -> Option<Self> {
        if NOT_A_DENIAL.contains(&inputs.label) {
            return None;
        }
        let generic = matches!(inputs.label, "policy_denied" | "refused");
        let class = RestrictedClass::from_label(inputs.label).or_else(|| {
            generic
                .then(|| inputs.host.and_then(restricted_class))
                .flatten()
        });
        if let Some(class) = class {
            return Some(Self::Restricted(class));
        }
        let kind = match inputs.label {
            "policy_denied" | "refused" if inputs.port == Some(SSH_PORT) => Self::SshPort,
            "policy_denied" | "refused" => Self::NotAllowed,
            "rate_limited" => Self::RateLimited,
            "malformed" => Self::Malformed,
            "typed_transform_required" => Self::TypedTransformRequired,
            "termination_unavailable" | "termination_failed" => Self::TerminationUnavailable,
            "termination_exhausted" => Self::TerminationBusy,
            "resource_exhausted" => Self::FlowLimit,
            "peer_destination" => Self::PeerDestination,
            "placeholder_in_url" | "placeholder_in_body" => Self::PlaceholderMisplaced,
            "placeholder_dropped" => Self::PlaceholderUnbound,
            "unframeable_request" | "pipelined_request" | "authority_mismatch" => Self::Unframeable,
            "route_denied" => Self::RouteDenied {
                route: inputs.route.unwrap_or_default().to_string(),
            },
            "ambiguous_path" => Self::AmbiguousPath,
            "endpoint_rules_unenforceable" => Self::RulesUnenforceable,
            "approval_unavailable" => Self::ApprovalUnavailable,
            "echo_refused" => Self::EchoRefused {
                detail: inputs.detail.unwrap_or_default().to_string(),
            },
            other => Self::Unrecognised {
                label: other.to_string(),
            },
        };
        Some(kind)
    }

    /// A few words on why, for the line that reports the refusal.
    pub(in crate::commands) fn describe(&self) -> String {
        match self {
            Self::NotAllowed => "not in the allow-list".into(),
            Self::Restricted(class) => class.describe().into(),
            Self::SshPort => "SSH port".into(),
            Self::RateLimited => "connection rate limit".into(),
            Self::Malformed => "unparseable destination".into(),
            Self::TypedTransformRequired => "secret-bound destination, opaque flow".into(),
            Self::TerminationUnavailable => "secret-bound destination, not terminated".into(),
            Self::TerminationBusy => "too many host-terminated connections".into(),
            Self::FlowLimit => "too many concurrent connections".into(),
            Self::PeerDestination => "peer name over the HTTP proxy".into(),
            Self::PlaceholderMisplaced => "secret placeholder outside a header".into(),
            Self::PlaceholderUnbound => "secret placeholder to an unbound destination".into(),
            Self::Unframeable => "request the host could not read as HTTP/1.1".into(),
            Self::RouteDenied { .. } => "refused by an endpoint route".into(),
            Self::AmbiguousPath => "ambiguous request path".into(),
            Self::RulesUnenforceable => "endpoint rules need interception".into(),
            Self::ApprovalUnavailable => "needs approval, no approver".into(),
            Self::EchoRefused { .. } => "echo not admitted".into(),
            Self::Unrecognised { label } => format!("refused: {label}"),
        }
    }

    /// What can be done about it, for the destination `subject` names.
    pub(in crate::commands) fn remedy(&self, allow_target: Option<&str>) -> Remedy {
        let flag = |target: &str| format!("--allow-host {target}");
        match self {
            Self::NotAllowed => match allow_target {
                Some(target) => Remedy::AllowHost { flag: flag(target) },
                None => Remedy::Advice {
                    text: "the network policy does not admit it".into(),
                },
            },
            Self::Restricted(class) if class.readmittable() => match allow_target {
                Some(target) => Remedy::NameExplicitly { flag: flag(target) },
                None => Remedy::Never {
                    why: "denied by default; only a grant naming the exact address admits it"
                        .into(),
                },
            },
            Self::Restricted(_) => Remedy::Never {
                why: "never reachable from a workload; no grant admits it".into(),
            },
            Self::SshPort => Remedy::Never {
                why: "SSH (TCP/22) never reaches a workload; no grant admits it".into(),
            },
            Self::RouteDenied { route } => Remedy::EditRoute {
                route: route.clone(),
            },
            Self::AmbiguousPath => Remedy::Never {
                why: "a path with encoded separators or dot segments is refused under endpoint \
                      rules; send the canonical path"
                    .into(),
            },
            other => Remedy::Advice {
                text: other.advice().into(),
            },
        }
    }

    /// The explanation for a refusal that no allow-list entry changes.
    fn advice(&self) -> &'static str {
        match self {
            Self::RateLimited => "the workload opened connections faster than this VM allows",
            Self::Malformed => "the host could not parse the destination",
            Self::TypedTransformRequired => {
                "a secret is bound there, so only HTTP requests the host can read are forwarded"
            }
            Self::TerminationUnavailable => {
                "a secret is bound there and the host could not terminate the connection to \
                 substitute it"
            }
            Self::TerminationBusy => "retry with fewer simultaneous connections to it",
            Self::FlowLimit => "this VM reached its concurrent-connection limit",
            Self::PeerDestination => "peers are reached over TCP, not through the HTTP proxy",
            Self::PlaceholderMisplaced => {
                "a secret placeholder is substituted only in a request header"
            }
            Self::PlaceholderUnbound => {
                "that secret is not bound to this destination; bind it with --secret NAME:HOST \
                 only if it should go there"
            }
            Self::Unframeable => "the request was not a single well-formed HTTP/1.1 request",
            Self::RulesUnenforceable => {
                "its endpoint route has method/path rules the host enforces only by \
                 intercepting; set intercept = true on that route"
            }
            Self::ApprovalUnavailable => {
                "an `ask` rule matched and no approver is configured, so it was refused"
            }
            Self::EchoRefused { .. } => "the network policy does not admit echo to it",
            _ => "refused by the host",
        }
    }

    /// Whether the remedy is an allow-list entry the summary can collect into
    /// one re-run command.
    pub(in crate::commands) fn is_plain_allow(&self) -> bool {
        matches!(self, Self::NotAllowed)
    }

    /// Whether it is denied by default and admitted only by a grant naming
    /// the exact address — listed apart from the plain allows.
    pub(in crate::commands) fn is_named_only(&self) -> bool {
        matches!(self, Self::Restricted(class) if class.readmittable())
    }
}

/// What the person running the workload can do. Serialized as the `remedy` of
/// a `--json` denial record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(in crate::commands) enum Remedy {
    /// Admit it on the next run with this flag.
    AllowHost { flag: String },
    /// Denied by default; naming this exact destination admits it.
    NameExplicitly { flag: String },
    /// An endpoint route refused it; its rules decide.
    EditRoute { route: String },
    /// No grant admits it.
    Never { why: String },
    /// Not a permission problem.
    Advice { text: String },
}

impl Remedy {
    /// The remedy as it reads after the dash of a notice line.
    pub(in crate::commands) fn render(&self, target_has_port: bool) -> String {
        match self {
            Self::AllowHost { flag } if target_has_port => format!("allow with {flag}"),
            Self::AllowHost { flag } => {
                format!("allow with {flag} (port 443; add :PORT for another)")
            }
            Self::NameExplicitly { flag } => {
                format!("denied by default; admitted only by naming it exactly: {flag}")
            }
            Self::EditRoute { route } if route.is_empty() => {
                "change the matching endpoint route's rules ([[network.routes]] in mvm.toml, or \
                 --allow-endpoint)"
                    .to_string()
            }
            Self::EditRoute { route } => format!(
                "change the rules of endpoint route `{route}` ([[network.routes]] in mvm.toml, or \
                 --allow-endpoint)"
            ),
            Self::Never { why } => why.clone(),
            Self::Advice { text } => text.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(label: &str, port: Option<u16>) -> DenialKind {
        DenialKind::classify(&ReasonInputs {
            label,
            port,
            ..Default::default()
        })
        .unwrap_or_else(|| panic!("{label} is a denial"))
    }

    /// Every label the endpoint records for a refusal. A label missing here
    /// would render as "refused: <label>" with no remedy.
    const EVERY_REFUSAL_LABEL: &[&str] = &[
        "policy_denied",
        "refused",
        "rate_limited",
        "malformed",
        "typed_transform_required",
        "termination_unavailable",
        "termination_failed",
        "termination_exhausted",
        "resource_exhausted",
        "peer_destination",
        "placeholder_in_url",
        "placeholder_in_body",
        "placeholder_dropped",
        "unframeable_request",
        "pipelined_request",
        "authority_mismatch",
        "cloud_metadata",
        "loopback",
        "unspecified",
        "link_local",
        "shared_address_space",
        "embedded_restricted",
        "private_range",
        "unique_local",
        "multicast",
        "reserved",
        "route_denied",
        "ambiguous_path",
        "endpoint_rules_unenforceable",
        "approval_unavailable",
        "echo_refused",
    ];

    #[test]
    fn every_recorded_refusal_label_has_a_meaning_and_a_remedy() {
        for label in EVERY_REFUSAL_LABEL {
            let kind = classify(label, Some(443));
            assert!(
                !matches!(kind, DenialKind::Unrecognised { .. }),
                "{label} is unrecognised"
            );
            assert!(!kind.describe().is_empty(), "{label}");
            let remedy = kind.remedy(Some("h:443")).render(true);
            assert!(!remedy.is_empty(), "{label}");
        }
    }

    #[test]
    fn a_policy_refusal_is_remedied_by_the_exact_allow_host_flag() {
        let kind = classify("policy_denied", Some(443));
        assert_eq!(kind, DenialKind::NotAllowed);
        assert_eq!(kind.describe(), "not in the allow-list");
        assert_eq!(
            kind.remedy(Some("api.example.com:443")),
            Remedy::AllowHost {
                flag: "--allow-host api.example.com:443".into()
            }
        );
        assert_eq!(
            kind.remedy(Some("api.example.com:443")).render(true),
            "allow with --allow-host api.example.com:443"
        );
    }

    #[test]
    fn a_refused_lookup_names_the_port_the_bare_flag_admits() {
        let rendered = classify("policy_denied", None)
            .remedy(Some("pypi.org"))
            .render(false);
        assert_eq!(
            rendered,
            "allow with --allow-host pypi.org (port 443; add :PORT for another)"
        );
    }

    /// The boundary working is not a missing permission: no flag, no manifest
    /// entry, no "allow" of any kind is offered for these.
    #[test]
    fn metadata_and_the_absolute_ranges_are_never_offered_an_allow() {
        for label in [
            "cloud_metadata",
            "loopback",
            "unspecified",
            "link_local",
            "shared_address_space",
            "embedded_restricted",
        ] {
            let kind = classify(label, Some(80));
            let remedy = kind.remedy(Some("169.254.169.254:80"));
            assert!(
                matches!(remedy, Remedy::Never { .. }),
                "{label}: {remedy:?}"
            );
            let text = remedy.render(true);
            assert!(!text.contains("--allow-host"), "{label}: {text}");
            assert!(!text.contains("allow with"), "{label}: {text}");
            assert!(!kind.is_plain_allow(), "{label}");
        }
        assert_eq!(
            classify("cloud_metadata", Some(80)).describe(),
            "a cloud instance-metadata endpoint"
        );
    }

    #[test]
    fn the_ssh_port_is_never_offered_an_allow_even_as_a_policy_refusal() {
        let kind = classify("policy_denied", Some(22));
        assert_eq!(kind, DenialKind::SshPort);
        assert!(matches!(kind.remedy(Some("h:22")), Remedy::Never { .. }));
    }

    /// A private range is admitted only by naming the exact address, and the
    /// notice says that rather than presenting it as an ordinary allow.
    #[test]
    fn a_private_range_says_it_must_be_named_explicitly() {
        let kind = classify("private_range", Some(5432));
        assert_eq!(kind.describe(), "an RFC1918 private range");
        let remedy = kind.remedy(Some("10.0.0.5:5432"));
        assert_eq!(
            remedy,
            Remedy::NameExplicitly {
                flag: "--allow-host 10.0.0.5:5432".into()
            }
        );
        let text = remedy.render(true);
        assert!(text.contains("naming it exactly"), "{text}");
        assert!(!text.starts_with("allow with"), "{text}");
        assert!(!kind.is_plain_allow());
        assert!(kind.is_named_only());
    }

    #[test]
    fn a_route_refusal_points_at_the_route_that_decided_it() {
        let kind = DenialKind::classify(&ReasonInputs {
            label: "route_denied",
            port: Some(443),
            route: Some("github"),
            ..Default::default()
        })
        .unwrap();
        let text = kind.remedy(None).render(true);
        assert!(text.contains("endpoint route `github`"), "{text}");
        assert!(!text.contains("--allow-host"), "{text}");
    }

    #[test]
    fn refusals_no_allow_list_changes_offer_no_allow_flag() {
        for label in [
            "rate_limited",
            "malformed",
            "typed_transform_required",
            "termination_unavailable",
            "termination_exhausted",
            "resource_exhausted",
            "peer_destination",
            "placeholder_in_body",
            "unframeable_request",
            "endpoint_rules_unenforceable",
            "approval_unavailable",
            "ambiguous_path",
        ] {
            let text = classify(label, Some(443))
                .remedy(Some("h:443"))
                .render(true);
            assert!(!text.contains("--allow-host"), "{label}: {text}");
        }
    }

    /// A gate that records only the generic word for a restricted address
    /// still never gets an allow offered for it: the address decides.
    #[test]
    fn a_generic_refusal_of_a_restricted_literal_is_read_by_its_address() {
        let classify_at = |host: &str| {
            DenialKind::classify(&ReasonInputs {
                label: "policy_denied",
                host: Some(host),
                port: Some(80),
                ..Default::default()
            })
            .unwrap()
        };
        for host in [
            "169.254.169.254",
            "100.100.100.200",
            "[fd00:ec2::254]",
            "127.0.0.1",
            "[::1]",
            "0.0.0.0",
            "169.254.1.1",
            "100.64.0.1",
            "[::ffff:169.254.169.254]",
        ] {
            let kind = classify_at(host);
            assert!(
                matches!(kind, DenialKind::Restricted(class) if !class.readmittable()),
                "{host}: {kind:?}"
            );
        }
        assert_eq!(
            classify_at("169.254.169.254"),
            DenialKind::Restricted(RestrictedClass::CloudMetadata)
        );
        for host in ["10.0.0.5", "192.168.1.1", "172.16.0.1", "[fd12::1]"] {
            assert!(classify_at(host).is_named_only(), "{host}");
        }
        assert_eq!(classify_at("93.184.216.34"), DenialKind::NotAllowed);
        assert_eq!(classify_at("api.example.com"), DenialKind::NotAllowed);
    }

    /// A specific label the gate recorded is never overridden.
    #[test]
    fn a_recorded_class_label_wins_over_the_address() {
        let kind = DenialKind::classify(&ReasonInputs {
            label: "rate_limited",
            host: Some("10.0.0.5"),
            port: Some(80),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(kind, DenialKind::RateLimited);
    }

    #[test]
    fn a_failed_connect_is_not_a_denial() {
        assert!(
            DenialKind::classify(&ReasonInputs {
                label: "connect_failed",
                ..Default::default()
            })
            .is_none()
        );
    }

    #[test]
    fn an_unknown_label_is_shown_verbatim_without_a_remedy_flag() {
        let kind = classify("something_new", Some(443));
        assert_eq!(kind.describe(), "refused: something_new");
        assert!(
            !kind
                .remedy(Some("h:443"))
                .render(true)
                .contains("--allow-host")
        );
    }

    #[test]
    fn remedy_json_is_tagged_by_kind() {
        let json = serde_json::to_value(Remedy::AllowHost {
            flag: "--allow-host a:443".into(),
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({"kind": "allow_host", "flag": "--allow-host a:443"})
        );
        let json = serde_json::to_value(Remedy::Never { why: "x".into() }).unwrap();
        assert_eq!(json, serde_json::json!({"kind": "never", "why": "x"}));
    }
}
