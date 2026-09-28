//! One egress refusal, read out of a chain-signed audit entry.
//!
//! Only entries the per-VM network endpoint writes are read, and only when
//! they name the machine being watched: several machines share one tenant
//! chain, and a refusal attributed to the wrong one would send its owner off
//! to widen a policy that was never in the way.

use chrono::{DateTime, Utc};
use mvm_hostd::supervisor::PlanAuditEntry;
use mvm_hostd::supervisor::audit_recorder::LABEL_VM_NAME;

use super::reason::{DenialKind, ReasonInputs, Remedy};

/// What was refused, in the shape the notice names it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::commands) enum Subject {
    /// A TCP connect to `host:port`.
    Tcp(String),
    /// A UDP datagram to `addr:port`.
    Udp(String),
    /// A DNS lookup of a name.
    Lookup(String),
    /// An HTTP request an endpoint route decided: method and `host:port`.
    Request { method: String, target: String },
    /// An ICMP echo to a host.
    Echo(String),
}

impl Subject {
    /// The destination as `--allow-host` takes it, when one could admit it.
    pub(in crate::commands) fn allow_target(&self) -> Option<&str> {
        match self {
            Self::Tcp(target) | Self::Request { target, .. } => Some(target),
            Self::Lookup(name) if !name.is_empty() => Some(name),
            _ => None,
        }
    }

    /// Whether the destination carries an explicit port.
    pub(in crate::commands) fn has_port(&self) -> bool {
        !matches!(self, Self::Lookup(_))
    }

    /// The host half of the destination, brackets kept off an IPv6 literal.
    fn host(&self) -> Option<&str> {
        match self {
            Self::Tcp(target) | Self::Udp(target) | Self::Request { target, .. } => Some(
                target
                    .rsplit_once(':')
                    .map_or(target.as_str(), |(host, _)| host),
            ),
            Self::Lookup(name) | Self::Echo(name) => Some(name),
        }
    }

    fn port(&self) -> Option<u16> {
        match self {
            Self::Tcp(target) | Self::Udp(target) | Self::Request { target, .. } => target
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse().ok()),
            Self::Lookup(_) | Self::Echo(_) => None,
        }
    }
}

impl std::fmt::Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(target) => f.write_str(target),
            Self::Udp(target) => write!(f, "udp {target}"),
            Self::Lookup(name) if name.is_empty() => f.write_str("DNS lookup"),
            Self::Lookup(name) => write!(f, "DNS lookup of {name}"),
            Self::Request { method, target } => write!(f, "{method} {target}"),
            Self::Echo(host) => write!(f, "ping {host}"),
        }
    }
}

/// One refusal the host recorded for the watched machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct EgressDenial {
    pub at: DateTime<Utc>,
    /// The audit event that recorded it.
    pub event: String,
    /// The reason label exactly as recorded.
    pub reason: String,
    pub subject: Subject,
    pub kind: DenialKind,
}

impl EgressDenial {
    /// The refusal `entry` records for machine `vm`, if it records one.
    pub(in crate::commands) fn from_entry(entry: &PlanAuditEntry, vm: &str) -> Option<Self> {
        if entry.labels.get(LABEL_VM_NAME).map(String::as_str) != Some(vm) {
            return None;
        }
        let label = |key: &str| entry.labels.get(key).map(String::as_str);
        let (subject, reason) = match entry.event.as_str() {
            "host.flow.denied" => {
                let target = label("target")?.to_string();
                let subject = match label("class") {
                    Some("udp") => Subject::Udp(target),
                    _ => Subject::Tcp(target),
                };
                (subject, label("reason")?)
            }
            "dns.refused" => {
                let reason = label("reason").or(label("verdict"))?;
                (
                    Subject::Lookup(label("qname").unwrap_or_default().to_string()),
                    reason,
                )
            }
            "secret.flow_refused" => (
                Subject::Tcp(label("destination")?.to_string()),
                label("reason")?,
            ),
            "secret.placeholder_dropped" => (
                Subject::Tcp(label("destination")?.to_string()),
                "placeholder_dropped",
            ),
            "host.route.decided" if label("verdict") == Some("refused") => (
                Subject::Request {
                    method: label("method").unwrap_or("other").to_string(),
                    target: label("destination")?.to_string(),
                },
                label("reason")?,
            ),
            "icmp.refused" => (
                Subject::Echo(label("host").unwrap_or_default().to_string()),
                "echo_refused",
            ),
            _ => return None,
        };
        let kind = DenialKind::classify(&ReasonInputs {
            label: reason,
            host: subject.host(),
            port: subject.port(),
            route: label("route"),
            detail: label("reason"),
        })?;
        Some(Self {
            at: entry.timestamp,
            event: entry.event.clone(),
            reason: reason.to_string(),
            subject,
            kind,
        })
    }

    pub(in crate::commands) fn remedy(&self) -> Remedy {
        self.kind.remedy(self.subject.allow_target())
    }

    /// The live notice: what, why, and what to do.
    pub(in crate::commands) fn notice(&self) -> String {
        format!(
            "egress blocked: {} ({}) — {}",
            self.subject,
            self.kind.describe(),
            self.remedy().render(self.subject.has_port())
        )
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::collections::BTreeMap;

    pub(in crate::commands::vm::egress_denials) fn entry(
        event: &str,
        labels: &[(&str, &str)],
    ) -> PlanAuditEntry {
        PlanAuditEntry {
            timestamp: "2026-09-26T10:00:00Z".parse().unwrap(),
            tenant: mvm_core::plan::TenantId("local".into()),
            plan_id: mvm_core::plan::PlanId("00000000-0000-0000-0000-000000000000".into()),
            plan_version: 0,
            bundle_id: None,
            bundle_version: None,
            image_name: "<unbound>".into(),
            image_sha256: "0".repeat(64),
            event: event.into(),
            caller_commitment: None,
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    fn denial(event: &str, labels: &[(&str, &str)]) -> EgressDenial {
        EgressDenial::from_entry(&entry(event, labels), "vm-a").expect("a denial for vm-a")
    }

    #[test]
    fn a_refused_connect_reads_as_the_example_notice() {
        let d = denial(
            "host.flow.denied",
            &[
                ("vm_name", "vm-a"),
                ("class", "tcp"),
                ("target", "api.example.com:443"),
                ("reason", "policy_denied"),
            ],
        );
        assert_eq!(
            d.notice(),
            "egress blocked: api.example.com:443 (not in the allow-list) — allow with \
             --allow-host api.example.com:443"
        );
    }

    #[test]
    fn another_machines_refusal_is_not_this_ones() {
        let other = entry(
            "host.flow.denied",
            &[
                ("vm_name", "vm-b"),
                ("target", "a:443"),
                ("reason", "policy_denied"),
            ],
        );
        assert!(EgressDenial::from_entry(&other, "vm-a").is_none());
        let unattributed = entry(
            "host.flow.denied",
            &[("target", "a:443"), ("reason", "policy_denied")],
        );
        assert!(EgressDenial::from_entry(&unattributed, "vm-a").is_none());
    }

    #[test]
    fn a_metadata_refusal_names_no_flag() {
        let d = denial(
            "host.flow.denied",
            &[
                ("vm_name", "vm-a"),
                ("target", "169.254.169.254:80"),
                ("reason", "cloud_metadata"),
            ],
        );
        let notice = d.notice();
        assert!(
            notice.starts_with(
                "egress blocked: 169.254.169.254:80 (a cloud instance-metadata endpoint) — never"
            ),
            "{notice}"
        );
        assert!(!notice.contains("--allow-host"), "{notice}");
    }

    #[test]
    fn a_refused_lookup_is_named_as_a_lookup() {
        let d = denial(
            "dns.refused",
            &[
                ("vm_name", "vm-a"),
                ("qname", "pypi.org"),
                ("reason", "policy_denied"),
            ],
        );
        assert_eq!(d.subject, Subject::Lookup("pypi.org".into()));
        assert!(
            d.notice().contains("DNS lookup of pypi.org"),
            "{}",
            d.notice()
        );
        // The record-level DNS entry carries `verdict` rather than `reason`.
        let d = denial(
            "dns.refused",
            &[
                ("vm_name", "vm-a"),
                ("qname", "pypi.org"),
                ("verdict", "refused"),
            ],
        );
        assert_eq!(d.kind, DenialKind::NotAllowed);
    }

    #[test]
    fn a_udp_refusal_is_labelled_as_udp() {
        let d = denial(
            "host.flow.denied",
            &[
                ("vm_name", "vm-a"),
                ("class", "udp"),
                ("target", "8.8.8.8:53"),
                ("reason", "policy_denied"),
            ],
        );
        assert!(d.notice().starts_with("egress blocked: udp 8.8.8.8:53"));
    }

    #[test]
    fn a_route_refusal_carries_its_method_and_route() {
        let d = denial(
            "host.route.decided",
            &[
                ("vm_name", "vm-a"),
                ("route", "github"),
                ("rule", "otherwise"),
                ("outcome", "deny"),
                ("destination", "api.github.com:443"),
                ("method", "POST"),
                ("verdict", "refused"),
                ("reason", "route_denied"),
            ],
        );
        assert_eq!(
            d.subject,
            Subject::Request {
                method: "POST".into(),
                target: "api.github.com:443".into()
            }
        );
        assert!(
            d.notice().contains("endpoint route `github`"),
            "{}",
            d.notice()
        );
    }

    #[test]
    fn a_forwarded_route_decision_is_not_a_denial() {
        let forwarded = entry(
            "host.route.decided",
            &[
                ("vm_name", "vm-a"),
                ("destination", "api.github.com:443"),
                ("verdict", "forwarded"),
            ],
        );
        assert!(EgressDenial::from_entry(&forwarded, "vm-a").is_none());
    }

    #[test]
    fn an_admitted_flow_and_a_failed_connect_are_not_denials() {
        for (event, reason) in [
            ("host.flow.allowed", "policy_denied"),
            ("host.flow.denied", "connect_failed"),
        ] {
            let e = entry(
                event,
                &[("vm_name", "vm-a"), ("target", "a:443"), ("reason", reason)],
            );
            assert!(
                EgressDenial::from_entry(&e, "vm-a").is_none(),
                "{event}/{reason}"
            );
        }
    }

    #[test]
    fn secret_path_refusals_are_read_from_their_destination() {
        let d = denial(
            "secret.flow_refused",
            &[
                ("vm_name", "vm-a"),
                ("destination", "api.example.com:443"),
                ("reason", "placeholder_in_body"),
            ],
        );
        assert_eq!(d.kind, DenialKind::PlaceholderMisplaced);
        let d = denial(
            "secret.placeholder_dropped",
            &[("vm_name", "vm-a"), ("destination", "evil.example")],
        );
        assert_eq!(d.kind, DenialKind::PlaceholderUnbound);
    }
}
