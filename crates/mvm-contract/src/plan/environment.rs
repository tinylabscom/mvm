//! The signed environment descriptor a portable bundle may carry.
//!
//! An environment descriptor states what a packaged workload needs from the
//! launch that boots it: the program it runs, the resources it was sized for,
//! the mount points and secret slots it expects, the capabilities it requires,
//! and the application processes it supervises. It is carried as the
//! [`super::bundle::BundleMember::Environment`] member, so it is covered by the
//! publisher's manifest signature like every other member.
//!
//! The descriptor never grants anything. Every capability it requires must be
//! permitted by the bundle's own security posture, and every launch is still
//! held to the posture, the host's ceilings and its own flags. Resources are
//! the defaults a launch starts from when it names none, not an allocation.
//! Secret slots are names only: the value is bound on the host at launch time
//! and substituted on the endpoint side, never written into the bundle or the
//! guest.
//!
//! Structural rules live here and run on the descriptor alone
//! ([`EnvironmentDescriptor::validate`]). Rules that relate the descriptor to
//! the rest of the manifest (architecture, posture) run in `mvm-core`'s bundle
//! verifier.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::pack_spec::{PackIdentity, PackResources, PackTarget};

/// The only descriptor version this build reads. A descriptor declaring any
/// other version is refused rather than read under rules it was not written
/// for.
pub const ENVIRONMENT_DESCRIPTOR_VERSION: u32 = 1;

/// Longest logical name a volume, secret slot or service may carry.
pub const MAX_ENVIRONMENT_NAME_BYTES: usize = 64;

/// Longest single argv element, working directory or guest path.
pub const MAX_ENVIRONMENT_STRING_BYTES: usize = 4096;

/// Most entries any one descriptor list may hold. Bounds the work a verifier
/// does on a signed but hostile descriptor.
pub const MAX_ENVIRONMENT_ENTRIES: usize = 64;

/// What a packaged workload requires from the launch that boots it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentDescriptor {
    /// Version of this descriptor's own shape, independent of the bundle
    /// schema. Must equal [`ENVIRONMENT_DESCRIPTOR_VERSION`].
    pub descriptor_version: u32,
    /// The pack this environment was built from, when it came from one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack: Option<PackIdentity>,
    /// Guest target the environment was built for. Must agree with the
    /// bundle manifest's `arch`.
    pub target: PackTarget,
    /// The program the image runs.
    pub entrypoint: EnvironmentEntrypoint,
    /// Advisory sizing. A launch that names no `--cpus` / `--memory` starts
    /// from these; the host's admission ceilings and budget still apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<PackResources>,
    /// Signed egress ceiling; this declaration grants no launch authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<EnvironmentPolicy>,
    /// Mount points the workload expects. Declaring any requires the
    /// [`EnvironmentCapability::HostVolumes`] capability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<EnvironmentVolume>,
    /// Secrets the workload reads, by name only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_slots: Vec<SecretSlot>,
    /// Capabilities the workload requires. Each must be permitted by the
    /// bundle's security posture.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<EnvironmentCapability>,
    /// Application processes the workload runs beside its entrypoint. These
    /// are guest processes, not host services the broker exposes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<ApplicationService>,
}

/// Exact destinations an application may request. An empty list denies all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentPolicy {
    /// Canonical lowercase DNS names or IP literals with an explicit nonzero
    /// port. IPv6 literals use brackets; patterns and implicit ports are refused.
    pub allow_hosts: Vec<String>,
}

impl EnvironmentPolicy {
    pub fn validate(&self) -> Result<(), EnvironmentDescriptorError> {
        bounded("policy.allow_hosts", self.allow_hosts.len())?;
        for authority in &self.allow_hosts {
            Self::parse_authority(authority)?;
        }
        unique(
            "policy.allow_hosts",
            self.allow_hosts.iter().map(String::as_str),
        )
    }

    /// Parse only the canonical authority spelling accepted in signed policy.
    pub fn parse_authority(
        authority: &str,
    ) -> Result<crate::policy::network_policy::HostPort, EnvironmentDescriptorError> {
        use crate::policy::network_policy::HostPort;
        use core::net::{Ipv4Addr, Ipv6Addr};

        let fail = || invalid("policy.allow_hosts", "expected a canonical exact HOST:PORT");
        if authority.len() > MAX_ENVIRONMENT_STRING_BYTES {
            return Err(fail());
        }
        let parsed: HostPort = authority.parse().map_err(|_| fail())?;
        let (_, port) = authority.rsplit_once(':').ok_or_else(fail)?;
        if parsed.port == 0 || port != parsed.port.to_string() {
            return Err(fail());
        }
        if let Some(host) = parsed
            .host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
        {
            let ip: Ipv6Addr = host.parse().map_err(|_| fail())?;
            if ip.to_string() != host {
                return Err(fail());
            }
            return Ok(HostPort::new(host, parsed.port));
        }
        let host = &parsed.host;
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            if ip.to_string() != *host {
                return Err(fail());
            }
        } else if host.len() > 253
            || host.split('.').all(|label| {
                label.bytes().all(|b| b.is_ascii_digit())
                    || label.strip_prefix("0x").is_some_and(|hex| {
                        !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
                    })
            })
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        {
            return Err(fail());
        }
        Ok(parsed)
    }
}

/// The program an environment runs: literal argv, no shell evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentEntrypoint {
    pub argv: Vec<String>,
    /// Absolute guest directory the program starts in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

/// A mount point the workload expects, by logical name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentVolume {
    pub name: String,
    /// Absolute, normalized guest path.
    pub guest_path: String,
}

/// A secret the workload reads, named the way the workload sees it.
///
/// There is deliberately no value field: the shape refuses one.
// allow(secret-debug): a slot is a name and a required flag; the value is
// bound on the host at launch and never reaches this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretSlot {
    /// Environment-variable style name, as the existing secret binding names
    /// its target.
    pub name: String,
    /// A required slot refuses a launch that binds no secret to it.
    pub required: bool,
}

/// What a workload may require from its launch. A closed set: a capability
/// this reader does not know fails the manifest parse instead of being
/// ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentCapability {
    /// Outbound network through the host endpoint. Requires a posture that
    /// allows egress.
    Egress,
    /// Host shares or volumes attached to the guest. Requires a posture that
    /// allows volumes.
    HostVolumes,
    /// An interactive terminal, which only a development-profile agent
    /// serves. Requires a posture that is not sealed-prod.
    InteractiveTerminal,
}

impl EnvironmentCapability {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Egress => "egress",
            Self::HostVolumes => "host_volumes",
            Self::InteractiveTerminal => "interactive_terminal",
        }
    }
}

/// A guest application process the workload runs. Distinct from the broker's
/// host service identifiers on purpose: an application service is something
/// the guest runs, a broker service is something the host answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationService {
    pub name: String,
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

/// Why a descriptor was refused. Messages name the offending field and never
/// echo a value that may be a secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvironmentDescriptorError {
    #[error(
        "environment descriptor version {found} is not supported (this build reads {supported})"
    )]
    UnsupportedVersion { found: u32, supported: u32 },
    #[error("environment pack identity is invalid: expected namespace/name and SemVer version")]
    PackIdentity,
    #[error("environment {field} is invalid: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("environment {field} declares {name:?} more than once")]
    Duplicate { field: &'static str, name: String },
    #[error(
        "environment {field} carries what looks like an inline secret value; declare a secret \
         slot and bind it at launch instead"
    )]
    InlineSecret { field: &'static str },
    #[error("environment declares volumes but does not require the host_volumes capability")]
    VolumesWithoutCapability,
}

impl EnvironmentDescriptor {
    /// Every structural rule the descriptor carries on its own.
    pub fn validate(&self) -> Result<(), EnvironmentDescriptorError> {
        if self.descriptor_version != ENVIRONMENT_DESCRIPTOR_VERSION {
            return Err(EnvironmentDescriptorError::UnsupportedVersion {
                found: self.descriptor_version,
                supported: ENVIRONMENT_DESCRIPTOR_VERSION,
            });
        }
        if let Some(pack) = &self.pack {
            pack.validate()
                .map_err(|_| EnvironmentDescriptorError::PackIdentity)?;
        }
        validate_resources(self.resources.as_ref())?;
        if let Some(policy) = &self.policy {
            policy.validate()?;
        }
        bounded("volumes", self.volumes.len())?;
        bounded("secret_slots", self.secret_slots.len())?;
        bounded("capabilities", self.capabilities.len())?;
        bounded("services", self.services.len())?;
        validate_slots(&self.secret_slots)?;
        let slot_names: Vec<&str> = self.secret_slots.iter().map(|s| s.name.as_str()).collect();
        validate_program(
            "entrypoint",
            &self.entrypoint.argv,
            self.entrypoint.working_dir.as_deref(),
            &slot_names,
        )?;
        validate_volumes(&self.volumes)?;
        if !self.volumes.is_empty() && !self.requires(EnvironmentCapability::HostVolumes) {
            return Err(EnvironmentDescriptorError::VolumesWithoutCapability);
        }
        unique("capabilities", self.capabilities.iter().map(|c| c.as_str()))?;
        unique("services", self.services.iter().map(|s| s.name.as_str()))?;
        for service in &self.services {
            logical_name("services", &service.name)?;
            validate_program(
                "services",
                &service.argv,
                service.working_dir.as_deref(),
                &slot_names,
            )?;
        }
        Ok(())
    }

    /// Whether the descriptor requires `capability`.
    pub fn requires(&self, capability: EnvironmentCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// The secret slots a launch must bind.
    pub fn required_secret_slots(&self) -> impl Iterator<Item = &str> {
        self.secret_slots
            .iter()
            .filter(|slot| slot.required)
            .map(|slot| slot.name.as_str())
    }
}

impl PackTarget {
    /// The bundle-manifest architecture label this target corresponds to.
    pub fn arch_label(self) -> &'static str {
        match self {
            Self::X86_64Linux => "x86_64",
            Self::Aarch64Linux => "aarch64",
        }
    }
}

fn invalid(field: &'static str, reason: &'static str) -> EnvironmentDescriptorError {
    EnvironmentDescriptorError::Invalid { field, reason }
}

fn bounded(field: &'static str, len: usize) -> Result<(), EnvironmentDescriptorError> {
    if len > MAX_ENVIRONMENT_ENTRIES {
        return Err(invalid(field, "too many entries"));
    }
    Ok(())
}

fn validate_resources(resources: Option<&PackResources>) -> Result<(), EnvironmentDescriptorError> {
    match resources {
        Some(r) if r.cpu_cores == 0 || r.memory_mb == 0 => Err(invalid(
            "resources",
            "CPU cores and memory MiB must be positive",
        )),
        _ => Ok(()),
    }
}

fn unique<'a>(
    field: &'static str,
    names: impl Iterator<Item = &'a str>,
) -> Result<(), EnvironmentDescriptorError> {
    let mut seen: Vec<&str> = Vec::new();
    for name in names {
        if seen.contains(&name) {
            return Err(EnvironmentDescriptorError::Duplicate {
                field,
                name: name.into(),
            });
        }
        seen.push(name);
    }
    Ok(())
}

/// Lowercase-led logical name: `[a-z0-9][a-z0-9_-]*`, bounded.
fn logical_name(field: &'static str, name: &str) -> Result<(), EnvironmentDescriptorError> {
    let well_formed = !name.is_empty()
        && name.len() <= MAX_ENVIRONMENT_NAME_BYTES
        && name
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if !well_formed {
        return Err(invalid(field, "names must match [a-z0-9][a-z0-9_-]{0,63}"));
    }
    Ok(())
}

fn validate_slots(slots: &[SecretSlot]) -> Result<(), EnvironmentDescriptorError> {
    for slot in slots {
        if slot.name.len() > MAX_ENVIRONMENT_NAME_BYTES
            || !crate::protocol::vm_backend::is_secret_env_name(&slot.name)
        {
            return Err(invalid(
                "secret_slots",
                "slot names must be environment-variable names of at most 64 bytes",
            ));
        }
    }
    unique("secret_slots", slots.iter().map(|s| s.name.as_str()))
}

fn validate_volumes(volumes: &[EnvironmentVolume]) -> Result<(), EnvironmentDescriptorError> {
    for volume in volumes {
        logical_name("volumes", &volume.name)?;
        guest_absolute_path("volumes", &volume.guest_path)?;
    }
    unique("volumes", volumes.iter().map(|v| v.name.as_str()))?;
    unique("volumes", volumes.iter().map(|v| v.guest_path.as_str()))
}

/// An absolute guest path with no empty, `.` or `..` segment, no backslash
/// and no control characters. `/` alone is refused: nothing mounts over the
/// guest root.
fn guest_absolute_path(field: &'static str, path: &str) -> Result<(), EnvironmentDescriptorError> {
    let Some(rest) = path.strip_prefix('/') else {
        return Err(invalid(field, "guest paths must be absolute"));
    };
    if path.len() > MAX_ENVIRONMENT_STRING_BYTES
        || rest.is_empty()
        || path.chars().any(|c| c.is_control() || c == '\\')
        || rest
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(invalid(
            field,
            "guest paths must be normalized, below the root, with no traversal",
        ));
    }
    Ok(())
}

fn validate_program(
    field: &'static str,
    argv: &[String],
    working_dir: Option<&str>,
    slot_names: &[&str],
) -> Result<(), EnvironmentDescriptorError> {
    if argv.first().is_none_or(|program| program.trim().is_empty()) {
        return Err(invalid(field, "argv must name a program"));
    }
    if argv.len() > MAX_ENVIRONMENT_ENTRIES * 4
        || argv
            .iter()
            .any(|arg| arg.contains('\0') || arg.len() > MAX_ENVIRONMENT_STRING_BYTES)
    {
        return Err(invalid(field, "argv elements must be bounded and NUL-free"));
    }
    if let Some(dir) = working_dir {
        guest_absolute_path(field, dir)?;
    }
    if argv_carries_inline_secret(argv, slot_names) {
        return Err(EnvironmentDescriptorError::InlineSecret { field });
    }
    Ok(())
}

/// Whether an argv hands a secret to the program inline: `KEY=value` or
/// `--key=value` where the key is a declared slot or secret-shaped, or a
/// secret-shaped `--flag` followed by its value. A descriptor is signed and
/// published; a credential written into it is a credential given away.
fn argv_carries_inline_secret(argv: &[String], slot_names: &[&str]) -> bool {
    let secret_key = |key: &str| {
        let key = key.trim_start_matches('-');
        !key.is_empty()
            && (slot_names.contains(&key)
                || crate::ir::is_secret_field_name(&key.replace('-', "_")))
    };
    argv.iter()
        .enumerate()
        .skip(1)
        .any(|(i, arg)| match arg.split_once('=') {
            Some((key, value)) => !value.is_empty() && secret_key(key),
            None => {
                arg.starts_with('-')
                    && secret_key(arg)
                    && argv.get(i + 1).is_some_and(|next| !next.starts_with('-'))
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn s(v: &str) -> String {
        v.to_string()
    }

    fn descriptor() -> EnvironmentDescriptor {
        EnvironmentDescriptor {
            descriptor_version: ENVIRONMENT_DESCRIPTOR_VERSION,
            pack: Some(PackIdentity {
                name: s("anthropic/claude-code"),
                version: s("1.0.0"),
            }),
            target: PackTarget::X86_64Linux,
            entrypoint: EnvironmentEntrypoint {
                argv: vec![s("/usr/bin/claude")],
                working_dir: Some(s("/workspace")),
            },
            resources: Some(PackResources {
                cpu_cores: 2,
                memory_mb: 2048,
            }),
            policy: None,
            volumes: vec![EnvironmentVolume {
                name: s("workspace"),
                guest_path: s("/workspace"),
            }],
            secret_slots: vec![SecretSlot {
                name: s("ANTHROPIC_API_KEY"),
                required: true,
            }],
            capabilities: vec![
                EnvironmentCapability::Egress,
                EnvironmentCapability::HostVolumes,
            ],
            services: vec![ApplicationService {
                name: s("language-server"),
                argv: vec![s("/usr/bin/lsp"), s("--stdio")],
                working_dir: None,
            }],
        }
    }

    #[test]
    fn a_complete_descriptor_validates_and_round_trips() {
        let d = descriptor();
        d.validate().expect("valid descriptor");
        let value = serde_json::to_value(&d).unwrap();
        assert_eq!(value["target"], "x86_64-linux");
        assert_eq!(value["capabilities"][1], "host_volumes");
        assert_eq!(
            serde_json::from_value::<EnvironmentDescriptor>(value).unwrap(),
            d
        );
        assert_eq!(
            d.required_secret_slots().collect::<Vec<_>>(),
            ["ANTHROPIC_API_KEY"]
        );
    }

    #[test]
    fn a_minimal_descriptor_needs_only_version_target_and_entrypoint() {
        let d: EnvironmentDescriptor = serde_json::from_value(serde_json::json!({
            "descriptor_version": 1,
            "target": "aarch64-linux",
            "entrypoint": { "argv": ["/bin/app"] },
        }))
        .unwrap();
        d.validate().unwrap();
        assert!(d.capabilities.is_empty() && d.resources.is_none());
    }

    #[test]
    fn an_unsupported_descriptor_version_is_refused() {
        let d = EnvironmentDescriptor {
            descriptor_version: 2,
            ..descriptor()
        };
        assert_eq!(
            d.validate(),
            Err(EnvironmentDescriptorError::UnsupportedVersion {
                found: 2,
                supported: 1
            })
        );
    }

    #[test]
    fn an_unknown_capability_or_field_fails_the_parse() {
        let mut value = serde_json::to_value(descriptor()).unwrap();
        value["capabilities"] = serde_json::json!(["raw_network"]);
        assert!(serde_json::from_value::<EnvironmentDescriptor>(value).is_err());

        let mut value = serde_json::to_value(descriptor()).unwrap();
        value["privileged"] = serde_json::json!(true);
        assert!(serde_json::from_value::<EnvironmentDescriptor>(value).is_err());
    }

    #[test]
    fn a_secret_slot_with_a_value_fails_the_parse() {
        let mut value = serde_json::to_value(descriptor()).unwrap();
        value["secret_slots"][0]["value"] = serde_json::json!("sk-live-123");
        assert!(serde_json::from_value::<EnvironmentDescriptor>(value).is_err());
    }

    #[test]
    fn inline_secret_values_in_argv_are_refused() {
        for argv in [
            vec![s("/bin/app"), s("ANTHROPIC_API_KEY=sk-123")],
            vec![s("/bin/app"), s("--api-key=sk-123")],
            vec![s("/bin/app"), s("--token"), s("abc")],
            vec![s("/bin/app"), s("--password=hunter2")],
        ] {
            let mut d = descriptor();
            d.entrypoint.argv = argv.clone();
            assert_eq!(
                d.validate(),
                Err(EnvironmentDescriptorError::InlineSecret {
                    field: "entrypoint"
                }),
                "{argv:?}"
            );
        }
        let mut d = descriptor();
        d.services[0].argv = vec![s("/bin/svc"), s("--secret=x")];
        assert_eq!(
            d.validate(),
            Err(EnvironmentDescriptorError::InlineSecret { field: "services" })
        );
        let mut d = descriptor();
        d.entrypoint.argv = vec![s("/bin/app"), s("--token-file"), s("/run/t")];
        d.validate()
            .expect("a file path flag is not a secret value");
    }

    type Mutation = fn(&mut EnvironmentDescriptor);

    #[test]
    fn absent_policy_preserves_old_descriptor_bytes() {
        let bytes = br#"{"descriptor_version":1,"target":"aarch64-linux","entrypoint":{"argv":["/bin/app"]}}"#;
        let d: EnvironmentDescriptor = serde_json::from_slice(bytes).unwrap();
        d.validate().unwrap();
        assert!(d.policy.is_none());
        assert_eq!(serde_json::to_vec(&d).unwrap(), bytes);
    }

    #[test]
    fn an_old_closed_reader_refuses_a_policy_bearing_descriptor() {
        #[derive(Deserialize, Serialize)]
        #[serde(deny_unknown_fields)]
        struct OldDescriptor {
            descriptor_version: u32,
            target: PackTarget,
            entrypoint: EnvironmentEntrypoint,
        }
        let old = serde_json::json!({
            "descriptor_version": 1, "target": "aarch64-linux",
            "entrypoint": {"argv": ["/bin/app"]}
        });
        let descriptor: OldDescriptor = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(serde_json::to_value(descriptor).unwrap(), old);
        let mut new = old;
        new["policy"] = serde_json::json!({"allow_hosts": ["api.anthropic.com:443"]});
        assert!(serde_json::from_value::<OldDescriptor>(new).is_err());
    }

    #[test]
    fn signed_policy_round_trips_and_is_closed() {
        let mut d = descriptor();
        d.policy = Some(EnvironmentPolicy {
            allow_hosts: vec![s("api.anthropic.com:443"), s("[2001:db8::1]:443")],
        });
        d.validate().unwrap();
        let mut value = serde_json::to_value(&d).unwrap();
        assert_eq!(
            serde_json::from_value::<EnvironmentDescriptor>(value.clone()).unwrap(),
            d
        );
        value["policy"]["allow_any"] = serde_json::json!(true);
        assert!(serde_json::from_value::<EnvironmentDescriptor>(value).is_err());
    }

    #[test]
    fn policy_refuses_ambiguous_authorities_duplicates_and_bounds() {
        for host in [
            "",
            "api.anthropic.com",
            "api.anthropic.com:0",
            "api.anthropic.com:0443",
            "api.anthropic.com:+443",
            "API.anthropic.com:443",
            "api.anthropic.com.:443",
            "*.anthropic.com:443",
            "https://api.anthropic.com:443",
            "user@api.anthropic.com:443",
            "api.anthropic.com:443/path",
            "api.anthropic.com :443",
            "127.00.0.1:443",
            "127.1:443",
            "0x7f000001:443",
            "0x7f.1:443",
            "2001:db8::1:443",
            "[2001:0db8::1]:443",
            "[::1%lo0]:443",
            "a..com:443",
            "-a.com:443",
        ] {
            assert!(EnvironmentPolicy::parse_authority(host).is_err(), "{host}");
        }
        for host in ["api.anthropic.com:443", "127.0.0.1:443", "[::1]:443"] {
            assert!(EnvironmentPolicy::parse_authority(host).is_ok(), "{host}");
        }
        let mut policy = EnvironmentPolicy {
            allow_hosts: vec![s("api.anthropic.com:443"); 2],
        };
        assert!(matches!(
            policy.validate(),
            Err(EnvironmentDescriptorError::Duplicate { .. })
        ));
        policy.allow_hosts = (0..=MAX_ENVIRONMENT_ENTRIES)
            .map(|i| alloc::format!("host{i}.example:443"))
            .collect();
        assert!(policy.validate().is_err());
        policy.allow_hosts.pop();
        policy.validate().unwrap();
        policy.allow_hosts = vec![s(&"a".repeat(MAX_ENVIRONMENT_STRING_BYTES + 1))];
        assert!(policy.validate().is_err());
        policy.allow_hosts.clear();
        policy.validate().unwrap();
    }

    #[test]
    fn structural_refusals() {
        let cases: Vec<(&str, Mutation)> = vec![
            ("empty argv", |d| d.entrypoint.argv.clear()),
            ("blank program", |d| d.entrypoint.argv = vec![s(" ")]),
            ("relative working dir", |d| {
                d.entrypoint.working_dir = Some(s("work"))
            }),
            ("traversal volume", |d| {
                d.volumes[0].guest_path = s("/a/../b")
            }),
            ("root volume", |d| d.volumes[0].guest_path = s("/")),
            ("bad volume name", |d| d.volumes[0].name = s("Work Space")),
            ("bad slot name", |d| d.secret_slots[0].name = s("api-key")),
            ("duplicate slot", |d| {
                let slot = d.secret_slots[0].clone();
                d.secret_slots.push(slot)
            }),
            ("duplicate capability", |d| {
                d.capabilities.push(EnvironmentCapability::Egress)
            }),
            ("duplicate service", |d| {
                let svc = d.services[0].clone();
                d.services.push(svc)
            }),
            ("zero memory", |d| {
                d.resources = Some(PackResources {
                    cpu_cores: 1,
                    memory_mb: 0,
                })
            }),
            ("bad pack identity", |d| {
                d.pack = Some(PackIdentity {
                    name: s("no-namespace"),
                    version: s("1"),
                })
            }),
            ("volumes without capability", |d| {
                d.capabilities
                    .retain(|c| *c != EnvironmentCapability::HostVolumes)
            }),
        ];
        for (what, mutate) in cases {
            let mut d = descriptor();
            mutate(&mut d);
            assert!(d.validate().is_err(), "{what} must be refused");
        }
    }

    #[test]
    fn target_maps_to_manifest_arch_labels() {
        assert_eq!(PackTarget::X86_64Linux.arch_label(), "x86_64");
        assert_eq!(PackTarget::Aarch64Linux.arch_label(), "aarch64");
    }
}
