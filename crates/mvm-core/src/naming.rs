use anyhow::{Result, bail};

/// Validate a VM name: lowercase alphanumeric + hyphens, 1-63 chars (RFC 1123).
///
/// VM names flow into filesystem paths and shell commands, so only
/// a safe subset of characters is accepted.
pub fn validate_vm_name(name: &str) -> Result<()> {
    validate_id(name, "VM name")
}

/// Validate a template name: lowercase alphanumeric + hyphens + underscores, 1-63 chars.
pub fn validate_template_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 63 {
        bail!("template name must be 1-63 characters, got {}", name.len());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        bail!(
            "template name must be lowercase alphanumeric + hyphens/underscores: {:?}",
            name
        );
    }
    if name.starts_with('-') || name.starts_with('_') {
        bail!(
            "template name must not start with a hyphen or underscore: {:?}",
            name
        );
    }
    Ok(())
}

/// Validate a Nix flake reference for safe shell interpolation.
///
/// Rejects empty strings and any character that would be interpreted by the
/// shell as a metacharacter (`;`, `|`, `&`, `$`, `(`, `)`, `` ` ``, `!`,
/// `<`, `>`, newline).
pub fn validate_flake_ref(s: &str) -> Result<()> {
    if s.is_empty() {
        bail!("flake reference must not be empty");
    }
    const SHELL_META: &[char] = &[';', '|', '&', '$', '(', ')', '`', '!', '<', '>', '\n', '\r'];
    if let Some(bad) = s.chars().find(|c| SHELL_META.contains(c)) {
        bail!(
            "flake reference contains unsafe character {:?} — shell metacharacters not allowed",
            bad
        );
    }
    Ok(())
}

/// Validate a tenant or pool ID: lowercase alphanumeric + hyphens, 1-63 chars.
pub fn validate_id(id: &str, kind: &str) -> Result<()> {
    if id.is_empty() || id.len() > 63 {
        bail!("{} ID must be 1-63 characters, got {}", kind, id.len());
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!(
            "{} ID must be lowercase alphanumeric + hyphens: {:?}",
            kind,
            id
        );
    }
    if id.starts_with('-') || id.ends_with('-') {
        bail!("{} ID must not start or end with a hyphen: {:?}", kind, id);
    }
    Ok(())
}

/// Which persistent builder VM a name belongs to. The token is the on-disk
/// state-dir infix, so the variants are the storage format and not a display
/// nicety — renaming one strands every existing builder state dir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderVmSlot {
    /// The libkrun builder, `mvm-persistent-builder-vm-*`.
    Libkrun,
    /// The HVF builder, `mvm-persistent-builder-hvf-*`.
    Hvf,
}

impl BuilderVmSlot {
    fn token(self) -> &'static str {
        match self {
            Self::Libkrun => "vm",
            Self::Hvf => "hvf",
        }
    }
}

/// Shared prefix of every long-lived builder VM name.
const PERSISTENT_BUILDER_PREFIX: &str = "mvm-persistent-builder-";

/// Shared prefix of every ephemeral per-job builder shell VM name.
const BUILDER_SHELL_JOB_PREFIX: &str = "mvm-hvf-builder-shell-";

/// Name of the long-lived builder VM for `session_id` in `slot`.
pub fn persistent_builder_vm_name(slot: BuilderVmSlot, session_id: &str) -> String {
    format!("{PERSISTENT_BUILDER_PREFIX}{}-{session_id}", slot.token())
}

/// Name of the ephemeral builder VM that runs one shell job and exits.
pub fn builder_shell_vm_name(job_id: &str) -> String {
    format!("{BUILDER_SHELL_JOB_PREFIX}{job_id}")
}

/// True when `name` is a VM the build system owns rather than one the user
/// asked for.
///
/// These VMs write their runtime state into the same `~/.mvm/vms/` namespace
/// as workload machines, so every surface that presents "the user's machines"
/// has to exclude them by name — there is no other discriminator on disk. The
/// predicate lives beside the two minting functions above so a change to the
/// name format cannot silently stop matching.
pub fn is_builder_owned_vm_name(name: &str) -> bool {
    name.starts_with(PERSISTENT_BUILDER_PREFIX) || is_ephemeral_builder_vm_name(name)
}

/// True when `name` is a per-job builder VM: state that exists only for the
/// duration of one build and is safe to remove once nothing owns it.
///
/// The persistent builder is deliberately excluded — its dir is its warm Nix
/// store, and reaping it would throw away the cache it exists to hold.
pub fn is_ephemeral_builder_vm_name(name: &str) -> bool {
    name.starts_with(BUILDER_SHELL_JOB_PREFIX)
}

/// Generate a random instance ID: "i-" followed by 8 hex chars.
pub fn generate_instance_id() -> String {
    let bytes: [u8; 4] = rand_bytes();
    format!(
        "i-{}",
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    )
}

/// Generate a human-friendly VM name, e.g. "brisk-otter-a1b2".
///
/// The suffix keeps the name collision-resistant while preserving a stable,
/// easy-to-say shape for CLI output and logs.
pub fn generate_machine_name() -> String {
    const ADJECTIVES: &[&str] = &[
        "brisk", "calm", "clever", "cozy", "dapper", "fuzzy", "gentle", "glossy", "happy",
        "lively", "merry", "nimble", "plucky", "quiet", "snug", "sunny",
    ];
    const ANIMALS: &[&str] = &[
        "badger", "beaver", "finch", "gecko", "heron", "koala", "lemur", "lynx", "marten", "otter",
        "panda", "pika", "puffin", "quokka", "stoat", "wombat",
    ];

    let bytes = rand_bytes();
    let adjective = ADJECTIVES[usize::from(bytes[0]) % ADJECTIVES.len()];
    let animal = ANIMALS[usize::from(bytes[1]) % ANIMALS.len()];
    let suffix = u16::from_be_bytes([bytes[2], bytes[3]]);
    format!("{adjective}-{animal}-{suffix:04x}")
}

/// Generate a TAP device name: tn<net_id>i<ip_offset>.
/// Max 12 chars, fits within Linux 15-char IFNAMSIZ limit.
pub fn tap_name(tenant_net_id: u16, ip_offset: u8) -> String {
    format!("tn{}i{}", tenant_net_id, ip_offset)
}

/// Deterministic MAC address from tenant_net_id and ip_offset.
/// Format: 02:xx:xx:xx:xx:xx (locally administered).
pub fn mac_address(tenant_net_id: u16, ip_offset: u8) -> String {
    let net_bytes = tenant_net_id.to_be_bytes();
    format!(
        "02:fc:{:02x}:{:02x}:00:{:02x}",
        net_bytes[0], net_bytes[1], ip_offset
    )
}

/// Simple random bytes using uuid crate (already a dependency).
fn rand_bytes() -> [u8; 4] {
    let id = uuid::Uuid::new_v4();
    let bytes = id.as_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

/// Parse a "tenant/pool" or "tenant/pool/instance" path.
pub fn parse_pool_path(path: &str) -> Result<(&str, &str)> {
    let parts: Vec<&str> = path.splitn(3, '/').collect();
    if parts.len() < 2 {
        bail!("Expected <tenant>/<pool>, got {:?}", path);
    }
    Ok((parts[0], parts[1]))
}

/// Parse a "tenant/pool/instance" path.
pub fn parse_instance_path(path: &str) -> Result<(&str, &str, &str)> {
    let parts: Vec<&str> = path.splitn(4, '/').collect();
    if parts.len() < 3 {
        bail!("Expected <tenant>/<pool>/<instance>, got {:?}", path);
    }
    Ok((parts[0], parts[1], parts[2]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the predicate is that it recognises what the
    /// minting functions produce; asserting against a hand-written literal
    /// would let the two drift apart and still pass.
    #[test]
    fn builder_vm_names_are_recognised_as_builder_owned() {
        for slot in [BuilderVmSlot::Libkrun, BuilderVmSlot::Hvf] {
            let name = persistent_builder_vm_name(slot, "abc123");
            assert!(
                is_builder_owned_vm_name(&name),
                "{name:?} must read as builder-owned"
            );
            assert!(
                !is_ephemeral_builder_vm_name(&name),
                "{name:?} is the warm store and must never read as ephemeral"
            );
        }
        let job = builder_shell_vm_name("92326-1787337475138993000");
        assert!(is_builder_owned_vm_name(&job));
        assert!(is_ephemeral_builder_vm_name(&job));
    }

    /// The slot tokens are the on-disk state-dir infixes documented in
    /// CLAUDE.md; changing one strands existing builder state.
    #[test]
    fn builder_slot_tokens_are_the_documented_on_disk_names() {
        assert_eq!(
            persistent_builder_vm_name(BuilderVmSlot::Libkrun, "s"),
            "mvm-persistent-builder-vm-s"
        );
        assert_eq!(
            persistent_builder_vm_name(BuilderVmSlot::Hvf, "s"),
            "mvm-persistent-builder-hvf-s"
        );
        assert_eq!(builder_shell_vm_name("j"), "mvm-hvf-builder-shell-j");
    }

    #[test]
    fn a_user_machine_name_is_not_builder_owned() {
        for name in ["web", "builder", "mvm-builder", "my-persistent-builder-vm"] {
            assert!(
                !is_builder_owned_vm_name(name),
                "{name:?} is a user machine"
            );
        }
    }

    #[test]
    fn test_validate_id_valid() {
        assert!(validate_id("acme", "Tenant").is_ok());
        assert!(validate_id("my-pool-1", "Pool").is_ok());
        assert!(validate_id("a", "Tenant").is_ok());
    }

    #[test]
    fn test_validate_id_invalid() {
        assert!(validate_id("", "Tenant").is_err());
        assert!(validate_id("UPPER", "Tenant").is_err());
        assert!(validate_id("-leading", "Tenant").is_err());
        assert!(validate_id("trailing-", "Tenant").is_err());
        assert!(validate_id("has space", "Tenant").is_err());
        assert!(validate_id(&"a".repeat(64), "Tenant").is_err());
    }

    #[test]
    fn test_tap_name() {
        assert_eq!(tap_name(3, 5), "tn3i5");
        assert_eq!(tap_name(4095, 254), "tn4095i254");
    }

    #[test]
    fn test_tap_name_fits_linux_limit() {
        // Worst case: tn4095i254 = 10 chars, under 15
        let name = tap_name(4095, 254);
        assert!(name.len() <= 15, "TAP name too long: {}", name);
    }

    #[test]
    fn test_mac_address_format() {
        let mac = mac_address(3, 5);
        assert!(mac.starts_with("02:fc:"));
        assert_eq!(mac.len(), 17);
    }

    #[test]
    fn test_generate_instance_id_format() {
        let id = generate_instance_id();
        assert!(id.starts_with("i-"));
        assert_eq!(id.len(), 10); // "i-" + 8 hex chars
    }

    #[test]
    fn test_generate_machine_name_is_valid_vm_name() {
        let name = generate_machine_name();
        validate_vm_name(&name).unwrap_or_else(|e| panic!("generated name {name:?}: {e}"));
        assert!(
            name.split('-').count() == 3,
            "expected adjective-animal-hex, got {name:?}"
        );
    }

    #[test]
    fn test_parse_pool_path() {
        let (t, p) = parse_pool_path("acme/workers").unwrap();
        assert_eq!(t, "acme");
        assert_eq!(p, "workers");
    }

    #[test]
    fn test_parse_instance_path() {
        let (t, p, i) = parse_instance_path("acme/workers/i-a3f7b2c1").unwrap();
        assert_eq!(t, "acme");
        assert_eq!(p, "workers");
        assert_eq!(i, "i-a3f7b2c1");
    }

    // validate_vm_name
    #[test]
    fn test_validate_vm_name_valid() {
        assert!(validate_vm_name("myvm").is_ok());
        assert!(validate_vm_name("my-vm-1").is_ok());
        assert!(validate_vm_name("a").is_ok());
        assert!(validate_vm_name(&"a".repeat(63)).is_ok());
    }

    #[test]
    fn test_validate_vm_name_empty() {
        assert!(validate_vm_name("").is_err());
    }

    #[test]
    fn test_validate_vm_name_too_long() {
        assert!(validate_vm_name(&"a".repeat(64)).is_err());
    }

    #[test]
    fn test_validate_vm_name_uppercase() {
        assert!(validate_vm_name("MyVM").is_err());
    }

    #[test]
    fn test_validate_vm_name_leading_hyphen() {
        assert!(validate_vm_name("-bad").is_err());
    }

    #[test]
    fn test_validate_vm_name_special_chars() {
        assert!(validate_vm_name("vm;evil").is_err());
        assert!(validate_vm_name("vm name").is_err());
        assert!(validate_vm_name("vm/path").is_err());
    }

    // validate_template_name
    #[test]
    fn test_validate_template_name_valid() {
        assert!(validate_template_name("base").is_ok());
        assert!(validate_template_name("my-template").is_ok());
        assert!(validate_template_name("my_template").is_ok());
        assert!(validate_template_name("worker1").is_ok());
    }

    #[test]
    fn test_validate_template_name_empty() {
        assert!(validate_template_name("").is_err());
    }

    #[test]
    fn test_validate_template_name_leading_hyphen() {
        assert!(validate_template_name("-bad").is_err());
    }

    #[test]
    fn test_validate_template_name_special_chars() {
        assert!(validate_template_name("bad;name").is_err());
        assert!(validate_template_name("bad name").is_err());
    }

    #[test]
    fn test_validate_template_name_too_long() {
        assert!(validate_template_name(&"a".repeat(64)).is_err());
    }

    // validate_flake_ref
    #[test]
    fn test_validate_flake_ref_valid() {
        assert!(validate_flake_ref(".").is_ok());
        assert!(validate_flake_ref("./my-flake").is_ok());
        assert!(validate_flake_ref("github:org/repo").is_ok());
        assert!(validate_flake_ref("git+https://github.com/org/repo").is_ok());
        assert!(validate_flake_ref("/absolute/path").is_ok());
    }

    #[test]
    fn test_validate_flake_ref_empty() {
        assert!(validate_flake_ref("").is_err());
    }

    #[test]
    fn test_validate_flake_ref_semicolon() {
        assert!(validate_flake_ref(". ; rm -rf /").is_err());
    }

    #[test]
    fn test_validate_flake_ref_pipe() {
        assert!(validate_flake_ref(".|evil").is_err());
    }

    #[test]
    fn test_validate_flake_ref_dollar() {
        assert!(validate_flake_ref("$(evil)").is_err());
    }

    #[test]
    fn test_validate_flake_ref_newline() {
        assert!(validate_flake_ref("flake\nmalicious").is_err());
    }
}
