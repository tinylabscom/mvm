//! Compile-time contract between `mvmctl` and the per-VM host helper
//! binaries it spawns (`mvm-hvf-supervisor`, `mvm-libkrun-supervisor`,
//! `mvm-network-endpoint`, and `mvmctl` itself when the qemu bridge re-execs
//! it).
//!
//! Both sides of every host↔helper config pipe are compiled from the same
//! source tree, so each binary carries the same
//! [`HOST_HELPER_CONTRACT_VERSION`]. A binary built from an older revision —
//! or from the other cargo profile, which cargo never rebuilds across —
//! carries a different one. `aux_bin::resolve_verified` asks the resolved
//! helper for its version before spawning it, so a stale helper is rebuilt
//! or refused instead of failing mid-boot with a JSON parse error.
//!
//! Bump [`HOST_HELPER_CONTRACT_VERSION`] whenever any host↔helper config
//! contract changes incompatibly. The shape-pin tests (one per strict config
//! type, e.g. `HvfSupervisorConfig`) force that bump: they hash the
//! serialized struct and compare against a pin stored in this file, so a
//! contract change without a version bump fails the test suite.

/// Version of the host↔helper config contract this build speaks.
///
/// Helpers compiled from the same tree answer the
/// [`CONTRACT_PROBE_FLAG`] probe with this value; `mvmctl` refuses to spawn
/// a helper that answers differently.
pub const HOST_HELPER_CONTRACT_VERSION: u32 = 1;

/// CLI flag every host helper answers by printing its contract version and
/// exiting 0. Binaries built before the probe existed exit non-zero instead,
/// which the resolver reads as "stale" — that is the whole point.
pub const CONTRACT_PROBE_FLAG: &str = "--contract-version";

/// Response body a helper prints for [`CONTRACT_PROBE_FLAG`]:
/// `<bin> contract-version=<N>` followed by a newline.
pub fn probe_response(bin: &str) -> String {
    format!("{bin} {CONTRACT_PROBE_KEY}={HOST_HELPER_CONTRACT_VERSION}\n")
}

const CONTRACT_PROBE_KEY: &str = "contract-version";

/// Whether an argv (including argv\[0\]) requests the contract probe, so a
/// helper's `main` can answer it before doing anything else.
pub fn probe_requested(mut args: impl Iterator<Item = String>) -> bool {
    args.next();
    args.any(|arg| arg == CONTRACT_PROBE_FLAG)
}

/// Answer the contract probe and exit 0 when it was requested; do nothing
/// otherwise. Every host helper's `main` calls this as its first statement,
/// before panic hooks, self-signing, or config reads — the probe must stay
/// cheap and side-effect-free so `aux_bin::resolve_verified` can run it on
/// every spawn.
pub fn exit_with_probe_answer_if_requested(bin: &str) {
    if probe_requested(std::env::args()) {
        print!("{}", probe_response(bin));
        std::process::exit(0);
    }
}

/// Parse the version out of a helper's probe stdout.
///
/// Strict on purpose: exactly `<anything> contract-version=<u32>` on the
/// first line. A looser parse would let an unrelated crash banner read as a
/// version answer.
pub fn parse_probe_version(stdout: &str) -> Option<u32> {
    let line = stdout.lines().next()?.trim_end();
    let (name, rest) = line.split_once(' ')?;
    if name.is_empty() {
        return None;
    }
    rest.strip_prefix(CONTRACT_PROBE_KEY)?
        .strip_prefix('=')?
        .parse()
        .ok()
}

/// FNV-1a over the canonical JSON of a fully populated
/// [`crate::host::hvf_supervisor::HvfSupervisorConfig`]. The shape-pin test
/// in that module recomputes this and compares — changing the struct's
/// fields without updating this pin (and bumping the contract version)
/// fails the test suite. Test-only because it exists solely for that test.
#[cfg(test)]
pub(crate) const HVF_CONFIG_SHAPE_HASH: u64 = 0x319f_4039_b7ab_fb40;

/// 64-bit FNV-1a, implemented inline so the shape pins have no dependency.
#[cfg(test)]
pub(crate) fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_response_round_trips_through_the_parser() {
        let response = probe_response("mvm-hvf-supervisor");
        assert_eq!(
            parse_probe_version(&response),
            Some(HOST_HELPER_CONTRACT_VERSION)
        );
    }

    #[test]
    fn parser_accepts_any_binary_name() {
        assert_eq!(parse_probe_version("mvmctl contract-version=7\n"), Some(7));
    }

    #[test]
    fn parser_rejects_garbage() {
        for stdout in [
            "",
            "\n",
            "mvm-hvf-supervisor\n",
            "contract-version=1\n",
            "mvm-hvf-supervisor contract-version=\n",
            "mvm-hvf-supervisor contract-version=1 extra\n",
            "mvm-hvf-supervisor contract-version=1x\n",
            "mvm-hvf-supervisor contract-version=-1\n",
            "mvm-hvf-supervisor contract-version= 1\n",
            "panic: something broke contract-version=3\n",
        ] {
            assert_eq!(parse_probe_version(stdout), None, "input: {stdout:?}");
        }
    }

    #[test]
    fn parser_reads_only_the_first_line() {
        assert_eq!(
            parse_probe_version("mvm-hvf-supervisor contract-version=2\nnoise\n"),
            Some(2)
        );
        assert_eq!(parse_probe_version("noise\nmvm contract-version=2\n"), None);
    }

    #[test]
    fn probe_requested_finds_the_flag_anywhere_after_argv0() {
        assert!(probe_requested(
            [
                "mvm-hvf-supervisor".to_string(),
                "--contract-version".to_string()
            ]
            .into_iter()
        ));
        assert!(probe_requested(
            [
                "mvmctl".to_string(),
                "__qemu-vsock-bridge".to_string(),
                "--contract-version".to_string()
            ]
            .into_iter()
        ));
        assert!(!probe_requested(
            ["mvm-hvf-supervisor".to_string()].into_iter()
        ));
        assert!(!probe_requested(
            ["mvm-hvf-supervisor".to_string(), "--verbose".to_string()].into_iter()
        ));
    }

    #[test]
    fn fnv1a_matches_the_reference_value() {
        // Published FNV-1a test vector (from the FNV reference page).
        assert_eq!(fnv1a_64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a_64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a_64(b"foobar"), 0x8594_4171_f739_67e8);
    }
}
