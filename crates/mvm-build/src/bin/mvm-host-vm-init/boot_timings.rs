//! Per-phase cold-path timings for the builder VM. Plan 76 Phase 5.
//!
//! The builder VM init pipeline has obvious points where time is
//! spent (pseudofs mount, /dev/vdb format-or-mount, /nix-store seed,
//! virtio-fs share mount, network up, job execution). When a user
//! sees `mvmctl build` take longer than expected, the right question
//! is "which phase ate the wall clock?" — and the right answer is a
//! per-phase millisecond breakdown written next to `/job/result` so
//! the host can surface it through `mvmctl boot-report` (Phase 4)
//! without parsing console logs.
//!
//! **Wire shape.** JSON object, hand-rolled with the same JSON
//! escaper used for `/job/result` so we don't pull `serde_json` into
//! the builder-init crate's size budget (Plan 72 W3 caps the
//! static-linked init at 1.5 MiB). Every field is `u64` ms-since-
//! init-start or `null` for "phase didn't run this boot" (e.g.
//! `nix_seeded_ms` on a second-boot reuse).
//!
//! **Anchor.** `init_start_ms` is always `0`. All other timings are
//! `Instant::now().duration_since(boot_at).as_millis()` against the
//! `BootTimings::new()` call's anchor. That anchor sits as close to
//! `linux::run`'s entry as we can get; the few milliseconds spent
//! pre-anchor are constant across boots and uninteresting.
//!
//! **Module shape.** Cross-platform so `cargo test` on macOS hosts
//! exercises the JSON writer without paying for a Linux cross-
//! compile. The Linux-only `linux` module in `main.rs` is the only
//! caller; macOS / non-Linux builds compile this module but never
//! call into it. `#[allow(dead_code)]` at the `mod` site in `main.rs`
//! handles the workspace-ergonomics dead-code warning the same way
//! `install` and `proxy` are handled.

use std::time::Instant;

/// Per-phase cold-path timings, in ms since `init_start_ms`.
///
/// `None` means "this phase didn't run on this boot" — for example,
/// `nix_seeded_ms` stays `None` on the second + subsequent boots
/// because the persistent store is already populated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BootTimings {
    /// Anchor — always `Some(0)` once stamped. Cheaper to keep the
    /// `Option` shape than to special-case the first field.
    pub init_start_ms: Option<u64>,
    /// `/proc`, `/sys`, `/dev`, `/tmp` mounted.
    pub pseudofs_ready_ms: Option<u64>,
    /// `/dev/vdb` formatted (only stamped on the first boot of a
    /// fresh image) and mounted at `/nix-store`.
    pub nix_device_ready_ms: Option<u64>,
    /// `/nix-store` seeded from the rootfs's `/nix/store`.
    /// `None` on second-boot reuse where the seed was skipped.
    pub nix_seeded_ms: Option<u64>,
    /// `/nix-store` bind-mounted over `/nix`.
    pub nix_mounted_ms: Option<u64>,
    /// `/nix-path-registration` loaded into `/nix/var/nix/db` so
    /// nix-daemon skips re-substituting the seeded closure. `None`
    /// on subsequent boots where the sentinel
    /// (`/nix-store/.seed-db-loaded`) is present and registration
    /// is skipped.
    pub nix_db_loaded_ms: Option<u64>,
    /// `fuse` + `virtiofs` kernel modules loaded.
    pub modules_ready_ms: Option<u64>,
    /// All virtio-fs shares (`job`, `out`, `work`) mounted.
    pub virtiofs_ready_ms: Option<u64>,
    /// Network up (DHCP successful). `None` on offline builds.
    pub network_ready_ms: Option<u64>,
    /// User's `cmd.sh` / install pipeline started executing.
    pub job_start_ms: Option<u64>,
    /// User's `cmd.sh` / install pipeline returned.
    pub job_end_ms: Option<u64>,
    /// `reboot(RB_POWER_OFF)` about to be invoked. The host sees
    /// the shutdown-eventfd shortly after.
    pub poweroff_start_ms: Option<u64>,
}

impl BootTimings {
    /// Stamp `init_start_ms = 0` against `anchor`. Subsequent
    /// `mark_*` calls measure ms since `anchor`.
    pub fn new(anchor: Instant) -> (Self, Instant) {
        let t = Self {
            init_start_ms: Some(0),
            ..Self::default()
        };
        // Return both the struct and the anchor so callers don't
        // have to thread `Instant` separately.
        (t, anchor)
    }

    /// Convert an `Instant` to "ms since `anchor`", saturating on
    /// the absurd. The builder VM's lifetime is bounded by the
    /// host's `mvmctl build --timeout` and the job's own deadline
    /// — neither ever approaches `u64::MAX` ms — but we saturate
    /// rather than panic to keep init crash-safe.
    pub fn ms_since(anchor: Instant) -> u64 {
        u64::try_from(anchor.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Render the struct as a single-line JSON object using the
    /// same escape discipline as `/job/result`. Hand-rolled to
    /// avoid pulling `serde_json` into the size budget.
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push('{');
        Self::push_field(&mut out, "init_start_ms", self.init_start_ms, true);
        Self::push_field(&mut out, "pseudofs_ready_ms", self.pseudofs_ready_ms, false);
        Self::push_field(
            &mut out,
            "nix_device_ready_ms",
            self.nix_device_ready_ms,
            false,
        );
        Self::push_field(&mut out, "nix_seeded_ms", self.nix_seeded_ms, false);
        Self::push_field(&mut out, "nix_mounted_ms", self.nix_mounted_ms, false);
        Self::push_field(&mut out, "nix_db_loaded_ms", self.nix_db_loaded_ms, false);
        Self::push_field(&mut out, "modules_ready_ms", self.modules_ready_ms, false);
        Self::push_field(&mut out, "virtiofs_ready_ms", self.virtiofs_ready_ms, false);
        Self::push_field(&mut out, "network_ready_ms", self.network_ready_ms, false);
        Self::push_field(&mut out, "job_start_ms", self.job_start_ms, false);
        Self::push_field(&mut out, "job_end_ms", self.job_end_ms, false);
        Self::push_field(&mut out, "poweroff_start_ms", self.poweroff_start_ms, false);
        out.push('}');
        out
    }

    fn push_field(out: &mut String, name: &str, value: Option<u64>, first: bool) {
        if !first {
            out.push(',');
        }
        out.push('"');
        out.push_str(name);
        out.push_str("\":");
        match value {
            Some(v) => out.push_str(&v.to_string()),
            None => out.push_str("null"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_all_none_except_no_anchor() {
        let t = BootTimings::default();
        assert!(t.init_start_ms.is_none());
        assert!(t.pseudofs_ready_ms.is_none());
        assert!(t.job_start_ms.is_none());
        assert!(t.poweroff_start_ms.is_none());
    }

    #[test]
    fn new_anchors_init_start_at_zero() {
        let (t, _anchor) = BootTimings::new(Instant::now());
        assert_eq!(t.init_start_ms, Some(0));
        assert!(t.pseudofs_ready_ms.is_none());
    }

    #[test]
    fn ms_since_returns_monotonic_elapsed() {
        let anchor = Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(3));
        let elapsed = BootTimings::ms_since(anchor);
        // Allow some slack — CI runners are noisy — but make sure
        // the elapsed time is at least 1 ms (rules out a frozen
        // clock or anchor mishandling).
        assert!(elapsed >= 1, "expected >= 1 ms, got {elapsed}");
    }

    #[test]
    fn to_json_emits_all_fields_in_stable_order() {
        let t = BootTimings {
            init_start_ms: Some(0),
            pseudofs_ready_ms: Some(12),
            nix_device_ready_ms: Some(18),
            nix_seeded_ms: None,
            nix_mounted_ms: Some(220),
            nix_db_loaded_ms: Some(225),
            modules_ready_ms: Some(35),
            virtiofs_ready_ms: Some(48),
            network_ready_ms: Some(250),
            job_start_ms: Some(260),
            job_end_ms: Some(8400),
            poweroff_start_ms: Some(8410),
        };
        let json = t.to_json();
        // Field order is the wire contract for downstream parsers
        // that key off ordering (e.g. shell scripts using `jq -c`
        // and pipe ordering for visual diff).
        assert_eq!(
            json,
            "{\"init_start_ms\":0,\
             \"pseudofs_ready_ms\":12,\
             \"nix_device_ready_ms\":18,\
             \"nix_seeded_ms\":null,\
             \"nix_mounted_ms\":220,\
             \"nix_db_loaded_ms\":225,\
             \"modules_ready_ms\":35,\
             \"virtiofs_ready_ms\":48,\
             \"network_ready_ms\":250,\
             \"job_start_ms\":260,\
             \"job_end_ms\":8400,\
             \"poweroff_start_ms\":8410}"
        );
    }

    #[test]
    fn to_json_emits_null_for_missing_phases() {
        // Cold-tier second boot: no seed, no network (offline),
        // DB already loaded on prior boot so skipped.
        let t = BootTimings {
            init_start_ms: Some(0),
            pseudofs_ready_ms: Some(7),
            nix_device_ready_ms: Some(11),
            nix_seeded_ms: None,
            nix_mounted_ms: Some(15),
            nix_db_loaded_ms: None,
            modules_ready_ms: Some(22),
            virtiofs_ready_ms: Some(30),
            network_ready_ms: None,
            job_start_ms: Some(40),
            job_end_ms: Some(120),
            poweroff_start_ms: Some(125),
        };
        let json = t.to_json();
        assert!(json.contains("\"nix_seeded_ms\":null"), "got {json}");
        assert!(json.contains("\"nix_db_loaded_ms\":null"), "got {json}");
        assert!(json.contains("\"network_ready_ms\":null"), "got {json}");
    }

    #[test]
    fn to_json_round_trip_through_serde_json_value_parses_cleanly() {
        // Belt + suspenders: hand-rolled JSON must still parse as
        // valid JSON via a real parser. Test-only dev-dep on
        // serde_json (already transitive through the workspace);
        // no impact on the builder-init binary's size.
        let t = BootTimings {
            init_start_ms: Some(0),
            pseudofs_ready_ms: Some(12),
            nix_device_ready_ms: Some(18),
            nix_seeded_ms: None,
            nix_mounted_ms: Some(220),
            nix_db_loaded_ms: Some(225),
            modules_ready_ms: Some(35),
            virtiofs_ready_ms: Some(48),
            network_ready_ms: Some(250),
            job_start_ms: Some(260),
            job_end_ms: Some(8400),
            poweroff_start_ms: Some(8410),
        };
        let json = t.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parses as JSON");
        assert_eq!(parsed["init_start_ms"], 0);
        assert_eq!(parsed["nix_seeded_ms"], serde_json::Value::Null);
        assert_eq!(parsed["network_ready_ms"], 250);
    }
}
