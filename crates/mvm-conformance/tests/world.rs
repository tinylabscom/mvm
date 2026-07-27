//! Shared state cucumber threads through the steps of one scenario.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::process::Output;

use mvm_core::kernel_advisory::{KernelAdvisory, KernelPin};
use mvm_core::kernel_format::KernelFormat;
use mvm_fs::snapshot_store::{FsSnapshotStore, SnapshotId};

/// Constructed fresh for every scenario. Holds the result of the most
/// recent CLI invocation so later `Then` steps can assert on it, plus the
/// workload identities parsed from successful `build address` runs, keyed by
/// fixture name.
#[derive(cucumber::World, Default)]
pub struct CliWorld {
    pub last_run: Option<Output>,
    /// `semantic_address` per fixture name, populated on a zero-exit
    /// `build address` run.
    pub addresses: HashMap<String, String>,
    /// `ir_hash` per fixture name, from the same run as `addresses`.
    pub ir_hashes: HashMap<String, String>,
    /// Full sealed-workload cmdline assembled through a real VMM driver.
    pub workload_cmdline: Option<String>,
    /// Kernel format mapped by the libkrun supervisor-config seam.
    pub libkrun_kernel_format: Option<KernelFormat>,
    /// An isolated `MVM_HOME` created by a `Given` step and reused by later
    /// steps that need to inspect the filesystem after a run.
    pub isolated_home: Option<tempfile::TempDir>,
    /// Whether live CLI steps should keep one warm standby for the next run.
    pub warm_residency: bool,
    /// Local kernel pins accumulated by the freshness-watcher scenarios.
    pub kernel_pins: Vec<KernelPin>,
    /// Latest upstream point release per `MAJOR.MINOR` series, as those same
    /// scenarios stage it before assessing.
    pub kernel_upstream: BTreeMap<String, String>,
    /// The verdict from the most recent freshness assessment.
    pub kernel_advisory: Option<KernelAdvisory>,
    /// Root directory for the OCI unpack scenarios.
    pub unpack_root: Option<tempfile::TempDir>,
    /// Paths written by prior layers when unpacking multiple layers.
    pub prior_layer_paths: HashSet<PathBuf>,
    /// The most recent OCI unpack report.
    pub last_unpack_report: Option<mvm_fs::oci::UnpackReport>,
    /// Scratch directory backing the warm-snapshot scenarios: holds the
    /// snapshot store root, the synthetic template rootfs artifact, and
    /// every materialized instance path.
    pub snapshot_tmp: Option<tempfile::TempDir>,
    /// The content-addressed snapshot store opened by a warm-snapshot
    /// `Given` step.
    pub snapshot_store: Option<FsSnapshotStore>,
    /// The id returned when the template rootfs artifact was stored.
    pub snapshot_id: Option<SnapshotId>,
    /// Path to the synthetic template rootfs artifact, kept so later steps
    /// can re-store it and assert dedup.
    pub snapshot_source_path: Option<PathBuf>,
    /// Bytes of the synthetic template rootfs artifact, for byte-equality
    /// assertions against materialized instances.
    pub snapshot_source_bytes: Option<Vec<u8>>,
    /// Path of the most recently materialized instance.
    pub snapshot_instance_path: Option<PathBuf>,
}

impl fmt::Debug for CliWorld {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CliWorld")
            .field("last_run", &self.last_run)
            .field("addresses", &self.addresses)
            .field("ir_hashes", &self.ir_hashes)
            .field("workload_cmdline", &self.workload_cmdline)
            .field("libkrun_kernel_format", &self.libkrun_kernel_format)
            .field(
                "isolated_home",
                &self.isolated_home.as_ref().map(|t| t.path().to_path_buf()),
            )
            .field("warm_residency", &self.warm_residency)
            .field("kernel_pins", &self.kernel_pins)
            .field("kernel_upstream", &self.kernel_upstream)
            .field("kernel_advisory", &self.kernel_advisory)
            .finish()
    }
}

impl CliWorld {
    /// The `Output` of the most recent CLI invocation, or a failed
    /// assertion naming the step that forgot to run one first.
    pub fn last_output(&self) -> &Output {
        self.last_run
            .as_ref()
            .expect("no CLI invocation recorded yet — a prior `When` step must run one")
    }

    /// The stored semantic address for `fixture`, or a failed assertion
    /// naming the fixture whose `When` step didn't run (or didn't succeed).
    pub fn address_of(&self, fixture: &str) -> &str {
        self.addresses.get(fixture).unwrap_or_else(|| {
            panic!(
                "no address recorded for {fixture:?} — its `When` step must run and succeed first"
            )
        })
    }

    /// The advisory from the most recent freshness assessment, or a failed
    /// assertion naming the missing `When` step.
    pub fn advisory(&self) -> &KernelAdvisory {
        self.kernel_advisory
            .as_ref()
            .expect("no advisory recorded yet — a prior `When` step must assess freshness")
    }
}
