use super::RunProfile;
use clap::Args as ClapArgs;
use std::path::PathBuf;

/// Optional source/config flags for `machine start`. When a persistent machine
/// does not already exist, these flags are used to create it on demand.
#[derive(ClapArgs, Debug, Clone, Default)]
pub(in crate::commands) struct MachineStartCreateFlags {
    /// OCI image reference to boot when creating the machine.
    #[arg(long, value_name = "REF", conflicts_with = "manifest")]
    pub image: Option<String>,
    /// Image-backed machine manifest to source defaults from.
    #[arg(long, value_name = "PATH", conflicts_with = "image")]
    pub manifest: Option<String>,
    /// Enable dev-tier outbound networking for the created machine.
    #[arg(long)]
    pub net: bool,
    /// Allow egress only to these hosts: `HOST[:PORT]` (repeatable).
    #[arg(long = "allow-host", value_name = "HOST[:PORT]")]
    pub allow_host: Vec<String>,
    /// Bind a peer route this machine may dial (repeatable).
    #[arg(long = "peer", value_name = "NAME:PORT=ADDR:PORT")]
    pub peer: Vec<String>,
    /// Forward the guest's CUDA/NVML calls to a host GPU over vsock.
    #[arg(long)]
    pub gpu: bool,
    /// Pin this machine to one host GPU ordinal, exposed as guest device zero.
    #[arg(long, value_name = "ORDINAL")]
    pub gpu_device: Option<u32>,
    /// vCPU cores the guest sees on lifecycle starts (not a host CPU share).
    #[arg(long)]
    pub cpus: Option<u32>,
    /// Cap host CPU time in millicores (1500 = 1.5 cores); not `--cpus`.
    #[arg(long = "cpu-limit", value_name = "MILLICORES")]
    pub cpu_limit: Option<u32>,
    /// Bound each start's wall-clock runtime in seconds.
    #[arg(long, value_name = "SECS")]
    pub timeout: Option<u64>,
    /// Read grants (CPU, wall clock, egress) from a JSON file.
    #[arg(long = "grants-file", value_name = "PATH")]
    pub grants_file: Option<PathBuf>,
    /// Memory for lifecycle starts (supports human-readable: 512M, 1G, ...).
    #[arg(long)]
    pub memory: Option<String>,
    /// Optional initial host memory commitment for lifecycle starts.
    #[arg(long, value_name = "SIZE")]
    pub mem_initial: Option<String>,
    /// Security profile for lifecycle starts.
    #[arg(long, value_enum)]
    pub profile: Option<RunProfile>,
    /// Overwrite an existing machine spec if the config changed.
    #[arg(long)]
    pub force: bool,
}
