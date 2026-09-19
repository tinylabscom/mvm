//! Permanent guard for the single view-only display transport.

use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::fs_walk::for_each_file;
use crate::rust_source::blank_comments_and_strings;

const CONTRACT: &str = "crates/mvm-contract/src/stream/display.rs";
const GUEST_BRIDGE: &str = "crates/mvm-agentd/src/display_bridge.rs";
const GUEST_BRIDGE_BIN: &str = "crates/mvm-agentd/src/bin/mvm-display-bridge.rs";
const SPEC_MAP: &str = "crates/mvm-vmm/src/host/spec_map.rs";
const HOST_PLANE: &str = "crates/mvm-hostd/src/stream/plane.rs";
const HOST_SOURCE: &str = "crates/mvm-hostd/src/stream/display_source.rs";
const VIEWER: &str = "crates/mvm-cli/src/commands/vm/display.rs";

pub fn run(workspace: &Path) -> Result<()> {
    let contract = production(&read(workspace, CONTRACT)?);
    if contract.matches("pub const DISPLAY_FRAME_PORT").count() != 1 {
        bail!("check-single-display-path: the display port must have one contract definition");
    }

    let spec = production(&read(workspace, SPEC_MAP)?);
    if spec.matches("service: GuestService::DisplayFrame").count() != 1 {
        bail!(
            "check-single-display-path: the shared workload spec must project exactly one display channel"
        );
    }

    let mut spawn_sites = Vec::new();
    for_each_file(
        &workspace.join("crates"),
        Some("rs"),
        &mut |path, source| {
            let code = production(source);
            for (index, _) in code.match_indices("DisplaySource::listen(") {
                let line = code[..index].bytes().filter(|byte| *byte == b'\n').count() + 1;
                let relative = path.strip_prefix(workspace).unwrap_or(path);
                spawn_sites.push(format!("{}:{line}", relative.display()));
            }
        },
    )?;
    let owners = spawn_sites
        .iter()
        .filter_map(|site| site.split(':').next())
        .collect::<Vec<_>>();
    if owners != [HOST_PLANE] {
        bail!(
            "check-single-display-path: expected exactly one display spawn site in {HOST_PLANE}, found {spawn_sites:?}"
        );
    }

    let source = production(&read(workspace, HOST_SOURCE)?);
    if source.contains("write_all(") || source.contains("impl Write") {
        bail!(
            "check-single-display-path: the host display source must remain read-only toward the guest"
        );
    }

    let bridge = production(&read(workspace, GUEST_BRIDGE)?);
    let bridge_bin = production(&read(workspace, GUEST_BRIDGE_BIN)?);
    for forbidden in ["TcpListener", "UnixListener", "::bind("] {
        if bridge.contains(forbidden) || bridge_bin.contains(forbidden) {
            bail!(
                "check-single-display-path: the guest display bridge must not listen ({forbidden})"
            );
        }
    }
    if bridge_bin.matches("bridge_session(").count() != 1
        || bridge_bin
            .matches("connect_host_vsock(DISPLAY_PORT")
            .count()
            != 1
    {
        bail!(
            "check-single-display-path: the guest must have one bridge entry point dialing the one display port"
        );
    }
    for required in [
        "Page.enable",
        "Page.startScreencast",
        "Page.screencastFrameAck",
        "Page.stopScreencast",
    ] {
        if !read(workspace, GUEST_BRIDGE)?.contains(required) {
            bail!("check-single-display-path: the fixed CDP allow-list lost {required}");
        }
    }

    let viewer = production(&read(workspace, VIEWER)?);
    if viewer.matches("TcpListener::bind(").count() != 1
        || !viewer.contains("TcpListener::bind((Ipv4Addr::LOCALHOST, 0))")
    {
        bail!("check-single-display-path: the viewer must have one non-configurable loopback bind");
    }
    for forbidden in ["0.0.0.0", "Ipv4Addr::UNSPECIFIED", "[::]"] {
        if viewer.contains(forbidden) {
            bail!("check-single-display-path: viewer contains non-loopback bind {forbidden}");
        }
    }

    eprintln!(
        "check-single-display-path: clean — one vsock channel, one host sink, no guest listener or host-to-guest source write, and one loopback-only viewer"
    );
    Ok(())
}

fn read(workspace: &Path, relative: &str) -> Result<String> {
    std::fs::read_to_string(workspace.join(relative)).with_context(|| format!("read {relative}"))
}

fn production(source: &str) -> String {
    blank_comments_and_strings(source.split("#[cfg(test)]").next().unwrap_or(source))
}
