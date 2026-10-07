//! Permanent guard for the single display transport: view-only frames out,
//! and attended input in only through the gate, the agent and one FIFO.

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
const ATTENDED_VIEWER: &str = "crates/mvm-cli/src/commands/vm/display/attended.rs";
const GUEST_INPUT: &str = "crates/mvm-agentd/src/display_input.rs";
const HOST_INPUT_ROUTE: &str = "crates/mvm-hostd/src/stream/display_input_route.rs";

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

    check_input_path(workspace)?;

    eprintln!(
        "check-single-display-path: clean — one vsock channel, one host sink, no guest listener or host-to-guest source write, one loopback-only viewer, and one gated input path"
    );
    Ok(())
}

/// Attended input has exactly one shape: the host gate's route calls the one
/// agent verb, the agent writes the one FIFO, and the bridge turns what it
/// reads into the three fixed CDP input methods.
fn check_input_path(workspace: &Path) -> Result<()> {
    let attended = production(&read(workspace, ATTENDED_VIEWER)?);
    if attended.contains("TcpListener::bind(") || !attended.contains("bind_loopback()") {
        bail!("check-single-display-path: the attended viewer must reuse the one loopback bind");
    }
    for forbidden in ["0.0.0.0", "Ipv4Addr::UNSPECIFIED", "[::]"] {
        if attended.contains(forbidden) {
            bail!(
                "check-single-display-path: attended viewer contains non-loopback bind {forbidden}"
            );
        }
    }

    let guest_input = production(&read(workspace, GUEST_INPUT)?);
    for forbidden in ["TcpListener", "UnixListener", "::bind("] {
        if guest_input.contains(forbidden) {
            bail!("check-single-display-path: the guest input path must not listen ({forbidden})");
        }
    }

    // Strings are kept here, unlike `production`, because the method names
    // are string literals; tests are still cut, since they name forbidden
    // methods on purpose to prove they are discarded.
    let bridge_full = read(workspace, GUEST_BRIDGE)?;
    let bridge_source = bridge_full
        .split("#[cfg(test)]")
        .next()
        .unwrap_or(&bridge_full);
    for required in [
        "Input.dispatchMouseEvent",
        "Input.dispatchKeyEvent",
        "Input.insertText",
    ] {
        if !bridge_source.contains(required) {
            bail!("check-single-display-path: the fixed CDP input allow-list lost {required}");
        }
    }
    for forbidden in [
        "\"Runtime.",
        "\"Fetch.",
        "\"Network.",
        "\"Storage.",
        "\"Target.",
    ] {
        if bridge_source.contains(forbidden) {
            bail!(
                "check-single-display-path: the display bridge names a CDP domain outside its allow-list ({forbidden})"
            );
        }
    }

    let mut senders = Vec::new();
    let mut desks = Vec::new();
    for_each_file(
        &workspace.join("crates"),
        Some("rs"),
        &mut |path, source| {
            let code = production(source);
            let relative = path
                .strip_prefix(workspace)
                .unwrap_or(path)
                .display()
                .to_string();
            if code.contains("send_display_input(") && !relative.ends_with("vsock/rpc.rs") {
                senders.push(relative.clone());
            }
            if code.contains("DisplayInputDesk::deliver(") {
                desks.push(relative);
            }
        },
    )?;
    if senders != [HOST_INPUT_ROUTE] {
        bail!(
            "check-single-display-path: expected the display input RPC to be sent only from {HOST_INPUT_ROUTE}, found {senders:?}"
        );
    }
    if desks.len() != 1 || !desks[0].ends_with("mvm-guest-agent/handlers.rs") {
        bail!(
            "check-single-display-path: expected one guest delivery site in the agent's handlers, found {desks:?}"
        );
    }
    Ok(())
}

fn read(workspace: &Path, relative: &str) -> Result<String> {
    std::fs::read_to_string(workspace.join(relative)).with_context(|| format!("read {relative}"))
}

fn production(source: &str) -> String {
    blank_comments_and_strings(source.split("#[cfg(test)]").next().unwrap_or(source))
}
