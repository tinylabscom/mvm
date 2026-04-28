# Plan: MicroVM One-Shot Exec (Sprint 41)

> **Scope**: Dev DX only. Adds a `mvmctl exec` subcommand that boots a transient microVM, runs a single command, and tears down. Inherits the existing `policy.access.debug_exec` gate (dev-mode only). No production policy changes.

## Context

[cco](https://github.com/nikvdp/cco) is a thin wrapper that runs Claude Code (or any command) inside a sandbox, automatically picking the strongest available backend (`sandbox-exec` on macOS → `bubblewrap` on Linux → Docker fallback). Its UX is the interesting part:

```
cco "write a hello world script"
cco --command "bash"
cco --add-dir ~/configs:ro --env API_KEY=sk-123 --packages terraform "..."
```

One command, transparent stdio, automatic teardown. The proposal is to offer the same shape with a Firecracker microVM as the sandbox — a strictly stronger isolation boundary than anything cco offers.

Most of the primitives already exist; the work is glue plus one new capability (host-directory mount).

A future companion: [mvmforge](https://github.com/tinylabscom/decorationer) (formerly "decorationer") emits a `launch.json` with an `entrypoint` block (`command`, `working_dir`, `env`). The eventual goal is for `mvmctl exec` to be able to read that block and invoke it directly. **That work is out of scope for this session**, but the v1 design must accommodate it as a non-breaking addition.

## What we already have

| Need | Status | Location |
|---|---|---|
| Boot a microVM headlessly | yes | `cmd_run` in `crates/mvm-cli/src/commands.rs:3129`, `backend.start(&VmStartConfig)` |
| Run a single command, capture exit code + stdout/stderr | yes | `cmd_console` in `crates/mvm-cli/src/commands.rs:4973`, `exec_at` in `crates/mvm-guest/src/vsock.rs:814`, `GuestRequest::Exec` in `mvm-guest-agent.rs:910` |
| Boot fast from a pre-built image | yes | Templates + snapshots — `restore_snapshot` in `crates/mvm-runtime/src/vm/instance/snapshot.rs:220` |
| Stop / teardown a VM | yes | `cmd_down` |
| Per-instance ext4 data disk + file injection into a drive | yes | `ensure_data_disk()` and `drive_file_inject_commands()` in `crates/mvm-runtime/src/vm/instance/disk.rs` |

`mvmctl console <vm> --command "..."` already returns the guest's exit code via `std::process::exit`. The whole exec-over-vsock half of this feature is done.

## v1 scope (decided)

- **`--add-dir host:guest` is in.** Read-only only in v1. Implementation: build an ext4 image containing the host directory contents, attach as a Firecracker drive, mount inside the guest at `guest`. Writes inside the guest are discarded on teardown. Reuses `disk.rs` primitives; **no virtio-fs work in v1.**
- **Dev-mode only.** Inherits the existing `policy.access.debug_exec` gate. No new policy knob.
- **`--template` is optional.** When omitted, the bundled `nix/default-microvm/` flake is built on first use and cached at `~/.cache/mvm/default-microvm/`. This is a **separate microVM image** from the `mvmctl dev` shell — exec always boots a fresh transient microVM, never the dev VM.
- **The same default also serves `mvmctl up`/`run`/`start`.** Those commands previously required `--flake` or `--template`; the source group's `required(true)` was dropped so they now fall back to the same bundled default image.
- **Entrypoint from a launch plan: deferred.** The CLI ships with the inline-command form only; the orchestrator API is designed so a launch-plan variant can be added later without changing the inline form's surface.

## Design

### CLI surface

```
mvmctl exec --template base -- uname -a
mvmctl exec --template base --cpus 2 --memory 1024 -- bash -c "..."
mvmctl exec --template base --env FOO=bar -- ./script.sh
mvmctl exec --template base --add-dir .:/work --add-dir ~/configs:/etc/configs -- ls /work
echo "hello" | mvmctl exec --template base -- cat
```

`--add-dir` syntax: `host:guest`. Always read-only in v1. We document the writes-lost semantic and suggest using stdout (or, later, `--out-dir`) for results.

### Internal shape (so the entrypoint future is non-breaking)

```rust
struct ExecRequest {
    template: String,
    cpus: u32,
    memory: Option<String>,
    add_dirs: Vec<AddDir>,        // host -> guest (RO in v1)
    env: Vec<(String, String)>,
    target: ExecTarget,
}

enum ExecTarget {
    Inline { argv: Vec<String> },
    // Future (not in v1, do not implement):
    // LaunchPlan { path: PathBuf },     // mvmforge launch.json
    // TemplateEntrypoint,               // entrypoint baked into template metadata
}
```

The CLI's `Commands::Exec` variant constructs `ExecRequest::Inline`. A later `Commands::Run` (or `--launch-plan` flag) constructs the same `ExecRequest` with a different `ExecTarget`. Same orchestrator, no churn.

### Behavior

1. Resolve the template (existing `resolve_template_artifacts` path used by `cmd_run`).
2. For each `--add-dir`, build a small ext4 image from the host directory and stage it as an extra drive in `VmStartConfig`. Reuse `ensure_data_disk()`'s sizing logic and `drive_file_inject_commands()`'s population pattern.
3. Allocate a transient instance name (e.g. `exec-<short-uuid>`) so it doesn't collide with user-named VMs.
4. Boot via `backend.start(&VmStartConfig)`. Prefer snapshot restore when the template has one (`template_snapshot_info` in `crates/mvm-runtime/src/vm/template/lifecycle.rs:325`); fall back to cold boot.
5. Wait for the guest agent to be reachable (existing `wait_for_healthy()` from Sprint 15).
6. Issue a `GuestRequest::Exec { command, stdin, timeout_secs }` over vsock. Stream stdout/stderr to the host's stdio, propagate exit code.
7. Tear down on exit (success, failure, or signal). Install a SIGINT handler so Ctrl-C kills the VM rather than orphaning it.

### Files to touch

- `crates/mvm-cli/src/commands.rs` — add `Commands::Exec` variant; new `cmd_exec(params)` that composes artifact resolution + the slimmed-down boot path + the vsock exec call + teardown.
- `crates/mvm-runtime/src/vm/image.rs` and `crates/mvm-runtime/src/vm/instance/disk.rs` — small helper to build a read-only ext4 image from a host directory (tarball populate then mark RO). Likely reuses what `drive_file_inject_commands()` already does.
- `crates/mvm-cli/src/lib.rs` (or wherever Clap dispatch lives) — wire the new subcommand.
- Tests in `tests/cli.rs` for argument parsing, especially `--add-dir host:guest` parsing edge cases (relative paths, `~`, missing colon).
- Integration test that boots a tiny template and runs `/bin/true` / `/bin/false` to verify exit code propagation, plus an `--add-dir` test that verifies a host file is readable inside the guest.

### Out of scope for v1 (explicitly)

- Writable `--add-dir` / virtio-fs / 9p — needs separate design.
- Persistent sessions (`cco --persist=...`).
- Auto-snapshot warming. We use whatever snapshot the template already has.
- `--packages` package install at runtime (cco's apt install). Bake into the template instead.
- Reading mvmforge `launch.json` and invoking its entrypoint — deferred but the `ExecTarget` enum reserves the slot.

## Platform caveats

- **Linux/KVM:** Full support. Snapshot restore should give sub-second boot.
- **macOS / Lima (QEMU):** Memory note flags `os error 95` (EOPNOTSUPP) on vsock snapshots in QEMU. Cold boot path still works; the orchestrator must fall back gracefully when snapshot restore fails on this backend.
- **macOS / Apple Container:** Existing blocker (`memory/project_apple_container_boot_model.md`) — containers exit immediately because rootfs uses custom init not vminitd. `mvmctl exec` would inherit this until that work lands.

## Verification

- `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` (per CLAUDE.md, no feature is done without these).
- New integration test: build the `minimal` example flake as a template, then `mvmctl exec --template minimal -- /bin/true` (expect exit 0) and `... -- /bin/false` (expect exit 1).
- `--add-dir` smoke test: `echo hello > /tmp/foo && mvmctl exec --template minimal --add-dir /tmp:/host -- cat /host/foo` returns `hello` and exit 0.
- Manual smoke test on the dev Lima VM: `mvmctl exec --template <something> -- uname -a` and verify the output matches the guest kernel, not the host.
- Time the boot+command+teardown loop with snapshots vs cold boot to confirm the snapshot path is actually worth it (target: sub-2s on Linux/KVM with snapshot).
- Ctrl-C test: send SIGINT mid-command, verify the microVM is torn down (no orphaned Firecracker process, no leftover tap interface).
