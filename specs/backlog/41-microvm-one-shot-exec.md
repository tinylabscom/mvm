# Sprint 41 — MicroVM One-Shot Exec

**Status:** Implementation complete. Live smoke test on Linux/KVM or Lima
deferred (tracked in PR test plan).

**Branch:** `feat/microvm-one-shot-exec`

**Plan:** [`specs/plans/24-microvm-one-shot-exec.md`](../plans/24-microvm-one-shot-exec.md)

## What shipped

A new `mvmctl exec` subcommand that boots a transient Firecracker microVM,
runs a single command via vsock, streams stdio, propagates the exit code,
and tears the VM down on exit (success, failure, or SIGINT).

```
mvmctl exec -- uname -a                                # bundled default image
mvmctl exec --template my-tpl -- /bin/true             # registered template
mvmctl exec --add-dir .:/work -- ls /work              # share host dir, RO
mvmctl exec --env DEBUG=1 -- env | grep DEBUG          # env var injection
mvmctl exec --cpus 4 --memory 1G -- bash -c '…'        # custom resources
```

Inspired by [cco](https://github.com/nikvdp/cco)'s sandbox-wrapper UX, but
with a Firecracker microVM as the isolation boundary.

## Design highlights

### `ExecRequest` / `ExecTarget` / `ImageSource` (in `crates/mvm-cli/src/exec.rs`)

```rust
struct ExecRequest {
    image: ImageSource,
    cpus: u32,
    memory_mib: u32,
    add_dirs: Vec<AddDir>,
    env: Vec<(String, String)>,
    target: ExecTarget,
    timeout_secs: u64,
}

#[non_exhaustive]
enum ExecTarget { Inline { argv: Vec<String> } /* + future: LaunchPlan, TemplateEntrypoint */ }

#[non_exhaustive]
enum ImageSource {
    Template(String),
    Prebuilt { kernel_path, rootfs_path, initrd_path, label },
}
```

Both enums are `#[non_exhaustive]` so the planned mvmforge `LaunchPlan`
variant ([tinylabscom/decorationer](https://github.com/tinylabscom/decorationer))
can land without churning the inline-command surface.

### `--add-dir` (read-only host mount)

No virtio-fs work in v1. `vm/image.rs::build_dir_image_ro(host_dir, label,
dest)` sizes ext4 from `du`, mkfs's with a caller-provided label, mounts +
copies + unmounts. The orchestrator stages images at
`<vms_dir>/<vm_name>/extras/extra-N.ext4`, attaches them to Firecracker
with `is_read_only: true`, and prepends a wrapper script to the user's
command:

```sh
set -e
mkdir -p '/work'
mount LABEL='mvm-extra-0' '/work' -o ro
export FOO='bar'
exec '<argv>'…
```

The guest agent (PID 1 init via `mkGuest`) runs as root, so it can mount.
No new vsock protocol or guest-side change required.

### Bundled default image (`nix/default-microvm/`)

A minimal `mkGuest` flake — busybox + the auto-included guest agent, no
extra packages. Built via Nix on first use, cached at
`~/.cache/mvm/default-microvm/{vmlinux,rootfs.ext4}`.

Used as the fallback for **any** image-taking command when neither
`--flake` nor `--template` is supplied:
- `mvmctl exec` — boots a fresh transient microVM each invocation.
- `mvmctl up` / `mvmctl run` / `mvmctl start` — long-running VM. The
  source argument group's `required(true)` was dropped to allow this.

No download fallback in v1; users without Nix get a clear error pointing
at `--template`/`--flake`.

### `read_only` field on volumes

Threaded through `mvm_core::vm_backend::VmVolume`,
`mvm_runtime::vm::image::RuntimeVolume`, and the Firecracker drive emit in
`vm/microvm.rs`. Defaults to `false` for backwards compatibility with
existing persistent volumes.

## Files of note

| File | Change |
|------|--------|
| `crates/mvm-cli/src/exec.rs` | **new** — orchestrator + types + tests |
| `crates/mvm-cli/src/commands.rs` | `Commands::Exec` Clap variant + `run_oneshot` wrapper; `ensure_default_microvm_image` + `find_default_microvm_flake`; `Commands::Up` source group no longer required; `cmd_run` falls back to default image |
| `crates/mvm-cli/src/lib.rs` | `pub mod exec` |
| `crates/mvm-runtime/src/vm/image.rs` | `RuntimeVolume.read_only` + `build_dir_image_ro` helper |
| `crates/mvm-runtime/src/vm/microvm.rs` | Honor `vol.read_only` in Firecracker drive JSON |
| `crates/mvm-runtime/src/vm/backend.rs` | Propagate `read_only` through `FirecrackerConfig::from_start_config` |
| `crates/mvm-core/src/vm_backend.rs` | `VmVolume.read_only` + `Default` impl |
| `nix/default-microvm/flake.nix` | **new** — bundled default microVM image |
| `public/src/content/docs/reference/cli-commands.md` | Documents `mvmctl exec` and the default-image fallback for `up`/`run`/`start` |
| `specs/plans/24-microvm-one-shot-exec.md` | **new** — design doc |
| `specs/sprints/40-apple-container-dev.md` | **new** — archived prior sprint |

## Tests

21 new tests on top of the existing 987 (workspace total: 1 008).

- `commands::tests::exec_default_template_argv_only`
- `commands::tests::exec_with_template_and_resources`
- `commands::tests::exec_with_add_dir_and_env`
- `commands::tests::exec_requires_argv`
- `commands::tests::test_run_without_source_uses_default_microvm` (replaced `test_run_requires_source`)
- `exec::tests::*` (7 for `AddDir::parse` edge cases, 2 for `shell_quote`,
  3 for `build_guest_wrapper` / `target_command`, 1 for `transient_vm_name`)
- `vm::image::tests::build_dir_image_ro_rejects_*` (3 label-validation
  cases)

`cargo test --workspace` and `cargo clippy --workspace -- -D warnings`
both clean.

## Out of scope (deferred)

- **Live smoke tests on a real host** — the boot/exec/teardown loop,
  `--add-dir` mount, SIGINT teardown, and `nix build` of the bundled flake
  all need a Linux/KVM box or Lima dev VM. Tracked in the PR test plan.
- **Snapshot restore** — extra `--add-dir` drives don't match a snapshot's
  recorded drive layout. Cold boot only in v1.
- **Writable `--add-dir` / virtio-fs / 9p** — separate design needed.
- **mvmforge `launch.json` consumption** — `ImageSource` and `ExecTarget`
  reserve the slot; implementation is a follow-up sprint.
- **Download fallback** for the bundled default image — release artifacts
  to be added in a follow-up.
- **Persistent sessions** (cco's `--persist`) — out of scope.
- **Runtime package install** (cco's `--packages`) — bake into the
  template instead.

## Decision log

- **Chose `ExecTarget` enum + `ImageSource` enum over flag flags** so the
  planned mvmforge `LaunchPlan` variant is a non-breaking addition.
- **Wrapped command with mount script** instead of extending vsock
  protocol — reuses existing `GuestRequest::Exec`, no agent change.
- **Read-only mount via ext4 image** instead of virtio-fs — uses existing
  Firecracker drive plumbing; writes are intentionally discarded.
- **Bundled default image is shared across `exec` and `up`/`run`/`start`**
  rather than exec-only, in response to user feedback.
- **No live integration tests in CI** — would require Linux/KVM
  infrastructure; flagged in the PR for human-driven smoke.
