# The builder-VM bootstrap helper stops rebuilding what it is already running

Issue #3067. On a cold builder-image cache, a source-checkout `mvmctl` spawns a
second `mvmctl` — the builder-VM bootstrap helper — to refresh
`~/.mvm/cache/builder-vm/<arch>/`. It built that helper without
`--features embed-host-bins`, so the helper refused at
`host_binaries::extract` doing the one thing it was spawned for.

The featureless build command was fixed in passing by #3062, which added the
feature. That closes the refusal and opens a different hole: the helper build
now silently requires the pinned zig + musl Rust toolchain, and pays for it
with a multi-minute compile that ends in a build-script panic for anyone who
has never run `just toolchain-embed`. This finishes the job from the other end.

## The helper is only ever needed for its payload

Every reason to spawn a helper reduces to one: get hold of an `mvmctl` that
carries the embedded Linux host binaries. So the first question to ask is
whether the running binary already carries them — and for anyone who followed
`just embed`, it does. Compiling a second `mvmctl` to obtain a payload that is
already loaded in this process is the whole bug, and no amount of fixing the
build command addresses it.

`mvm-build` cannot read the embed table; it sits below the crate that owns it.
So `mvmctl` declares the answer once at startup
(`declare_current_exe_carries_host_binaries`, called from `run_command`
alongside the existing `register_*` seams), and
`resolve_builder_vm_bootstrap_bin` returns `current_exe()` on the strength of
it. The declaration defaults to `false`: a test binary or a library embedder
that never declares anything keeps the build-a-helper path it had.

The order matters and is now: explicit `MVM_BUILDER_VM_BOOTSTRAP_BIN`, then the
running binary, then a fresh cached helper, then a build. The env var stays on
top because someone who names a helper is telling us theirs is the one to use.

What this changes in practice:

- `mvmctl bootstrap` on an embedded build resolves to itself,
  `current_exe_matches` short-circuits the re-exec, and it bootstraps
  in-process. No cargo, no second process.
- Cold-cache auto-bootstrap from an embedded build spawns *itself* with
  `__builder-vm-bootstrap`. Still a subprocess — `mvm-build` cannot call up
  into `mvm-cli`'s bootstrap — but a spawn, not a compile.
- An unembedded parent falls through to the helper build, which is where the
  remaining two changes live.

## The refusal moved to before the compile

`crates/mvm-cli/build.rs`'s toolchain resolution moved down to
`mvm_build::embed_toolchain`, where the bootstrap can reach it, and grew `try_`
variants that report instead of panicking. `resolve_builder_vm_bootstrap_bin`
runs the same two resolutions the build script does — pinned zig, pinned Rust
with the musl target — before spawning cargo, and refuses in milliseconds with
what is missing.

The build script still `#[path]`-includes the file and still panics: a build
script that cannot find its toolchain has nothing to fall back on, and the
panic message is what a contributor reads. Only the caller that *does* have
somewhere to go reads a `Result`.

Deliberately not preflighted inside `build.rs` itself. The embed arm restores
from the content store before it compiles anything, so a cache hit needs no
toolchain at all; an unconditional check there would break the restore path
that CI and release builds run on.

## Every refusal names every way out

`MVM_BUILDER_VM_BOOTSTRAP_BIN` is the supported escape hatch and no error
mentioned it. Both helper-acquisition failures now end with the same tail: run
`just embed` so this binary carries the payload itself and needs no helper, or
point `MVM_BUILDER_VM_BOOTSTRAP_BIN` at one that does. The toolchain refusal
adds `just toolchain-embed` and quotes the underlying reason, so the reader can
tell a missing zig from a missing musl target.

The zig message previously said `pip install ziglang==<pin>`, which installs
zig and not the musl Rust targets. `just toolchain-embed` does both and is what
CLAUDE.md documents.

## One fork bomb closed on the way past

`auto_bootstrap_builder_vm_image` had no guard against being reached from
inside a bootstrap. Nothing exercised it because the helper was a distinct
binary that failed before it got that far; making the running binary the helper
puts the door in plain sight. Every spawned bootstrap now carries
`MVM_BUILDER_VM_BOOTSTRAP_ACTIVE`, and a process holding it reports the cold
cache instead of forking another child. One level of delegation is all that can
ever help — the second level has nothing new to try.

## Where it lives now

The helper logic moved out of `libkrun_builder.rs` into
`mvm_build::builder_vm_bootstrap` — acquisition, the declaration seam, the
re-exec, the preflight and their tests. `libkrun_builder.rs` was at 1491 of the
1500 production lines `check-file-size` allows, so this change did not fit
beside it, and the helper is not libkrun's anyway: `ensure_builder_vm_image`
calls it on every backend. `builder_vm_source_checkout_root` is now
`pub(crate)`; the three `mvm-cli` call sites moved to the new path.

## What is still true

`bootstrap_helper_build_command_uses_isolated_target_dir` still pins the
dedicated `target/mvm-builder-vm-bootstrap` target dir, which is load-bearing:
a plain `cargo build` into the main target dir swaps `mvmctl`'s embedded
payload out. `bootstrap_helper_needs_rebuild` still compares mtimes against
`bootstrap_helper_inputs`, so a hand-placed helper can still be rebuilt out
from under you — unchanged, and now much harder to reach.

## Validation

Workspace suite, doctests, `cargo clippy --workspace --all-targets -D
warnings`, `just check-gated`, `cargo run -p xtask -- check-all`.

Live on the Linux/KVM box, twice: `mvmctl machine build --builder qemu` from
`examples/sleeper`, an `mvmctl` built with `--features embed-host-bins`, a
scratch `MVM_HOME`, and `MVM_BUILDER_VM_BOOTSTRAP_BIN` unset — the env var is
the workaround, so setting it would hide the thing under test. The host's
shared `~/.mvm/cache/builder-vm/x86_64/` carries no image, so the opportunistic
seed declines and auto-bootstrap is genuinely reached.

Both runs completed in ~27 minutes with `{"exit_code":0}`: the builder image
built from the checkout via Stage 0 (`.mvm-provenance.json` records
`source_kind: source_checkout_stage0`), then the sleeper workload built and
registered as a template revision with its `rootfs.ext4` + `vmlinux`.
`target/mvm-builder-vm-bootstrap` was never created and the "cannot bootstrap a
builder VM" refusal never appeared — the running binary was the helper.

The one `cargo` compile visible in those logs is `mvm-network-endpoint`, a
separate pre-existing source-checkout auto-build, not the helper.
