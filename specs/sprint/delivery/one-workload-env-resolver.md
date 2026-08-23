# One workload-env resolver

Delivered 2026-08-21.

## What was wrong

Reported as "`mvmctl machine run --image rust:latest -it` isn't using the OCI
image". It was using it — `/usr/bin` carried the full Debian trixie toolchain
the image ships. What it was not using was the image's *declared environment*:

```
I have no name!@(none):~$ which rustc
I have no name!@(none):~$ which ld
/usr/bin/ld
```

`rust:latest` installs its toolchain under `/usr/local/cargo/bin` and puts it
on `PATH` through the image config alone (`RUSTUP_HOME`, `CARGO_HOME`, `PATH`).
Three separate defects stacked into that one prompt.

**1. Two paths into a workload, one of which resolved the environment.**
Materialization parsed the image's `Env`/`WorkingDir` and wrote them into the
rootfs, and exactly one binary read them back: `mvm-oci-entrypoint`, on the
`--entrypoint` path. `-it` takes `ConsoleOpen` instead, where
`console.rs::build_shell_env_from` assembled its own block from the guest
agent's process vars plus `--env` pairs. It never opened the file. The two
paths had no reason to agree and did not.

**2. An image declaring `Env` and no argv lost both.**
`oci_entrypoint_from_config_bytes` returned `None` on an empty argv, and
`inject_mvm_runtime` gated the write on `!argv.is_empty()`. An `Env`-only image
had its environment discarded along with the command it did not have.

**3. `I have no name!` and an empty `~`.**
`provision_workload_identity` writes the `/etc/passwd` entry for uid 901 and
creates `/home/mvm-worker` — behind
`optional_image_writes_allowed(rootfs_is_read_only())`. Every workload rootfs
is mounted `MS_RDONLY` (`guest_mount::mount_rootfs`, and `root=/dev/vda ro` on
every backend's cmdline), so on the OCI path that guard always fired and both
writes always no-opped. `workload_home()` then fell back to `/tmp`, which is
why the shell started in an empty directory. `mk-guest.nix` bakes both at build
time for the images mvm builds itself; the OCI path never got the equivalent.

A latent fourth: `build_shell_env_from` *appended* overrides rather than
replacing. `execve` accepts a block with a repeated name and `getenv` answers
with the first, so an override of an already-present name was a silent no-op.
The old code worked around this for `HOME`/`TERM` by dropping the inherited
copies by name; anything else would have been shadowed.

## What changed

**`crates/mvm-agentd/src/workload_env.rs` (new)** — the single resolver.
`ImageRuntimeConfig` (the serde type, now defined by the crate that reads it so
writer and reader cannot drift) plus a `WorkloadEnvironment` builder with an
explicit precedence ladder: default `PATH` floor → inherited process vars →
image declaration → `--env` overrides → forced `HOME`, and `TERM` only when the
session is interactive. Later layers replace in place rather than appending.

Both consumers now go through it. `console.rs` adds `.inherit()` and
`.interactive()`; `mvm-oci-entrypoint.rs` adds neither and is otherwise
identical. The console also honours the image's `WorkingDir`, matching where
the image's own entrypoint would have started.

`/etc/mvm/oci-entrypoint.json` → `/etc/mvm/image-runtime.json`: the file is no
longer an entrypoint concern. The path is folded into `INJECT_DESTS`, so the
content digest changes and already-materialized images re-materialize rather
than booting against a name nothing writes.

**Identity, baked at materialization.** `inject_mvm_runtime` now calls
`workload_identity::provision_in` against the staging tree — the same function
the boot path calls, at the one point in the lifecycle where the rootfs is
still writable. It appends only, and never over an entry the image already
claims. `/home/mvm-worker` joins `INJECT_DIRS` as a mount point.

**A writable home on a read-only root.** `guest_mount::mount_workload_home`
lays a tmpfs (`uid=901,gid=901`) over that mount point after the pivot and
before the privilege drop. Mounting over a directory needs no write to the
underlying filesystem, so this works on a sealed dm-verity root exactly as on a
plain one. `workload_home()` now reports what the boot path actually secured:
on a failed mount it returns the `/tmp` fallback rather than the read-only
mount point the `is_dir` probe would have reported.

**`xtask check-single-workload-env`** — the materialized config has exactly one
reader, and every declared consumer resolves through
`WorkloadEnvironment::builder()`. Wired into `ci.yml`. Both arms were confirmed
red against planted violations before the gate was called done.

## Evidence

- `cargo nextest run --workspace --exclude mvmctl`: 12635 passed, 3 failed.
  `cargo test --workspace --doc` clean. `cargo +nightly fmt --all -- --check`
  clean.
- The 3 failures, plus 24 more in the root `mvmctl` package's integration
  tests, are all one pre-existing local-environment fault: `CARGO_BIN_EXE_*`
  is unset, so `assert_cmd` cannot find the binary under test. Every one
  reproduces on clean `main` at `ee6b98d050` — verified directly, not assumed.
  Nothing in this change is implicated, and nothing in it is covered by those
  27 tests either, which is worth saying plainly rather than filing under
  "green".
- `cargo clippy --workspace --all-targets -- -D warnings` clean with two lints
  allowed: `clippy::double_must_use` on `#[async_trait]`
  (`mvm-fs/src/oci/manifest.rs`, `mvm-core/src/client/mod.rs`) and
  `clippy::chunks_exact_to_as_chunks` (`mvm-hostd/src/supervisor/icmp_echo.rs`).
  Both reproduce on `main` with identical flags; local clippy 0.1.99 is newer
  than the pinned CI toolchain. Two findings that *were* mine —
  `home_after_mount` unused on macOS, and a `useless_format` — are fixed.
- xtask gates run individually and green: `check-single-workload-env`,
  `check-guest-init-parity`, `check-guest-binary-lists`, `check-nextest-groups`,
  `check-claim-catalog`, `check-cli-runtime-surface`, `check-test-home-isolation`,
  `check-no-spec-refs-in-comments`, `check-declared-backing`, `check-honesty`,
  `check-file-size`, `check-single-home`, `check-sprint-append`.
- `just check-gated` clean — the Linux-gated arms of `mount_workload_home` and
  `guest_bootstrap` are not visible to a macOS `--all-targets` check.
- Mutation-checked, not just green: reverting the builder's replace-in-place to
  an append reddens `later_layers_replace_earlier_ones_rather_than_shadowing_them`
  and `the_console_and_the_entrypoint_agree_on_what_the_image_declared`;
  dropping `.image()` from the console reddens
  `console_takes_path_from_the_image_over_the_agents_own` and
  `console_starts_in_the_images_working_dir_when_it_declares_one`.

## Not done

The `(none)` hostname. The machine name never reaches the guest, so setting it
needs a new `mvm.hostname=` kernel-cmdline parameter plumbed through every
backend's boot-args construction and the boot-args validator. Deliberately
scoped out; `(none)` is what Nix-built images report too, so this is not an
OCI-path regression. Tracked as tinylabscom/mvm#2789.

Not verified on real hardware: this lands with the unit and gate evidence
above. The end-to-end proof is `mvmctl machine run --image rust:latest -it --
/bin/bash` reporting a `rustc` on `PATH` and a resolvable user, which needs a
host with a working backend.
