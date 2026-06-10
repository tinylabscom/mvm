# Plan 129 — live SDK-free egress e2e: Firecracker bringup + debug (session kickoff)

> Paste as the opening message of the next session. This is a **research + live-debug** session on a real box, not a code-authoring one — though small fixes (and one or two PRs) will fall out.

## Goal (the acceptance test)

Prove, live on the dev-KVM box, the Plan 129 **SDK-free egress substitution** end-to-end on **Firecracker**:

A secret-declaring workload boots on FC; a generic client in the guest (`curl http://<bound-host>` — no `import mvm`, no `HTTP_PROXY`) has its placeholder swapped for the **real** credential by the host-side transparent terminator, and:

- the destination receives the **real** `Authorization` value (substitution worked);
- the guest only ever held `mvm-secret-<hex>` (never the value);
- a `secret.substituted` entry is in the chain-signed audit log (no secret bytes);
- a request to an **unbound** host is refused (claim 12);
- the **host's own** egress is NOT intercepted (the `iifname` redirect is guest-scoped).

## What's already DONE (do not rebuild — verify, then build on it)

- **Terminator core** — PR #735 (merged, squash `111ae55e`): `mvm_hostd::supervisor::terminator` (`orig_dst`/`request`/`read`/`handler`/`listener`), `SubstitutionService::serve_terminator`, `EndpointConfig.terminator_listen`, bin runs the terminator concurrently. Reviewed, 805 tests.
- **FC wiring** — PR #744 (merged, squash `8c3a327b`): `mvm_backend::egress_redirect::EgressRedirect` (per-VM nft `nat prerouting iifname "<tap>" tcp dport 80 redirect to :<port>`), `mvm_backend::microvm::wire_egress_substitution` (spawns the per-VM `mvm-substitution-endpoint` with `terminator_listen: 0.0.0.0:<18080+slot.index>` + installs the redirect, gated on the admitted plan carrying secrets, fail-closed), shared `substitution_spawn` helper, `stop_vm` reaps the moat **before** its not-running early return, `mvm_core::plan::tenant_from_signed_json`.
- **Mechanism box-validated (Task 0'):** `nft … prerouting iifname "<iface>" tcp dport 80 redirect to :<port>` (chain `type nat hook prerouting priority -100`) + `SO_ORIGINAL_DST` recovers the dest; guest egress captured, host's own untouched. (Note: FC egress is **TAP + nft NAT**, NOT passt — passt/`skuid` is the libkrun path, deferred.)
- Background: declared substitution + undeclared-secret/PII redaction tiers are landed and box-validated over loopback (see `specs/prompts/129-local-admission-launch.md` and memory `project_plan_129_secrets_subsystem`).

## The box and its provisioning state (already set up — reuse)

`root@88.99.197.234` (Debian 12, x86_64, `/dev/kvm`). Already provisioned by the prior session:

- `iptables` installed (v1.8.9 **nf_tables shim**; mvm's FC MASQUERADE NAT uses iptables — the box was nft-only).
- **Firecracker v1.14.1** installed at `/usr/local/bin/firecracker` (the prior binary was the wrong arch; mvm uses PATH `firecracker`, expects v1.14.x).
- `~/.mvm-129/passt-hashes.toml` populated with the sha256 of `/usr/bin/passt` (the FC bridge hash-verifies passt).
- Default image cached at `/root/.cache/mvm-129/default-microvm/prod/`. **The manual `vmlinux` swap is no longer needed (#746 fixed):** the FC boot path now auto-extracts an ELF `vmlinux` from a bzImage on the fly (`mvm_build::fc_kernel::ensure_fc_loadable_kernel` → cached sibling `<kernel>.elf`), so a wiped/re-downloaded cache just works. Confirm the boot uses `<kernel>.elf` (the log prints "Setting boot source: …/vmlinux.elf"); if FC still rejects it, the kernel may use a non-gzip compression (xz/zstd) — extend `fc_kernel::extract_vmlinux` with that decoder.
- `/root/mvm-129` checked out + built (`mvmctl`, `mvm-firecracker-bridge`, `mvm-substitution-endpoint`). Build with rustup cargo (`/root/.cargo/bin`); `mvmctl` is the **root** package bin (`cargo build --bin mvmctl`, not `-p mvm-cli`).
- Always run with `MVM_CACHE_DIR=/root/.cache/mvm-129 MVM_DATA_DIR=/root/.mvm-129` to isolate from parallel sessions (`/root/mvm`, `/root/mvm-p129`).

With those, `MVM_CACHE_DIR=… MVM_DATA_DIR=… mvmctl up --hypervisor firecracker --builder qemu --kernel-source download --name fctest` **boots an FC microVM** (Guest IP 172.16.0.2). Confirm this still works first.

## Blockers to research/debug, in order

1. **FC guest-agent not reachable within 30s** (the immediate wall). The default image boots but `mvmctl up` reports "Guest agent not reachable" and auto-stops the VM; `console.log` is empty (no `hvc0` on the plain-Image kernel — see memory `reference_libkrun_workload_boot_verify_and_empty_console`). Investigate:
   - Is the agent actually failing, or just slow / is 30s too short? Can the wait be extended / the VM kept alive to inspect?
   - Does the **extracted** vmlinux differ behaviorally from a proper FC kernel (missing vsock/virtio config)? Compare against a known-good FC x86_64 vmlinux. Confirm `vhost-vsock` + the host UDS `v.sock` bridge come up (FC vsock guest-CID + `~/.mvm-129/vms/<vm>/v.sock`).
   - Instrument: add a serial console the kernel will write to (FC `--boot-source` cmdline `console=ttyS0`?), or boot a vmlinux that logs, to see how far init/the agent gets.
   - Cross-check the agent's vsock port/CID expectations vs what the FC backend configures.

2. ~~**The real fix for #746**~~ **DONE** — the FC boot path now extracts the ELF `vmlinux` from a bzImage before `/boot-source` (`mvm_build::fc_kernel`, gzip payload, cached `<kernel>.elf`; unit-tested). The release-pipeline-emits-vmlinux and publish-time-smoke-boot-gate options remain possible hardenings but are no longer on the critical path. (If blocker (1) persists with the extracted kernel, suspect a missing kernel CONFIG, not the extraction — compare against a known-good FC x86_64 vmlinux.)

3. **Local secret-workload launch glue** (so a *secret-declaring* workload can boot locally — see `specs/prompts/129-local-admission-launch.md`). **A parallel session is building exactly this in PR #745** ("local secret-workload launch + endpoint egress redaction") — **check #745's state first; it may already unblock this leg.** `mvmctl compile` refuses managed secret refs (`crates/mvm-sdk/src/compile/orchestrator.rs:98`); `mvmctl up` lowers secrets via `lower_workload_secrets` + `admit_plan_for_boot` (`up.rs:1010/1400`) and accepts **`--from-workload-ir <ir.json>`** (Plan 73 B.3). Settle the scope question (local secret launch in mvm vs mvmd — ADRs put deploy/tenant in mvmd) then wire/drive the path. `mvmctl invoke <manifest>` runs a workload **entrypoint**, not an arbitrary command — so the e2e needs the **`examples/python/secret-egress`** workload (its `app.py` does the curl-with-secret), which must be **built** (cold builder VM → #576 Stage-0 panic risk; warm the cache / `--kernel-source download`).

## The e2e recipe (once 1–3 are unblocked)

```
export MVM_CACHE_DIR=/root/.cache/mvm-129 MVM_DATA_DIR=/root/.mvm-129
# 1. store + bind a secret to an HTTP (:80, Stage-1b has no TLS) echo host you control
printf '%s' "$REAL" | mvmctl secret set echo-key --host <bound-host> --type bearer --value -
# 2. launch the secret-declaring workload on FC (via the decided glue: up --from-workload-ir <ir>, or up --manifest)
mvmctl up --hypervisor firecracker --builder qemu --from-workload-ir <ir.json> --name segress
# 3. observe the wiring fired (the whole point):
#    - ~/.mvm-129/vms/segress/substitution.pid is live during the run, gone after stop
#    - a terminator listener on 0.0.0.0:<18080+slot.index>
#    - nft table `mvm_egress_segress` with the prerouting iifname "<tap>" redirect
#    - invoke/run the entrypoint; assert the echo dest saw the REAL Authorization, guest held only mvm-secret-…
#    - mvmctl audit verify exits 0 with a secret.substituted entry (no secret bytes)
#    - a request to an UNBOUND host is refused (claim 12)
#    - a host-side curl to the bound host is NOT intercepted
```

Run a small HTTP echo on a box-reachable address as the bound host (the terminator forwards to the original dst over plain http; Stage 1b is http-only).

## Code/file anchors

- FC wiring: `crates/mvm-backend/src/microvm.rs` (`wire_egress_substitution`, `stop_vm`, `start_vm_firecracker`, `configure_flake_microvm`), `crates/mvm-backend/src/egress_redirect.rs`, `crates/mvm-backend/src/substitution_spawn.rs`.
- Endpoint+terminator: `crates/mvm-hostd/src/supervisor/{substitution_endpoint.rs, substitution_proxy.rs, terminator/*}`, bin `crates/mvm-hostd/src/bin/mvm-substitution-endpoint.rs`.
- FC bridge + passt-hash: `crates/mvm-vm-host/src/bin/mvm-firecracker-bridge.rs`, `crates/mvm-vm-host/src/firecracker_bridge/parse.rs`.
- Launch glue: `crates/mvm-cli/src/commands/vm/{up.rs, run_plan.rs, managed_secrets.rs}`, `crates/mvm-sdk/src/compile/orchestrator.rs`.
- Plan + design: `specs/notes/plan-129-stage1b-2-transparent-terminator-plan.md`, `specs/prompts/129-local-admission-launch.md`.

## Norms / gotchas

- Worktree only; **no `Co-Authored-By`/Claude trailer**; repo merges are **squash**; main needs a review/`enforce_admins` toggle for self-merge.
- Box: `pkill -f mvm-substitution-endpoint` **self-kills the launching shell** (path in its own argv) — use `pkill -x mvm-substitutio`. Isolate every run with `MVM_CACHE_DIR`/`MVM_DATA_DIR`. The box locale is broken — pipe ssh output through `grep -v 'setlocale\|LC_ALL'`.
- Stage 2 (name-constrained CA + `https`, ADR-006) is out of scope; Stage 1b is http-only.
- Memory: `project_plan_129_terminator_backend_gap` (the full bringup chain + decisions), `project_plan_129_secrets_subsystem`, `reference_passt_outbound_nft_redirectable`.
