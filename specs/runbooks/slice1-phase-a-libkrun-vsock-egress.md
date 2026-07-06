# Runbook — Slice 1 Phase A: libkrun transparent-TCP vsock egress live verification

**What this proves:** a no-bound-secret libkrun **workload** reaches the network
through the host vsock `EgressGate` (claim-10) instead of the NIC, when opted in via
`MVM_VSOCK_EGRESS`, with the gvproxy/passt NIC still attached (Phase A retains it).
Passing this unblocks **Phase B** (fold claims-12/13 substitution onto the vsock
front door, delete the NIC, widen `check-vsock-only-egress`).

**Where this must run:** macOS with the `slp/krun/*` Homebrew trio
(`brew install slp/krun/libkrun slp/krun/libkrunfw slp/krun/gvproxy`). It cannot run
in CI — the automated gate (below) is green, but the vsock path is only *proven* by a
live boot.

## Automated gate (already green on this branch)

- `cargo fmt --all -- --check` ✅
- `cargo clippy --workspace -- -D warnings` ✅
- `cargo clippy -p mvm-vm-host --features libkrun-sys -- -D warnings` ✅ (lints the cfg-gated egress block)
- `cargo nextest run --workspace` — see branch status
- New unit tests: `state_has_bound_secrets_is_false_for_empty_state`, `vsock_egress_opt_in_reads_env`, `serves_only_when_opted_in_no_secrets_and_port_present`, `vsock_egress_cmdline_token_only_when_eligible`.

## Pre-flight

```sh
# From the worktree. The supervisor bin is NOT rebuilt by test runs — rebuild it,
# or a stale bin fails the boot with a deny_unknown_fields error.
cargo build -p mvm-vm-host --bin mvm-libkrun-supervisor --features libkrun-sys
cargo build
```

## Step 1 — allow path (the core proof)

Boot a **no-secrets** workload with a network policy that allow-lists exactly one
`host:port`, with the host opt-in set:

```sh
MVM_VSOCK_EGRESS=1 <your machine-run invocation> \
  --network-allow <HOST:PORT>            # a policy admitting one destination
```

Inside the guest, a proxy-aware client must reach the allow-listed target (mkGuest
Stage 2.6 exports `ALL_PROXY=socks5h://127.0.0.1:1080`):

```sh
curl -sS http://<HOST>:<PORT>/...        # honors ALL_PROXY → vsock → EgressGate → allow
```

Expected: the request succeeds; the host `mvm-libkrun-supervisor` egress server logs
an accepted flow; the guest never opened a NIC socket to reach it.

## Step 2 — verify the flag actually reached the guest (guards Minor M2)

The in-guest client only starts if `/init` set `MVM_VSOCK_EGRESS`. Confirm the token
threaded end-to-end:

```sh
# In the guest console/log:
cat /proc/cmdline | tr ' ' '\n' | grep mvm.vsock_egress   # expect: mvm.vsock_egress=1
pgrep -af mvm-egress-client                                # expect: the SOCKS5 client running
```

**If `mvm.vsock_egress=1` is present on the cmdline but the client did NOT start**,
the `/init` parse (busybox `grep` BRE `\|`) didn't match — apply the portable fix in
`nix/lib/mk-guest.nix` Stage 2.55: replace
`grep -q ' mvm\.vsock_egress=1\( \|$\)'` with `grep -qE ' mvm\.vsock_egress=1( |$)'`
(ERE), rebuild the image, re-boot.

## Step 3 — deny path

Same VM, a target NOT on the allow-list:

```sh
curl -sS http://<OTHER_HOST>:<PORT>/...   # expect: failure — EgressGate Deny, never dialed
```

Expected: connection refused/closed by the host egress server; the target host sees no
connection.

## Step 4 — confirm the NIC is still attached (Phase A retains it)

```sh
# In the guest:
ip link                                    # expect: lo AND the workload NIC present
```

Phase A does **not** remove the NIC. Phase B is what flips this assertion to "only
`lo`" once substitution is folded onto the vsock path.

## Step 5 — record results and unblock Phase B

Fill in the actual commands + output below, then author the Phase B plan
(substitution fold + NIC delete + widen `check-vsock-only-egress`). Phase B is
security-touching and requires maintainer review per the ADR-100 Step 2.3 note.

| Check | Command | Expected | Actual |
|-------|---------|----------|--------|
| allow-path fetch | (Step 1) | 200/success | _TBD on hardware_ |
| flag reached guest | (Step 2) | token + client running | _TBD_ |
| deny-path fetch | (Step 3) | refused | _TBD_ |
| NIC retained | (Step 4) | NIC + lo | _TBD_ |
