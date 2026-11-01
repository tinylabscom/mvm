# Live KVM acceptance evidence, 2026-11-01

Backing: preview
Validation: none — this records evidence for the parent issues; it is not a claim of complete enforcement.

Live runs for the demo umbrella [#4839](https://github.com/tinylabscom/mvm/issues/4839),
covering boxes that earlier reconciliations
([#4508](claude-demo-baseline-acceptance-evidence.md),
[#4509/#4510/#4511](application-descriptor-acceptance-evidence.md)) left blocked
on a KVM host. The issues own status. Every output below was seen in the run it
is quoted from; anything not run is listed as a limit, not implied.

## Method

Two operator-authorised x86_64 Linux hosts, each used from a fresh scratch
directory with `MVM_HOME` inside it, so every key is a box-local test key
created by that run and no real key was copied or printed.

| Host | Kernel | Firecracker | systemd | Source |
|---|---|---|---|---|
| A: Debian 12, 12 cores, `/dev/kvm` | 6.1.0-53-amd64 | v1.17.0 | 252 | `0c7c27ec166158f7f4d20d5886ad88aa8106672c` (origin/main) |
| B: Ubuntu, 20 cores, `/dev/kvm` | 7.0.0-22-generic | v1.17.0 | 259.5 | `d95c9a4303f1f7b0206f363a91891885a058b511` (origin/main) |

Both ran `cargo build --bin mvmctl --features user,embed-host-bins` (debug,
`mvmctl 0.26.0`, 5m45s and 6m18s) from a clone, with the box's own cargo
(`nightly-2026-08-25` active, pinned `1.97.1` + zig 0.13.0 for the embedded
payload). `mvmctl bootstrap` assembled the guest runtime from the source tree
(`doctor`: `guest runtime: this tree's archive 5f9279041b54 — assembled from the
source guest runtime`); the image set was `image-set/v0.2.4`, signature and
digests verified on fetch. No signed release runtime was used:

```
$ curl -sL -o /dev/null -w '%{http_code}' https://github.com/tinylabscom/mvm/releases/download/v0.24.0/mvm-guest-bins-v0.24.0.tar.gz
404
```

The `v0.24.0` runtime asset still 404s, so a release binary cannot assemble its
runtime; everything here uses the source-built runtime. No signing with release
keys, publication, or paid/credentialed request took place; the only secret
was the documented non-secret test value `not-a-real-key`.

## #4508 — isolated baseline and offline Claude smoke

Host A, `Verdict: MET` for the offline smoke and audit-chain bullets on Linux
Firecracker. Exact commands (cwd = the clone, scratch `MVM_HOME`):

```
printf %s not-a-real-key | mvmctl secret set agent-workload-smoke --provider anthropic --value -
printf %s mvm-agent-smoke | mvmctl --verbose machine run --flake examples/agent-workload --entrypoint \
  --from-workload-ir examples/agent-workload/workload-smoke.json --allow-host api.anthropic.com:443 --timeout 120
```

Output (stdout) and exit status:

```
agent-workload smoke: placeholder-present
2.1.273 (Claude Code)
exit=0
```

The builder was the Firecracker builder (`doctor`: `builder backend: firecracker
— auto-detected`), image `fetched (image-set/v0.2.4)`, "host-side Nix is not
used"; the workload ran `backend=firecracker`, plan
`sha256:ea839dd9bab24f711044e2e1b0816e735db290305c56b737255015b1284879c6`, image
`fe6636c9faa8b425…`. Audit:

```
$ mvmctl trust audit verify sha256:ea839dd9…4879c6 --json
verdict VERIFIED, event_count 9, late_entries 0, seal reason "exited", exit_code "0"
$ mvmctl -v trust audit verify
audit chain '…/audit/local.jsonl' verifies clean: 31 entries
append-only: 2 published root(s), 1 transition(s) proven a prefix extension
```

The entries were `plan.admitted`, `decision_record`, `plan.grant_required`,
`plan.asset_identities`, `plan.policy_resolved`, `plan.egress_destinations`,
`plan.launched`, `gateway.transcript_sealed`, `plan.exited`, `session.sealed`.

Limits. The smoke makes no outbound request and proves startup only, not model
access or network enforcement. Peak memory was not measured, so 4096 MiB is
still an allocation and not a capacity claim. The runtime is source-built, not
the signed release asset. Isolation is by `MVM_HOME` and a private directory;
the host kernel, Firecracker and cargo caches are shared.

Host B, `Verdict: BLOCKED` on systemd 259 — a product defect, not a host fault.
The same command failed before the guest booted:

```
builder VMM-level failure: firecracker builder run: capture Firecracker pid … after boot:
parse Firecracker pid from …/fc.pid (marker contents: "$"): invalid digit found in string
```

Cause, reproduced in isolation on that host: `systemd-run --scope` rewrites
`$$` to `$` in its command line on systemd 259, and the Firecracker launch
script (`launch_script` in `crates/mvm-backends/src/fc/daemon.rs`) writes its
own pid from `"$$"` inside `systemd-run --scope … sh -c '…'`.

```
$ systemd-run --version | head -1
systemd 259 (259.5-0ubuntu3.4)
$ systemd-run --user --scope sh -c 'echo a=$$'        # prints  a=$
$ systemd-run --user --scope sh -c 'echo a=$$$$'      # prints  a=1962049
```

On systemd 252 (host A) the same line prints a real pid and the launch works.
Any host with systemd 259 or newer refuses every scoped Firecracker launch
until the script stops depending on a literal `$$` surviving `systemd-run`.
This is recorded here for follow-up; nothing was changed.

## #4510 — acquisition/install on Linux, including real SIGKILL

Host B (kernel 7.0), `Verdict: PARTIAL`. Missing from before and now run:

1. The 29 existing `registry_pack::application_bundle` tests, built and run
   natively on Linux (`cargo test -p mvm-core --lib --features host-state,test-support`):
   `test result: ok. 29 passed; 0 failed; 1 ignored`.
2. A real-process kill of the installer, from a box-local scratch test that is
   not committed. The test re-executes its own binary as a child that runs
   `install_with` over a hermetic signed archive and a real descriptor, and
   `Child::kill()` (SIGKILL) ends it.
   - Boundary kill: the child parks inside the commit step (content and
     descriptor already published, pin not yet written), and is killed there.

     ```
     WITNESS child pid 2103242 status signal=Some(9)
     WITNESS after SIGKILL: pins=0, install dir complete, no .partial
     WITNESS next install committed: pins=1
     ```

   - Sweep: 600 rounds, each killing a child after a delay from 0 to 25 ms
     across the whole install, then asserting a pin never exists without
     complete, byte-exact content and that a clean install afterwards always
     commits:

     ```
     WITNESS rounds=600 sigkilled=199 exited_before_kill=401 pinned_after_kill=416
       unpinned_after_kill=184; all invariants held and every recovery install committed
     ```

Limits, unchanged where not run. `kill` is a process death, not power loss:
no storage-level or directory-fsync crash certification was attempted. The
sweep samples kill points by delay rather than naming each syscall boundary, and
only the commit step is pinned deterministically. The outer descriptor
signature is still injected (`accept_signature`), so a genuine Sigstore-signed
application installed through the public CLI remains `BLOCKED`: signing is
keyless and needs Fulcio, which was not used here, and no release signing was
authorised. The 29 tests were not run on aarch64.

## #4511 — booted launch and chain-signed audit on Firecracker

Host A, two parts.

Signed-bundle launch, `Verdict: MET` for the booted launch plus audit entry on
the `.mvmpkg` route that an application reference resolves into (`run`
continues as `--manifest <bundle-sha256>`):

```
mvmctl --verbose build examples/agent-workload --from flake --out agent-workload.mvmpkg
  Built local archive …/agent-workload.mvmpkg (396441088 bytes, key_id=918e829de09b0ae7bf2fe4b8293d3cd4)
mvmctl trust add $MVM_HOME/keys/host-signer.pub          # public key, scratch trust store
  Trusted key_id 918e829de09b0ae7bf2fe4b8293d3cd4
printf %s mvm-agent-smoke | mvmctl --verbose run agent-workload.mvmpkg --entrypoint \
  --from-workload-ir examples/agent-workload/workload-smoke.json --allow-host api.anthropic.com:443 --timeout 120
  local build, signed by this host's key; not release-verified
  agent-workload smoke: placeholder-present
  2.1.273 (Claude Code)
  exit=0
```

Plan `sha256:1163defbc9d03049e36152601672357ed0a8cc16c6a1ade3553b7ae634c4fcf5`,
`backend=firecracker`, bundle
`19f996b94f5e0ead7716f5e7937a47a2862624885982bde97d3ff0167ea820cf`:

```
$ mvmctl trust audit verify sha256:1163defb…fcf5 --json
VERIFIED, event_count 9, late_entries 0, seal reason "exited", exit_code "0"
$ mvmctl -v trust audit verify
audit chain verifies clean: 68 entries
```

Every entry in the session carries `bundle_sha256` and `origin=local-build`:
`plan.admitted`, `decision_record`, `plan.grant_required`, `plan.asset_identities`,
`plan.policy_resolved`, `plan.egress_destinations`, `plan.launched` (with
`backend=firecracker`), `gateway.transcript_sealed`, `plan.exited` (`exit_code=0`)
and `session.sealed`.

Defect found: without the `trust add` step the same `run` fails after a
successful verify-and-install, contradicting the `cli-commands.md` statement
that a local build runs on this host's key alone:

```
local build, signed by this host's key; not release-verified
[mvm] verified …/agent-workload.mvmpkg and installed it as bundle 19f996b9…
Error: installed bundle 19f996b9…: trust store has no entry for key_id 918e829de09b0ae7bf2fe4b8293d3cd4
```

`settle_manifest_archive` admits the host key, but
`installed_bundle_verified_manifest`
(`crates/mvm-runtime/src/vm/template/lifecycle/snapshot.rs`) re-verifies the
installed bundle against `FsTrustStore` alone, which never contains the host
key. The `--dry-run` form passed because it installs nothing. This agrees with
the earlier reading in the application evidence ("launches only if that host
key has been enrolled"), and the docs and the launch path still disagree.

Application-reference launch, `Verdict: BLOCKED`. `mvmctl run -a
runtime/python@1.2.3 --dry-run` on a clean store gave the documented actionable
error, a live witness for the missing-install criterion only:

```
Error: application runtime/python@1.2.3 is not installed; run `mvmctl pack pull runtime/python@1.2.3`
```

No catalogued application with a genuine publisher signature exists to pull, so
catalog → authenticated descriptor → install → reference launch was not run,
and `application_launch` (reference, descriptor digest, bundle identity, run
and plan ids) was not observed on a booted VM. The entry is also the local
audit log, not the chain-signed log, per the earlier evidence.

## Verdicts

| Box | Verdict | What is witnessed | What is not |
|---|---|---|---|
| #4508 offline smoke, Linux Firecracker | MET on host A; BLOCKED on host B | Live smoke exit 0, `placeholder-present`, `2.1.273 (Claude Code)`, audit VERIFIED | Capacity, signed release runtime (404), any model request; host B fails on the systemd 259 `$$` defect |
| #4510 Linux target + SIGKILL | PARTIAL | 29 tests on Linux; real SIGKILL at the commit boundary and 199 kills across 600 rounds, no pin without content, recovery always commits | Genuine Sigstore-signed application through the CLI; power loss; aarch64 |
| #4511 booted launch + chain-signed audit | MET for the `.mvmpkg` route; BLOCKED for the application reference | Firecracker boot of a signed bundle, session VERIFIED with `bundle_sha256` on each entry | Reference launch (needs a signed descriptor); local-build launch without key enrolment fails |

## Cleanup

Each host's scratch directory (`/root/mvm-live-20261031-a1` on B,
`/root/mvm-live-20261031-b1` on A) was removed with its `MVM_HOME`, builds and
cached images; the one idle Firecracker pool process started by the run on A
was stopped by pid. Host B also kept `aarch64-unknown-linux-gnu` and
`wasm32-wasip1` rust-std components for toolchain `1.97.1` that the repo's
`rust-toolchain.toml` installed on first use, plus shared cargo registry
downloads; they were not removed.
