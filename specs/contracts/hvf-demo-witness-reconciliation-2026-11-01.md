# HVF demo witness reconciliation, 2026-11-01

Backing: preview
Validation: none — this records which demo-witness inputs exist on `8be5161c7e`; it is not a claim that the demo works.

Read-only reconciliation for the demo umbrella [#4839](https://github.com/tinylabscom/mvm/issues/4839)
on the macOS HVF host (arm64, macOS 27). The issues own status. No VM was
booted, nothing was signed or published, and no request was made.

## What exists

| Input | State at `8be5161c7e` |
|---|---|
| Release `v0.26.0` | Not published. `gh release view v0.26.0` returns "release not found"; Release run 41379793985 on this commit was still in progress, so it is not yet baseline evidence. |
| Signed guest runtime asset | None published for any version (see the 404 in `live-kvm-acceptance-evidence-2026-11-01.md`). |
| Installed or built `mvmctl` on this Mac | None. No binary under `target/`, in any scratch worktree, or on `PATH`; only `~/.cache/mvm` payload caches. |
| Final Claude application archive | Not built. mvm-packs#76 records a frozen input packet only; the fresh measured rootfs/verity/raw hash and the official signature are listed as still required. |
| Signed application descriptor / catalog entry | None, so `mvmctl pack pull agent/claude` has nothing to resolve. |
| Application-reference policy denial, hermetic | No test in `crates/mvm-cli/tests` or a pull request exercises a policy denial on an installed application reference; `signed_registry_pack.rs` covers catalog mismatch and legacy-publisher reuse only. |

## Verdicts

| Box | Verdict | Remaining item |
|---|---|---|
| First final-candidate HVF demo witness | BLOCKED | Needs the published `v0.26.0` release with signed runtime, the signed final archive and descriptor (mvm-packs#76), and the separate operator consent for the paid request (mvm-packs#84). |
| Demo contract across producer, registry, consumer, enforcement, installed execution | PARTIAL | Consumer and strict-parser slices are merged; the producer artifact and a genuine Sigstore-signed positive path do not exist. |
| Allow/deny audit witness | BLOCKED | Same artifact and consent prerequisites; mvm-packs#77 is supplementary to #84. |
| Reconcile demo issues | PARTIAL | #4507-#4511, #4391 and #4764 each still have an unmet criterion recorded in its own body; none is closable from this evidence. |
| Link schema/commit and verify paired CLI/runtime enforcement | PARTIAL | The request budget lives in `EnvironmentPolicy.request_budget`; enforcement with the exact client has not run. |
| #4511 hermetic policy denial | OPEN | No such test exists; it is a code change in `mvm-cli`/`mvm-runtime`, not an operator action. |

## Operator actions

- Release: someone with tag authority waits for Release run 41379793985, then
  confirms the published `v0.26.0` assets (#4764).
- Signing and publication of the Claude descriptor: the official OIDC workflow
  in mvm-packs must run on a main merge, by a maintainer; keys are never
  handled by an agent session.
- Paid request: explicit per-run consent and a budget-limited key (mvm-packs#84).
