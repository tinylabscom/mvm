# Public Claude consumer preflight

`claude-demo-preflight.py` implements the public acquisition prerequisite of
[mvm-packs#84](https://github.com/tinylabscom/mvm-packs/issues/84), **not live
demo acceptance**. It cannot launch a guest, send a model request, enroll an
identity, read a credential store, or remove native credentials.

Run only with separate operator approval for public acquisition. Supply these
required options with independently obtained nonsecret release assertions:

- `--cli`: absolute released executable path, without symlinks or write
  permission bits; `--cli-sha256`: its lowercase SHA-256.
- `--version`: exact expected `mvmctl --version` stdout, excluding final newline.
- `--release-commit`: full 40-character release commit assertion. This is
  recorded, not authenticated against a release tag by the script.
- `--home` and `--mvm-home`: absolute isolated directories owned by the operator,
  mode 0700, without symlinks. MVM_HOME must be inside HOME. Prepare only public
  trust/configuration and the already-enrolled identity for the final executable.
  Enrollment and host-held binding readiness are not proved by this preflight.
- `--descriptor-sha256`, `--archive-sha256`, `--archive-size`, `--key-id`:
  exact public `agent/claude@2.0.0` descriptor and independently trusted bundle
  assertions. No draft or local artifact is acceptable.
- `--endpoint api.anthropic.com:443`: assertion only, not enforcement evidence.

Optional `--check-readiness` additionally requires `--caller-installation`,
`--caller-public-key-sha256` (SHA-256 of the 32 raw public-key bytes) and
`--binding-name`. It invokes only `env caller-identity show` and `secret ls`,
not enrollment, secret retrieval or a native signing challenge. The caller pin
must be enrolled rather than pending; exactly one Anthropic-provider row must
match the binding name and the canonical bearer/Anthropic-only metadata.
Unknown, broader, ambiguous or approval-required bindings are refused. These
are public metadata checks, **not proof of the native ACL for this executable**.
The normal launcher must still authenticate the actual caller and binding.

Set `MVM_TEST_CLAUDE_DEMO=1` explicitly. Missing prerequisites fail rather than
skip. The script executes the absolute CLI with a minimal environment and its
working directory outside the source checkout:

```text
mvmctl --version
mvmctl search agent/claude
mvmctl pull agent/claude
mvmctl pack verify agent/claude@2.0.0 --json
```

Downloading and independent signature trust remain in the canonical CLI. The
script measures installed archive bytes separately. Existing application cache,
lock, bundle, audit, session or VM state is refused. Each command runs once using
the existing OCI witness's bounded output/deadline runner.

Evidence remains in a new mode-0700 `/tmp/mvm-claude-preflight-*` directory.
Inspect privately before sharing; prepared stores are not copied into evidence.
A passing exit means **preflight only**. Reports always keep `demo_acceptance`,
`model_request_attempted`, `guest_boot_witnessed`, `custody_verified` and
`credential_cleanup_attempted` false.

## Separately authorized live acceptance

Do not substitute this preflight for the primary workflow. The separately gated
`claude-demo-consumer.py` and its operator guide implement the live workflow.
Live acceptance still
requires separately authorized native Apple Silicon execution, a host-held
Anthropic binding, at most one authorized model request with a $0.50 ceiling,
and exactly `tell me a joke\n` piped into `mvmctl run agent/claude` without extra
runtime flags. The consumer runner requires correlated canonical
plan/session/run, descriptor/bundle/image/runtime, verified audit-chain,
effective endpoint enforcement and original-owner clean-stop evidence.

This preflight cannot prove a one-request ceiling, account spending, effective
network enforcement or native completion. Never derive cleanup authorization
from PID disappearance. Retain the original custody owner and recovery evidence
on uncertain completion; do not delete enrolled credentials or consumer state.
Artifact re-export/publication belongs to mvm#4764 and mvm-packs#76.

The source example currently allows three Claude turns. A single CLI invocation,
one-shot stdin, `--max-turns`, or the client's `--max-budget-usd` is not a
pre-forward one-model-request limit. The response-time AI token meter alone
does not establish this limit. The canonical signed network AI policy now
supports a strict `request_budget` that reserves attempts and a conservative,
exact-model USD bound before forwarding; see the network-egress-policy guide.
That policy is not automatically attached to existing application archives.
The consumer runner refuses a bundle without the signed ceiling; the normal
application route applies it without runtime flags. A three-turn artifact or a cheaper
model alias is not a substitute.

The shared OCI subprocess runner supports bounded one-shot stdin; its
hermetic test proves exact `tell me a joke\n` bytes and EOF without invoking
`mvmctl`. Its existing process-group kill on timeout is **not a native custody
recovery mechanism**. Do not wire it directly to a credential-bearing live run:
the consumer runner uses a separate native observer that retains the original
CLI owner and regular output files rather than killing a group on timeout.

## Hermetic checks

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_claude_demo_preflight.py -v
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-oci-bundle-smoke.py --backend hvf --self-test
```

These checks do not execute `mvmctl`, access credentials or make paid calls.
