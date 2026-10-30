# Public Claude consumer acceptance

`claude-demo-consumer.py` is a separately authorized live witness for
[mvm-packs#84](https://github.com/tinylabscom/mvm-packs/issues/84).
Its hermetic tests do not launch `mvmctl` or contact a model.

## Prepare before opting in

Use an approved native Apple Silicon consumer, outside a source checkout.
Prepare a private mode-0700 HOME containing a private MVM_HOME with only public
trust/configuration, an already-enrolled caller identity for the exact final
executable, and exactly one Anthropic-provider host binding. No enrollment,
credential import, trust-key addition, cleanup or permission change is done by
the runner. Never pass a credential value in any option or environment variable.

The CLI must be the absolute, independently verified released executable, with
no symlinks or writable permission bits and an OS immutable flag. Enrollment
must already cover that exact executable. `--check-readiness` reads only public
caller/binding metadata; the actual native launch must authenticate the caller.
The runner verifies the CLI code signature and checks its digest and file
identity before and after the witness.

Obtain these nonsecret assertions independently from the public release:

- `--cli`, `--cli-sha256`, `--version`, `--release-commit`.
- `--home`, `--mvm-home`, `--caller-installation`,
  `--caller-public-key-sha256` (hash of the 32 raw public-key bytes),
  and `--binding-name`.
- `--descriptor-sha256`, `--archive-sha256`, `--archive-size`, `--key-id`,
  and `--archive-url` (exact public HTTPS source, without credentials or query).
- `--kernel-sha256`, `--rootfs-sha256`, `--rootfs-roothash`,
  `--runtime-version`, `--runtime-archive-sha256`,
  `--runtime-overlay-roothash`.

The genuine public `agent/claude@2.0.0` archive must carry a signed environment
with its normal default entrypoint, exactly the required `ANTHROPIC_API_KEY`
slot, and this policy:

```json
{
  "allow_hosts": ["api.anthropic.com:443"],
  "request_budget": {
    "max_requests": 1,
    "max_spend_microusd": 500000,
    "model": "claude-haiku-4-5-20251001"
  }
}
```

The installed application route applies the ceiling automatically and admission
refuses omission or widening. It grants no new egress. No `--secret`,
`--allow-host`, `--entrypoint`, backend flag, local registry, source checkout or
Nix evaluation is used. The artifact owner must make the baked client compatible
with this policy: exact model ID, output bound fitting the reservation, no
unreviewed beta headers or provider-side tools. This runner does not rebuild,
re-export, repair, transfer or publish an artifact.

Review the current provider tariff before authorizing a charge. The conservative
reservation uses the full 200K context at $2/MTok plus output at $5/MTok; 20,000
maximum output tokens reserve $0.50. It is not a provider-account billing cap,
and does not cover taxes, account charges or future price changes.

## Explicit live authorization

Invoke `python3 scripts/claude-demo-consumer.py` with all assertions above,
`--check-readiness`, `--endpoint api.anthropic.com:443`, `--budget-usd 0.50`,
`--authorize-model-request`, and `MVM_TEST_CLAUDE_DEMO=1`.
The parser refuses missing assertions; `--help` is safe and lists every option.
Only provide the authorization flag after separate consent for this exact run.

The executable workflow is:

```text
mvmctl --version
mvmctl env caller-identity show
mvmctl secret ls
mvmctl search agent/claude
mvmctl pull agent/claude
mvmctl pack verify agent/claude@2.0.0 --json
printf '%s\n' 'tell me a joke' | mvmctl run agent/claude
```

The readiness reads precede version/search in the implementation. The final
invocation uses an actual stdin pipe containing exactly `tell me a joke\n`.
The fixed prompt is written and the pipe's writer closed before spawning the
CLI, so its immediate stdin-readiness check sees both the payload and EOF.
There is one invocation and no automatic retry. A durable create-only
`MVM_HOME/claude-demo-attempt.json` reservation is synced **before** spawning.
Failure or interruption never releases that reservation.
After intent is reserved, `model_request_attempted` is `null` (unknown) until
correlated canonical evidence establishes a provider request. Neither the
intent file nor a PID observation is proof that a model ran or did not run.

## Evidence and recovery

Private `/tmp/mvm-claude-consumer-*` evidence preserves actual stdout/stderr,
the exact command vectors, release/artifact assertions, and canonical audit
verifier/show results. A particular joke is not asserted. Passing requires:

- Zero command exit and nonempty actual stdout, with stderr also preserved.
- Automatic HVF in the canonical launch/exit events.
- The original native completion token's rootfs/runtime/network observations,
  emitted by the original owner before the session seal.
- One intact, fully verified audit session, with no late entries.
- Exactly one endpoint reservation and one successful Anthropic response usage
  record, with matching VM and endpoint budget-lifetime identities.
- The expected host binding in both the reservation and canonical substitution
  handoff evidence.
- A canonical completed, direct forward outcome, not a proxy or partial delivery.
- Matching signed descriptor/archive facts and executable identity after run.

`audit_session_id` is the canonical audit session's plan ID, not an invented SDK
session identifier. The native boot nonce and endpoint budget UUID are public
observations, **not cleanup capabilities**. The kernel identity is taken from
canonical admission; retained rootfs/runtime facts come from native custody.
Missing or unsupported evidence fails acceptance, rather than being inferred
from command success or an agent claim.

On timeout (default 180 seconds, maximum 300), interruption or uncertain custody,
the runner sends no numeric signal and performs no external stop or deletion.
The original CLI runs in its own session with regular private output files,
so loss of the observer does not close its output pipe or deliberately kill its
custody owner. Retain the consumer HOME, original owner and recovery evidence.
Do not retry or delete a credential merely because a PID disappears. An
operator must resolve recovery through the canonical original-owner path.
Endpoint recreation or VM relaunch is outside this authorization.

The full live path remains unperformed until separately authorized with real
released inputs. Hermetic coverage, synthetic audit fixtures and source-only
archives are not public demo acceptance.

## Hermetic validation

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p 'test_claude_demo_*.py' -v
PYTHONDONTWRITEBYTECODE=1 python3 scripts/claude-demo-consumer.py --help
```
