# Design: the `ai` command — models run only in profile-matched microVMs

**Date:** 2026-07-29
**Status:** Design approved; implementation plan pending.
**Scope:** v1 is one-shot inference. Serving is phase 2, tool-calling is phase 3,
and both are gated by the boundaries stated in "Deferred, with boundaries".

## Goal

`mvmctl ai run <model> --vm-profile <p>` executes a model inside a microVM that
has been *proved* to satisfy that model's requirements, from a signed
`ExecutionPlan` that binds the model bytes, the runtime bytes, and the granted
resources together. A model whose requirements cannot be met is refused at
admission, not discovered as an OOM mid-generation.

mvm today is a sandbox for code an LLM writes. This adds the inverse: a sandbox
for the model itself.

## Decisions

Four load-bearing choices, settled before design:

1. **mvm orchestrates; it does not implement inference.** mvm owns acquisition,
   provenance, the capability match, the plan, the VM, and the audit trail. A
   third-party runtime does the arithmetic.
2. **Runtimes are pluggable behind a conformance-gated seam.** More than one
   inference runtime is supported. A runtime becomes admissible only by passing
   the conformance suite; the plan binds which runtime ran and its digest.
3. **Models are OCI artifacts.** Acquisition reuses the existing OCI provenance
   pipeline rather than growing a second one.
4. **Requirements are derived host-side at pull and frozen into the signed
   plan.** The guest never declares its own needs and never negotiates.

### Why pluggable, and what it actually costs

Pluggability avoids betting mvm's workload path on one third party's roadmap —
the same instinct that keeps VMM specifics behind `VmBackend` rather than
hardcoding one hypervisor. No single runtime covers every model, format, and
accelerator, and the format landscape (safetensors, GGUF) is not converging.

Two objections were raised against pluggability. One dissolves; one is real.

*Reproducibility — dissolves.* The concern was that different runtimes produce
different tokens for the same model and prompt (different dequantization paths,
sampler arithmetic, KV-cache precision), making the audit record
non-reproducible. But the plan already binds the runtime identity **and its
digest** alongside the model digest. `(model, runtime, runtime_digest, seed,
prompt) → output` remains an auditable relation; reproducibility is scoped
per-runtime, which is the honest guarantee and is sufficient. This objection was
overstated.

*Claim surface — real, and mitigated mechanically.* Each runtime is a fresh
untrusted-input parser, CVE stream, capability matrix, egress profile, guest
image, and footprint. The failure mode is not hypothetical: claim-10 egress
enforcement is currently live on two of four VM backends, because per-backend
enforcement was left to discipline. Pluggable runtimes go the same way unless a
runtime is **inadmissible until it proves itself**.

The answer is the conformance suite below. It is a precondition for admission,
enforced at plan synthesis, not a checklist someone is trusted to have run.

There is a genuine upside to being forced into this: with a single runtime, the
security properties would have been *implicitly* true of whichever runtime was
chosen and never stated. Pluggability forces them to be explicit and tested.

### The runtime seam

A runtime is described host-side by a registry entry and implemented guest-side
by a binary honouring the guest contract.

Host-side descriptor:

| Field | Meaning |
|---|---|
| `id` | Stable runtime identifier |
| `digest` | Digest of the guest binary/overlay carrying it |
| `formats` | Model formats this runtime accepts (never includes pickle) |
| `capabilities` | Ops, dtypes, quantizations it can execute |
| `overhead` | Resource overhead added to the model's own requirements |
| `conformance` | Attestation that this `(id, digest)` passed the suite |

Guest-side contract: declare capabilities, load a model from the read-only
volume, generate over chunked vsock. Three verbs, no more — the seam stays
narrow enough that a new runtime is a bounded amount of work.

### Reference runtime: candle

candle is the first runtime and the reference implementation of the seam. It is
Rust, safetensors-native, HF-backed, and builds static for a small guest.

Being precise: **candle uses `unsafe`** — memory-mapped safetensors access and
SIMD intrinsics at minimum. This is a meaningful reduction from a C++ runtime,
not the `forbid(unsafe_code)` guarantee `mvm-protocol` provides. Any claim
written about a runtime must say "no C/C++ on the workload path" only where that
is true of *that* runtime, never as a global property of `ai`.

candle's quantized/GGUF coverage is weaker than llama.cpp's. Under a pluggable
design this is no longer a dead end — it is the specific gap a second runtime
would fill, and the reason a GGUF-capable runtime is the obvious second entry.

**Footprint risk to measure in week one:** the complete guest footprint budget
is 50 MB, and it applies *per runtime image*. candle plus a tokenizer may exceed
it. Measure before embedding.

### Format policy across runtimes

Formats are per-runtime — candle accepts safetensors, a GGUF runtime accepts
GGUF. Two invariants hold **globally**, independent of runtime:

- **Pickle is never accepted by any runtime.** `.pt`/`.bin` pickle is arbitrary
  code execution on load. No registry entry may list it, and the loader refuses
  it before any runtime sees it.
- **Format detection is content-sniffed, never extension-based.** A file named
  `.safetensors` whose bytes are a pickle is refused. A model is dispatched to a
  runtime only after its true format is established.

Note what pluggability costs here: with a single safetensors-only runtime, "the
one format we accept has no code-execution semantics" would have been a claim.
It is now a weaker, per-runtime statement, and GGUF's richer metadata parser is
a larger attack surface than safetensors'. That is a real reduction in the
strength of the claim available, and the conformance suite's refusal ladder is
what keeps it from being a reduction in actual safety.

## Architecture

**The model is data; the runtime is code.** A runtime binary ships inside a
signed, dm-verity-sealed guest overlay and is measured like every other guest
executable. Model weights are a separate read-only volume. Swapping models never
re-seals the guest; swapping runtimes means selecting a different sealed
overlay, and the plan records which one. Neither digest is taken from the
guest's word.

**Model storage reuses the sealed-volume mechanism** that backs claim 11.
Models live at `<mvm_home>/volumes/models/<digest>/` alongside
`<mvm_home>/volumes/deps`, verified by the same `verify_sealed_volume`-shaped
path: a directory with a hash-chained manifest, checked before launch. SBOM and
CVE sidecars do not apply to weights, so the manifest carries an explicit
`kind: model` and their absence is by design rather than a stub — the verifier
must not have to guess which sidecars to expect.

**The model volume is dm-verity sealed, not merely hash-checked at admission.**
Admission-time hashing proves the bytes were correct when checked, not that they
stayed correct. Verity is continuous and kernel-enforced. A large, read-only,
long-lived blob reused across many runs is verity's ideal case, and the claim-3
machinery already exists. This matters because "sealed volume" will otherwise be
read as verity-strength when it is not.

### Crate placement

Following the existing dependency direction (high → low):

| Crate | Addition | Why here |
|---|---|---|
| `mvm-protocol` | `ModelRequirements`, `RuntimeCapabilities`, `Generate` DTOs | Already owns the Workload IR and policy DTOs; keeps these `no_std` and wasm-buildable |
| `mvm-fs` | `mvm_fs::model` — bounded format readers, one per accepted format | Pure parsing beside the ext4 writer and OCI unpacker; keeps mvm-fs a zero-mvm-dep leaf, so parsers are trivially fuzzable |
| `mvm-core` | `policy/model_requirements.rs` — derivation, `Profile::satisfies`, runtime registry and the three-party match; the `model` and `runtime` sections on `ExecutionPlan` | Derivation and matching are policy, not parsing; separating them makes the arithmetic unit-testable with no I/O |
| `mvm-hostd` | Admission check in `plan_admission.rs`, including the conformance gate | Where sealed-volume verification and plan admission already live |
| `mvm-cli` | `commands/ai/{pull,run,ls,profile,runtime}.rs` | Clap group = directory, one file per subaction |
| Guest | One runtime binary per runtime overlay | uid 901 under setpriv, model volume read-only, `Generate` on the existing vsock protocol |

`ai runtime list|show` exposes the registry — which runtimes exist, what each
accepts, and whether its conformance attestation is current.

`ai` is not folded into `run --image` because a model run is a different kind of
admission with its own requirement check, and that difference should be visible
rather than hidden behind a flag.

### Naming: "capability profile", and it extends templates

`--profile` is already taken. In `build image` and `template create` it means a
*nix image profile* — which software is in the guest. What `ai` needs is a
declared *resource and capability shape* — vCPUs, memory, available ops. Same
word, two axes, in adjacent commands. Resolved explicitly:

- The concept is a **capability profile**. Within `ai`'s own namespace the
  subcommand `ai profile list|show` is unambiguous, because it is a noun under
  `ai` rather than a flag.
- The flag is **`--vm-profile`**, never `--profile`. `--profile` is not a global
  argument, so there is no clap-level conflict, but reusing the word for a
  second meaning in a neighbouring command is exactly the ambiguity that costs
  someone an hour later.
- A capability profile **extends the existing template config rather than
  forking a parallel resource vocabulary.** Templates already declare a
  microVM's shape — cpus, memory, role, flake, image profile. Adding a declared
  capability set to that schema is an extension; inventing a second "profile"
  type that also carries cpus and memory would be a duplicate source of truth
  for the same facts, which is this repo's most common bug source.

What remains open is schema mechanics, not direction — see "Open questions".

## Data flow

### `ai pull <oci-ref>`

1. Resolve the reference. Under `--prod`, refuse a mutable reference **before
   any network fetch**.
2. Fetch the manifest, verify cosign against the configured registry policy,
   resolve to a digest.
3. Stream layers through the allow-listed OCI unpacker to disk. Never buffer a
   model in host RAM — a 30 B model is a 30 GB allocation.
4. **Content-sniff** the format. Pickle is refused outright. A format no
   registered runtime accepts is refused, naming the format and listing what is
   accepted. Extension is never consulted.
5. Parse the format header under bounds (see "Host-side parsing").
6. Derive `ModelRequirements` from **summed actual tensor shapes** plus dtype
   and context length — not from a declared parameter count. A model claiming
   7 B while carrying 70 B of weights would otherwise be granted an undersized
   VM.
7. Seal the volume: `content/`, hash-chained `meta.json` (`kind: model`),
   verity sidecar and roothash.
8. Emit `model.pulled` to the chain-signed audit log: registry host, repository,
   supplied reference, resolved manifest digest, layer digest list, trust
   policy, cosign verdict, detected format, derived requirements, verity
   roothash.

### `ai run <model> --vm-profile <p> [--runtime <id>]`

1. Verify the sealed volume and the verity roothash.
2. **Select the runtime.** Explicit `--runtime` if given; otherwise the single
   registered runtime accepting this model's format. Ambiguity is a refusal
   naming the candidates — never an implicit pick, because which runtime ran is
   a security-relevant fact and guessing it silently is how a model ends up
   somewhere unintended.
3. **Three-party match.** The runtime must accept the model's format and
   capabilities; the profile must satisfy the model's requirements *plus* the
   runtime's declared overhead. Failure is refused with a per-dimension diff
   naming what was unmet and by which party.
4. **Conformance gate.** The selected `(runtime_id, digest)` must carry a
   current conformance attestation. An unattested runtime is refused here, with
   no override flag.
5. Apply the host memory-grant ceiling, independent of what the model asks for.
6. Synthesize an `ExecutionPlan` binding model digest, runtime id, runtime
   digest, conformance attestation, verity roothash, resolved profile, frozen
   requirements, sampler seed, and prompt digest. Sign under the host signer,
   verify, enforce the validity window and the nonce replay store.
7. Admit: re-verify the sealed volume, re-check the three-party match and the
   conformance gate, confirm the resolved network policy is deny-all absent an
   explicit opt-in.
8. Emit `plan.admitted`. Boot a transient microVM — verity rootfs, read-only
   verity model volume, no network, no console, agent at uid 901.
9. Deliver the prompt over chunked vsock. Stream tokens back chunked.
10. Sanitize control sequences on the host before stdout.
11. Emit `plan.launched`, then `model.generated`: runtime id and digest, prompt
    digest, output digest, token counts, seed, duration. **No prompt or output
    bytes.**
12. Destroy the VM. Transient is the default lifecycle.

## Runtime conformance suite

A runtime is inadmissible until `(id, digest)` passes every check. The
attestation is recorded in the registry and verified at plan synthesis and again
at admission. This is the mechanism that keeps pluggability from reproducing the
partially-enforced backend matrix.

1. **Refusal ladder** — presented with a pickle payload, a truncated header, an
   offset past EOF, and a declared-huge header, the runtime refuses each with a
   named error rather than crashing, hanging, or loading. Formats differ between
   runtimes; refusal behaviour does not.
2. **No egress at load** — loads a model with deny-all egress and no network
   device, and succeeds. Catches runtimes that fetch tokenizers or configs at
   load time.
3. **Determinism** — fixed model, prompt and seed produce byte-identical output
   across two runs of the same `(id, digest)`. Scoped per-runtime by design;
   cross-runtime agreement is explicitly not claimed.
4. **Capability honesty** — declared capabilities match observed behaviour. A
   model using a declared-supported op runs; a model needing an undeclared op is
   refused *at admission*, not by failing mid-generation.
5. **Footprint** — the guest image carrying this runtime stays within budget.
6. **No interactive surface** — the runtime binary links no console or exec
   path, mirroring the claim-15 symbol contract.
7. **Frame discipline** — chunked `Generate` respects `MAX_FRAME_SIZE` in both
   directions and refuses oversize frames.

Adding a runtime means passing this suite. Failing any check means the runtime
cannot be selected, with no flag to override.

## Security surfaces

### Host-side parsing — the deliberate inversion

Deriving requirements host-side means a hostile model file attacks the **host**
parser before any microVM exists. This inverts mvm's usual posture and is
accepted deliberately, under bounds:

- Header length capped; a larger declared length is refused, not allocated.
- Every tensor offset and size validated against actual file length.
- Checked arithmetic on all `offset + size` computations.
- `forbid(unsafe_code)` in `mvm_fs::model`.
- Tensor *data* is never read on the host. Only the header.
- A `cargo-fuzz` target per accepted format, as claim-5-style witnesses.

Pluggability raises the stakes here: each accepted format adds a host-side
parser, and GGUF's metadata parser is substantially richer than safetensors'.
The per-format fuzz target is therefore a requirement for accepting a format,
not a follow-up.

**Documented upgrade path:** derive inside a disposable microVM using the
existing Stage-0/dev tier, so no untrusted model bytes are parsed on the host at
all. Strictly stronger. Deferred because it puts a VM boot on the `ai pull` path
and needs a trusted channel for returning derived requirements. **If a second
format lands and the host-side parser surface grows, this upgrade becomes
mandatory rather than optional.**

### Terminal escape injection

Generated tokens reach the user's terminal. Model output can carry ANSI/OSC
sequences — cursor manipulation, hyperlinks, clipboard writes on some
terminals. Control sequences are stripped on output by default, with an explicit
opt-out for raw. This is an attack on the operator, not the guest.

### Chat templates are an interpreter on untrusted input

Hugging Face models ship Jinja2 chat templates. Template semantics over
attacker-controlled data is a computation-DoS surface at best. **v1 refuses
templates outright** and treats the prompt as literal text. If templating ever
lands, it renders *only* inside the guest, never on the host, and template
handling joins the conformance suite.

### Framing

`MAX_FRAME_SIZE` is 256 KiB. Long-context prompts and streamed generations
exceed it, so `Generate` is chunked — and chunking is where framing bugs live.
The chunked path joins the fuzzed surface alongside `GuestRequest` and
`AuthenticatedFrame`, and frame discipline is a conformance check so a new
runtime cannot quietly get it wrong.

### Prompt confidentiality

Prompts routinely carry secrets.

- Never on a command line. Anything in argv is world-readable via `ps`.
- Never in an environment variable of a child process.
- Delivered over vsock or by file descriptor.
- The plan carries the prompt **digest**, never the prompt.
- The audit chain carries prompt and output **digests**, never bytes.

### Resource arithmetic

A model declaring a 2³¹ context length derives a KV-cache floor in the
petabytes. Derivation uses checked arithmetic and an absolute ceiling; an absurd
requirement is a refusal, not a VM spec. Runtime overhead is added with the same
checked arithmetic. Separately, the host enforces a memory-grant ceiling
independent of the model's ask, so a single `ai run` cannot exhaust the machine.

### Failure ladder

Eighteen named refusals, each with a test, none silently degrading:

1. Mutable reference under `--prod` — refused before network I/O
2. cosign verdict failure — refused before cache admission
3. Unpack path escape, symlink, or device node
4. Content-sniffed format is pickle — refused globally
5. Content-sniffed format accepted by no registered runtime
6. Header length over cap
7. Header length past EOF
8. Tensor offset or size overflow, or past EOF
9. Derived requirement over the absolute ceiling
10. Volume manifest tamper
11. Verity roothash mismatch
12. Runtime selection ambiguous — refused naming the candidates
13. Selected runtime does not accept the model's format or capabilities
14. Profile does not satisfy requirements plus runtime overhead — per-dimension diff
15. Profile ask over the host grant ceiling
16. Runtime lacks a current conformance attestation — no override
17. Unsigned, expired, or replayed plan
18. Resolved egress policy is not deny-all without an explicit opt-in

## Deferred, with boundaries

These are not omissions. Each is a boundary a later phase must argue past rather
than drift across.

### Prompt injection — out of scope only while `ai` is one-shot

v1 has no tools, so model output is data that reaches a terminal and nothing
else. **The moment model output can trigger a tool call, output becomes control
flow and the threat model changes completely** — an untrusted string starts
selecting actions. Phase 3 (agentic use) may not be added as an increment to
this design; it requires its own threat model covering at minimum: which verbs
model output may select, how those verbs are bound in the plan the way broker
services already are, and what the audit record of a model-selected action looks
like. The plan-bound verb enforcement machinery is the obvious foundation, and
the default must remain that model output selects nothing.

### Warm-pool KV residue — a phase-2 blocker for `ai serve`

Serving means reusing a warm VM across prompts. Prior prompt data persists in
guest memory, and the agent explicitly does not scrub between calls —
cross-call state is documented as the caller's responsibility. For a single
tenant's successive prompts that is a confidentiality question; across tenants
it is a confidentiality **bug**. `ai serve` cannot ship on the warm pool until
one of these holds:

- the guest scrubs KV-cache and prompt buffers between generations, with a test
  proving residue is absent; or
- a warm VM is bound to exactly one tenant for its whole life, enforced at claim
  time rather than by convention; or
- serving uses cold transient VMs per request, accepting the latency.

Under pluggability this becomes a **per-runtime** obligation and therefore joins
the conformance suite when serving lands — one runtime scrubbing correctly says
nothing about another.

This also queues behind the standby pool's own pre-flip blockers.

### Timing and resource side channels — out of scope, stated

Inference timing leaks prompt and output length, and shared-CPU cache effects
are real. Consistent with the existing exclusion of hardware-level attacks from
the threat model. Recorded so the exclusion is deliberate rather than silent. A
co-tenant threat model would have to revisit this; the single-workload-per-guest
rule is what currently makes it tolerable.

### GPU acceleration — out of scope, and it moves the C/C++ line

Accelerator backends pull in vendor toolchains — CUDA kernels, Metal shaders —
which moves C/C++ onto the workload path. microVM guests have no GPU passthrough
today, so CPU-only is the natural v1 scope. Under pluggability this is cleaner
than it would have been: a GPU-capable runtime is a *separate registry entry*
with its own conformance run and its own honest description of what it pulls in,
rather than a compile-time flag quietly changing the properties of the one
runtime.

### Model licensing and use restrictions — not addressed

Weights frequently carry licence terms restricting use. mvm records provenance
and makes no licence assertion. Noted so nobody reads `model.pulled` provenance
as a licence check.

## Testing

- **Unit** — derivation arithmetic (overflow, ceiling, dtype table); every
  `Profile::satisfies` dimension independently; runtime selection including the
  ambiguity refusal; content sniffing against each rejected magic; header
  validation against each malformed case.
- **Conformance** — the seven-check suite, run per runtime, gating admission.
  It is written **before** the second runtime exists, so the seam is validated
  by the suite rather than shaped by one implementation's accidents.
- **Fuzz** — one target per accepted format header; the chunked `Generate`
  framing.
- **Tamper** — byte-flip in `content/` caught by verity; `meta.json` tamper
  caught by the volume verifier; digest swap refused; a forged or stale
  conformance attestation refused.
- **Claims** — this adds claim-bearing behaviour, so it needs rows in the claims
  ledger with `fn:` and `ci:` witnesses. Those witnesses enter the mutation
  surface automatically via the ledger-derived pin, so a witness that cannot
  detect its property breaking will be reported.
- **CI** — an `ai-model-admission` lane exercising pull → run against a tiny
  fixture model with no network access, plus the refusal ladder and the
  conformance suite.

## Open questions

- How many runtimes ship in v1 — candle alone with the seam and suite proven by
  a mock, or candle plus a GGUF runtime so the seam is validated against a
  genuinely different format and language? See the note below.
- Does candle plus a tokenizer fit the 50 MB guest footprint budget? Measure
  before embedding. The budget applies per runtime image.
- How exactly does a capability profile attach to the template schema — a new
  optional section, or a separate file keyed by template name? Direction is
  settled (extend templates, do not fork a resource vocabulary); only the
  mechanics are open.
- Does verity on a second, very large volume add measurable boot cost? If it
  does, the fallback is admission-time hashing with the weaker guarantee stated
  explicitly rather than silently.
