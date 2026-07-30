# Design: the `ai` command — models run only in profile-matched microVMs

**Date:** 2026-07-29
**Status:** Design approved; implementation plan pending.
**Scope:** v1 is one-shot inference. Serving is phase 2, tool-calling is phase 3,
and both are gated by the boundaries stated in "Deferred, with boundaries".

## Goal

`mvmctl ai run <model> --vm-profile <p>` executes a model inside a microVM that has
been *proved* to satisfy that model's requirements, from a signed
`ExecutionPlan` that binds the model bytes, the runtime bytes, and the granted
resources together. A model whose requirements the profile cannot meet is
refused at admission, not discovered as an OOM mid-generation.

mvm today is a sandbox for code an LLM writes. This adds the inverse: a sandbox
for the model itself.

## Decisions

Four load-bearing choices, settled before design:

1. **mvm orchestrates; it does not implement inference.** mvm owns acquisition,
   provenance, the capability match, the plan, the VM, and the audit trail. A
   single pinned third-party runtime does the arithmetic.
2. **One runtime, pinned, digest-bound — `candle`.** Not pluggable.
3. **Models are OCI artifacts.** Acquisition reuses the existing OCI provenance
   pipeline rather than growing a second one.
4. **Requirements are derived host-side at pull and frozen into the signed
   plan.** The guest never declares its own needs and never negotiates.

### Why one runtime, not a pluggable set

Two properties mvm actually sells break under N runtimes.

*Reproducibility.* The same `mvmctl` is supposed to produce the same result on
every host. Different runtimes produce different tokens for the same model and
prompt — different dequantization paths, sampler arithmetic, KV-cache precision.
Since `ai run` writes provenance to a chain-signed audit log, a pluggable
runtime makes that record non-reproducible: the log names the model and prompt
while the output depended on something absent from the plan. Pinning one runtime
and putting *its* digest in the plan is what makes
`(model, runtime, seed, prompt) → output` an auditable relation.

*Claim surface.* Each runtime is a fresh untrusted-input parser, CVE stream,
capability matrix, and egress profile — several runtimes fetch tokenizers at load
time, which is a separate egress problem each time. The per-backend tier matrix
is already incomplete (claim-10 egress enforcement is live on two of four VM
backends). Multiplying the workload-bearing surface again is how that matrix
stays permanently incomplete.

The seam is defined without the plurality: a narrow guest-side contract
(declare capabilities, load model, generate) with exactly one implementation
behind it. A second implementation is a rebuild, not a portability break,
because mvm controls the guest image end to end — which is why runtime lock-in
is not the same risk as VMM lock-in.

### Why candle, and what it costs

The runtime's security-relevant job is parsing untrusted binary files — headers,
tensor layouts, tokenizer data. Doing that in Rust rather than C++ is the
largest available reduction in this choice, and it keeps C/C++ off the workload
path.

Being precise: **candle uses `unsafe`** — memory-mapped safetensors access and
SIMD intrinsics at minimum. This is a meaningful reduction from a C++ runtime,
not the `forbid(unsafe_code)` guarantee `mvm-protocol` provides. Any claim
written about this must say "no C/C++ on the workload path", never "memory-safe".

safetensors-first also buys a claim that is otherwise unavailable: safetensors
has no execution semantics — a JSON header and a flat tensor region. Pickle
(`.pt`/`.bin`) is arbitrary code execution on load. Supporting exactly one
format, and that format having no code-execution semantics, is a cheap and
defensible position.

The cost, stated plainly: candle's quantized/GGUF coverage is weaker than
llama.cpp's. This design targets provably-isolated auditable inference of
moderate models, not maximum model size per gigabyte of host RAM. If the latter
becomes the requirement, this decision must be revisited rather than stretched.

**Footprint risk to measure in week one:** the complete guest footprint budget
is 50 MB. candle plus a tokenizer may exceed it. This is an engineering
constraint, not a security one, but it could force decision 2 to be revisited,
so it must be measured before the runtime is embedded.

## Architecture

**The model is data; the runtime is code.** The candle-based inference binary
ships inside the signed, dm-verity-sealed guest overlay and is measured like
every other guest executable. Model weights are a separate read-only volume.
Swapping models never re-seals the guest; the runtime stays measured
independently. The plan binds both digests, and neither is taken from the
guest's word.

**Model storage reuses the sealed-volume mechanism** that backs claim 11.
Models live at `<mvm_home>/volumes/models/<digest>/` alongside
`<mvm_home>/volumes/deps`, verified by the same
`verify_sealed_volume`-shaped path: a directory with a hash-chained manifest,
checked before launch. SBOM and CVE sidecars do not apply to weights, so the
manifest carries an explicit `kind: model` and their absence is by design rather
than a stub — the verifier must not have to guess which sidecars to expect.

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
| `mvm-protocol` | `ModelRequirements`, `Generate` request/response DTOs | Already owns the Workload IR and policy DTOs; keeps these `no_std` and wasm-buildable |
| `mvm-fs` | `mvm_fs::model` — bounded safetensors header reader | Pure parsing beside the ext4 writer and OCI unpacker; keeps mvm-fs a zero-mvm-dep leaf, so the parser is trivially fuzzable |
| `mvm-core` | `policy/model_requirements.rs` — derivation and `Profile::satisfies`; the `model` section on `ExecutionPlan` | Derivation is policy, not parsing; separating them makes the arithmetic unit-testable with no I/O |
| `mvm-hostd` | Admission check in `plan_admission.rs` | Where sealed-volume verification and plan admission already live |
| `mvm-cli` | `commands/ai/{pull,run,ls,profile}.rs` | Clap group = directory, one file per subaction |
| Guest | candle runtime in the runtime overlay | uid 901 under setpriv, model volume read-only, `Generate` on the existing vsock protocol |

Four subcommands clears the grouping map's bar against single-member and
semantically-forced groups. `ai` is not folded into `run --image` because a
model run is a different kind of admission with its own requirement check, and
that difference should be visible rather than hidden behind a flag.

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
  capability set to that schema is an extension; inventing a second
  "profile" type that also carries cpus and memory would be a duplicate source
  of truth for the same facts, which is this repo's most common bug source.

What remains open is schema mechanics, not direction — see "Open questions".

## Data flow

### `ai pull <oci-ref>`

1. Resolve the reference. Under `--prod`, refuse a mutable reference **before
   any network fetch**.
2. Fetch the manifest, verify cosign against the configured registry policy,
   resolve to a digest.
3. Stream layers through the allow-listed OCI unpacker to disk. Never buffer a
   model in host RAM — a 30 B model is a 30 GB allocation.
4. **Content-sniff** the format. Exactly one is accepted: safetensors. Anything
   else is refused, naming the detected format. Extension is never consulted.
5. Parse the safetensors header under bounds (see "Host-side parsing").
6. Derive `ModelRequirements` from **summed actual tensor shapes** plus dtype
   and context length — not from a declared parameter count. A model claiming
   7 B while carrying 70 B of weights would otherwise be granted an undersized
   VM.
7. Seal the volume: `content/`, hash-chained `meta.json` (`kind: model`),
   verity sidecar and roothash.
8. Emit `model.pulled` to the chain-signed audit log: registry host, repository,
   supplied reference, resolved manifest digest, layer digest list, trust
   policy, cosign verdict, derived requirements, verity roothash.

### `ai run <model> --vm-profile <p>`

1. Verify the sealed volume and the verity roothash.
2. Resolve the named profile. Evaluate `Profile::satisfies(&requirements)`; on
   failure, refuse with a per-requirement diff naming each unmet dimension.
3. Apply the host memory-grant ceiling, which is independent of what the model
   asks for.
4. Synthesize an `ExecutionPlan` binding model digest, runtime digest, verity
   roothash, resolved profile, frozen requirements, sampler seed, and prompt
   digest. Sign under the host signer, verify, enforce the validity window and
   the nonce replay store.
5. Admit: re-verify the sealed volume, re-check `satisfies`, confirm the
   resolved network policy is deny-all absent an explicit opt-in.
6. Emit `plan.admitted`. Boot a transient microVM — verity rootfs, read-only
   verity model volume, no network, no console, agent at uid 901.
7. Deliver the prompt over chunked vsock. Stream tokens back chunked.
8. Sanitize control sequences on the host before stdout.
9. Emit `plan.launched`, then `model.generated`: prompt digest, output digest,
   token counts, seed, duration. **No prompt or output bytes.**
10. Destroy the VM. Transient is the default lifecycle.

## Security surfaces

### Host-side parsing — the deliberate inversion

Deriving requirements host-side means a hostile model file attacks the **host**
parser before any microVM exists. This inverts mvm's usual posture and is
accepted deliberately, under bounds:

- Header length capped at 16 MiB; a larger declared length is refused, not
  allocated.
- Every tensor offset and size validated against actual file length.
- Checked arithmetic on all `offset + size` computations.
- `forbid(unsafe_code)` in `mvm_fs::model`.
- Tensor *data* is never read on the host. Only the header.
- A `cargo-fuzz` target (`fuzz_safetensors_header`) as a claim-5-style witness.

**Documented upgrade path:** derive inside a disposable microVM using the
existing Stage-0/dev tier, so no untrusted model bytes are parsed on the host at
all. Strictly stronger. Deferred because it puts a VM boot on the `ai pull` path
and needs a trusted channel for returning the derived requirements, and because
a bounded header parse is small enough to prove. If the header parser ever grows
beyond header parsing, this upgrade becomes mandatory rather than optional.

### Terminal escape injection

Generated tokens reach the user's terminal. Model output can carry ANSI/OSC
sequences — cursor manipulation, hyperlinks, clipboard writes on some
terminals. Control sequences are stripped on output by default, with an explicit
opt-out for raw. This is a real attack on the operator, not the guest.

### Chat templates are an interpreter on untrusted input

Hugging Face models ship Jinja2 chat templates. Template semantics over
attacker-controlled data is a computation-DoS surface at best. **v1 refuses
templates outright** and treats the prompt as literal text. If templating ever
lands, it renders *only* inside the guest, never on the host.

### Framing

`MAX_FRAME_SIZE` is 256 KiB. Long-context prompts and streamed generations
exceed it, so `Generate` is chunked — and chunking is where framing bugs live.
The chunked path joins the fuzzed surface alongside `GuestRequest` and
`AuthenticatedFrame`; it does not sit beside it unfuzzed.

### Prompt confidentiality

Prompts routinely carry secrets.

- Never on a command line. Anything in argv is world-readable via `ps`.
- Never in an environment variable of a child process.
- Delivered over vsock or by file descriptor.
- The plan carries the prompt **digest**, never the prompt.
- The audit chain carries prompt and output **digests**, never bytes —
  consistent with the existing no-payload-bytes property of the broker channel.

### Resource arithmetic

A model declaring a 2³¹ context length derives a KV-cache floor in the
petabytes. Derivation uses checked arithmetic and an absolute ceiling; an absurd
requirement is a refusal, not a VM spec. Separately, the host enforces a
memory-grant ceiling independent of the model's ask, so a single `ai run`
cannot exhaust the machine.

### Format confusion

Format detection is content-based. A file named `.safetensors` whose bytes are a
pickle is refused. Extension-driven detection is the weak version of this and is
not used.

### Failure ladder

Fifteen named refusals, each with a test, none silently degrading:

1. Mutable reference under `--prod` — refused before network I/O
2. cosign verdict failure — refused before cache admission
3. Unpack path escape, symlink, or device node
4. Content-sniffed format is not safetensors
5. Header length over cap
6. Header length past EOF
7. Tensor offset or size overflow, or past EOF
8. Derived requirement over the absolute ceiling
9. Volume manifest tamper
10. Verity roothash mismatch
11. Profile does not satisfy requirements — with a per-requirement diff
12. Profile ask over the host grant ceiling
13. Unsigned, expired, or replayed plan
14. Resolved egress policy is not deny-all without an explicit opt-in
15. Guest reports a missing capability at load

## Deferred, with boundaries

These are not omissions. Each is a boundary that a later phase must argue past
rather than drift across.

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
it is a confidentiality **bug**. `ai serve` therefore cannot ship on the warm
pool until one of the following holds:

- the guest scrubs KV-cache and prompt buffers between generations, with a test
  proving residue is absent; or
- a warm VM is bound to exactly one tenant for its whole life, enforced at
  claim time rather than by convention; or
- serving uses cold transient VMs per request, accepting the latency.

This interacts with the standby pool shipping disarmed: the pool's own pre-flip
blockers must clear before this one is even reachable.

### Timing and resource side channels — out of scope, stated

Inference timing leaks prompt and output length, and shared-CPU cache effects
are real. Consistent with the existing exclusion of hardware-level attacks from
the threat model. Recorded so the exclusion is deliberate rather than silent. A
co-tenant threat model would have to revisit this, and the single-workload-per-
guest rule is what currently makes it tolerable.

### GPU acceleration — out of scope, and it moves the C/C++ line

candle is Rust end-to-end on the CPU path. Accelerator backends pull in vendor
toolchains — CUDA kernels, Metal shaders — which moves C/C++ back onto the
workload path and would weaken the justification for decision 2. microVM guests
have no GPU passthrough today, so CPU-only is the natural v1 scope. Any GPU work
must re-argue the runtime choice rather than inherit it.

### Model licensing and use restrictions — not addressed

Weights frequently carry licence terms restricting use. mvm records provenance
and makes no licence assertion. Out of scope, noted so nobody reads
`model.pulled` provenance as a licence check.

## Testing

- **Unit** — derivation arithmetic (overflow, ceiling, dtype table); every
  `Profile::satisfies` dimension independently; content sniffing against each
  rejected magic; header validation against each malformed case.
- **Fuzz** — `fuzz_safetensors_header`; the chunked `Generate` framing.
- **Tamper** — byte-flip in `content/` caught by verity; `meta.json` tamper
  caught by the volume verifier; digest swap refused.
- **Claims** — this adds claim-bearing behaviour, so it needs rows in the
  claims ledger with `fn:` and `ci:` witnesses. Those witnesses enter the
  mutation surface automatically via the ledger-derived pin, which means a
  witness that cannot detect its property breaking will be reported.
- **CI** — an `ai-model-admission` lane exercising pull → run against a tiny
  fixture model with no network access, plus the refusal ladder.

## Open questions

- Does candle plus a tokenizer fit the 50 MB guest footprint budget? Measure
  before embedding. A miss forces decision 2 to be revisited.
- How exactly does a capability profile attach to the template schema — a new
  optional section, or a separate file keyed by template name? Direction is
  settled (extend templates, do not fork a resource vocabulary); only the
  mechanics are open.
- Does verity on a second, very large volume add measurable boot cost? If it
  does, the fallback is admission-time hashing with the weaker guarantee stated
  explicitly rather than silently.
