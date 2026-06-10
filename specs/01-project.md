# Project overview

We're building the most secure sandbox available for running untrusted code,
and we refuse to trade away developer experience to get there. Attestation,
auditability, logging, encryption, and traceability are built into the
foundation — not bolted on — and the whole thing is meant to feel effortless.

Our posture is uncompromising. We never allow interactive access to a running
production microVM — no SSH, no console, no shell. We never patch or update a
running microVM; **we rebuild it from source and replace it.** Every workload
runs from a signed, audited plan, so nothing executes without full traceability.
And because we own the entire transport layer between the microVM and the
outside world, no secret ever lives inside a running workload — and sensitive
data, including personally identifiable information, is stripped from traffic in
both directions, whether you declared it or we detected it.

We run on many backends — libkrun and Apple Virtualization.framework on macOS,
Firecracker on Linux KVM, with Apple Container, cloud-hypervisor, and a WASM
sandbox alongside — and we support the operations people already expect: pull,
build, run, snapshot, pause/resume, stop, and clean up, plus host-mediated
service interactions. It runs on both Arm and x86-64 hardware.

Because security is the point, every piece of data is encrypted on the host.
We don't expose the guest on a raw network socket: we carry its tun/tap traffic
over vsock to a local Unix domain socket that only trusted clients may speak to.

Two technologies sit at the center of everything we do — they're what let us
deliver fast instantiation, predictable warm and cold states, and a hardened
substrate at the same time:

1. **MicroVMs**
2. **Nix**

## Who it's for

The sandbox exists for one hard problem: running code you don't fully trust,
fast, without it touching anything it shouldn't. That shows up in a few places:

- **AI agents running generated code.** When an agent writes and executes code,
  or runs code on a user's behalf, every execution is untrusted by definition.
  This is a safe place to run it, with the network, secrets, and filesystem all
  under policy.
- **Code interpreters for AI products.** Back a chat or notebook feature with a
  real, stateful execution environment that returns rich results, without handing
  users your infrastructure.
- **Regulated and security-conscious environments.** When you have to prove
  isolation, prove that nothing persists between sessions, and produce a signed
  audit trail of exactly what ran, those guarantees are built in.
- **CI and build isolation.** Run untrusted builds, tests, and third-party steps
  in disposable microVMs instead of on shared runners.

If you're handing a machine work you didn't write and can't fully vet, this is
where it should run.

## The foundations

### MicroVMs

MicroVMs are a stronger isolation technology than containers. Rather than
sharing a kernel with the host, each microVM runs its own kernel and its own
root filesystem on top of hardware virtualization. They're lightweight, boot in
milliseconds, and consume far less than a traditional VM. Their own kernel and
minimal device surface dramatically shrink the blast radius of a compromised
workload — and of the hosts running them.

We build our own minimal guest kernel: a small, purpose-built kernel with only
what a workload needs. That keeps boots fast, the attack surface narrow, and the
images lean.

### Nix

Nix is how we make builds predictable. Given the same inputs, a Nix build
produces the same output every time — the same packages, pinned to the same
versions, assembled the same way. That determinism is what makes "rebuild
instead of update" practical: when something needs to change, we don't mutate a
live machine and hope, we rebuild the image from a known-good definition and
replace it wholesale. Reproducible inputs in, predictable microVM out.

It's also what lets us promise the same result on every host. Builds are
hermetic — they don't depend on whatever happens to be installed on the machine
running them — so a workload built on one developer's laptop is the workload
that runs in production.

### The builder VM

Builds don't run on your machine — they run inside a VM we launch and control end
to end. The host's installed tools, versions, and quirks never touch the result;
the entire build environment, from the kernel up, is ours. That's what lets us
promise the same artifact on every host, and it keeps the build under the same
control and scrutiny as the workload it produces — nothing reaches in from the
outside to influence what gets built.

That same builder VM is also your development environment. In dev mode you can
drop into an interactive shell inside it — the one place we offer a live,
hands-on environment — to explore, prototype, and iterate with the exact
toolchain your builds use. You develop in the very environment that builds your
workload, then ship.

## Authoring without Nix — the SDK

Nix is the engine, but we never make users learn it. You describe a workload in
the language you already write — Python, TypeScript, etc. — and we derive everything
underneath: the image, the kernel, the build, the launch plan. Making this
effortless is a die-hard goal of the project; we treat developer experience as a
first-class feature, not an afterthought.

There are two patterns, and they meet very different needs.

### The decorator pattern (declarative)

Decorate a function with `@mvm.app(...)` and it _becomes_ the workload's
entrypoint. You declare the runtime image, resources, environment, and lifecycle
hooks right there in the decorator. We read that declaration **statically** —
your code is never executed on the host to build it — turn it into a microVM
image, and dispatch calls into the running guest:

```bash
mvmctl invoke greet --input name='ari'
```

The call returns the function's real, typed return value, not a stream of
console text. This is the path for packaged, repeatable workloads: declare it
once, build it, ship the signed result.

### The runtime pattern (imperative)

When you want to drive a sandbox directly, you use the `Sandbox` API,
synchronously or with async/await. This is the interactive, developer-time
surface — and it's a full **stateful code interpreter**, not just a command
runner. You execute code incrementally, variables and imports persist between
calls the way they do in a notebook, and each execution hands back rich,
structured results: stdout and stderr, the evaluated return value, and display
data such as charts or tables. The runtime pattern surfaces the same
interpreter-grade values the decorator's `invoke` returns — you're never reduced
to scraping a string out of a log.

On top of that the SDK exposes the things an interactive workload needs:
run a command, copy a file in or out, forward a port, set a timeout, manage the
filesystem. Typed helpers (a code-runner, a browser preset) make common cases a
single call.

### How you enter a workload

A workload is entered exactly one of two ways, and both ride the same vsock
channel — never SSH, never an open network port. A microVM exposes no listening
socket to attack; you reach it only over a local, trusted transport.

- A **function entrypoint.** A decorated workload names a function as its entry
  point. You invoke it by name, the call is dispatched into the guest over vsock,
  and you get the function's typed return value back. This is the production path.
- An **interactive shell.** In development, you can open a live shell into the
  guest — a terminal delivered over vsock — to explore and iterate. This exists
  only in dev mode. A sealed production workload has no shell to enter at all, by
  construction.

### One definition, one image

Both patterns — along with a plain `mvm.toml` and a hand-written Nix flake for
power users — lower to the _same_ internal workload definition and produce the
_same_ image. The flake is always available as an escape hatch and never a
requirement. The surfaces interconvert: the SDK can generate the `mvm.toml`
straight from a decorated app or a recorded session, so you can start in code and
drop down to a declarative file — or hand-edit the file and build from that —
without ever leaving the same definition.

### One IR, any language

Python and TypeScript are what we ship today, but they aren't the ceiling. Every
authoring surface lowers to the same internal workload definition, and the SDKs
themselves — the data types and the calls that drive a running sandbox — are
generated from a single schema rather than hand-written for each language. Adding
a new authoring language means generating another SDK against that one schema,
not rebuilding the system underneath it. The same machinery extends naturally to
Rust, Go, PHP, and beyond, so teams declare and drive workloads from the language
they already work in.

That's the language you _author_ in. The language your workload _runs_ in is
already wide open: because images are built from Nix and we ingest standard OCI
images, the code inside a microVM can be written in essentially anything — an
interpreted script, a compiled binary, a mixed-language service. The two choices
are independent. You might author in Python and run a Rust binary, or author in
TypeScript and run a Go service — whatever fits the job.

### Dependencies

Dependencies follow the same no-surprises rule: we read them from the manifest
your language already uses, resolve and build them reproducibly inside the
builder VM, and seal the result into an audited, read-only volume baked into the
image — so there's no install step at boot and no dependency fetching from a
running workload.

Each language brings its own convention, and we default to it. Python reads a
`requirements.txt`, TypeScript a `package-lock.json`, Go its modules, Rust its
Cargo lockfile — and as we add languages, each gets the native default its
ecosystem already expects. You declare dependencies the way you always have; we
handle the reproducible, sealed build underneath.

When a project doesn't fit a standard manifest, hooks are the escape hatch.
Hooks let you run your own steps at the key points in a workload's lifecycle:

- **`before_build`** — runs in the builder as the image is assembled. This is
  where custom dependency work goes: fetch a private package, compile a native
  library, run a bespoke installer.
- **`after_build`** — runs in the builder once the image is sealed: validate it,
  smoke-test that it boots, emit a build report. It observes the finished image
  but cannot alter it, so the seal always holds.
- **`before_start`** — runs at every boot, before the entrypoint takes over.
- **`after_start`** — a readiness check, polled until it passes before the
  workload is considered live and accepts calls.
- **`before_stop`** — runs inside the guest at shutdown, for best-effort cleanup.
  It is the last hook by design: the microVM is destroyed immediately after,
  leaving nothing behind — so there is no after-stop hook running on the host
  outside the sandbox.

Because the build hooks run inside the sealed builder, even a hand-rolled
dependency lands in the same audited, read-only volume. The default path is
convenient, and it never locks you out of the unusual case.

### Secrets

Secrets are declared, never embedded. You name a secret in the decorator and bind
it to the exact hosts it may reach, or set its value through the CLI so it never
lands in your source. The workload only ever sees an opaque placeholder in its
environment — the real value stays on the host and is substituted onto outbound
requests to the bound destination (described in the security model). Declaring a
secret is a one-liner; keeping it out of the guest is automatic.

### Addons and overlays

Common capabilities don't have to be rebuilt by hand. Addons are reusable
layers — each carrying its own files and lifecycle hooks — that you attach to a
workload and we compose into the image at build time, in attachment order. The
same composition mechanism produces a dev-rich image (extra tooling for fast
iteration) or a prod-slim image (only what the workload needs) from one
definition, so what you develop against and what you ship stay in lockstep
instead of drifting apart by hand.

## Working with OCI images

Not every workload starts from our SDK, so we meet artifacts where they already
live. We pull standard OCI images, verify them, and convert them into a microVM
root filesystem — recording the image's full provenance in the audit chain as we
go. You get the same isolation, immutability, and traceability whether the
workload came from a decorated function or an existing container image.

## Built for trust: auditability, attestation, and traceability

These three aren't security footnotes — they're core features, and much of the
system exists to deliver them.

- **Auditability.** Every meaningful action is recorded in a chain-signed,
  tamper-evident log: admission, launch, and failure of every workload; every
  host-service call; OCI provenance; and audit entries a workload emits about
  its own behavior. The chain detects any after-the-fact tampering, and you can
  verify it independently at any time.
- **Attestation.** We attest _what_ is running and bind those attestations to
  the workload's identity. Execution plans are signed; dependency volumes carry
  attestations, a software bill of materials, and vulnerability scans; OCI
  images carry verified provenance and signature verdicts. The result is a
  cryptographic record of exactly what was admitted to run.
- **Traceability.** Because nothing executes without a signed plan, every
  running workload traces back to precisely what was admitted — which image,
  which dependencies, under which policy, validated within which window. There
  are no untracked execution paths.

## What you can do with it

Beyond authoring, the project covers the full lifecycle of a sandbox with the
verbs people already expect — and a few they don't.

- **Build** a microVM image from an SDK definition, an `mvm.toml`, a Nix flake,
  or an OCI image.
- **Run and invoke** a workload as a headless microVM, then call into it: a
  one-shot function invocation for decorated workloads, or interactive code
  execution through the runtime `Sandbox`.
- **Speed: warm and cold.** We snapshot a booted microVM and restore from it,
  pause and resume live instances, keep warm pools ready, and fork a running
  sandbox to fan out many branches from one prepared state — so cold starts stay
  in the millisecond range and warm starts are faster still.
- **Resource limits and bounded execution.** Every workload declares its CPU,
  memory, and disk, and runs under those caps. Calls can carry a timeout and
  sessions a time-to-live, so a hung or runaway workload is reaped automatically
  rather than lingering or consuming the host without bound.
- **Templates and a catalog.** Capture a reusable image as a template, and
  browse, search, and fetch from a bundled image catalog to start from a
  known-good base. You can also publish your own signed images and templates to
  a registry and fetch them back on another host — every artifact stays
  content-addressed and signature-verified.
- **Networks.** Create named, isolated networks and attach workloads to them,
  governed by the egress policy described below.
- **Volumes and persistent workspaces.** Attach storage to a workload: the
  sealed, read-only dependency volumes; shares that mount read-only by default;
  and user-defined read-write volumes for working data and persistent workspaces
  that survive rebuilds. User volumes can only mount at dedicated, allow-listed
  locations like `/work` or `~/.cache` — they can never shadow or replace a
  Unix-native system directory such as `/bin` or `/usr/bin`. Volumes can be
  backed by local disk, in-memory tmpfs, or an S3-compatible object store, and
  are encrypted at rest.
- **Sessions.** Continue, resume, or run ephemeral sessions against a sandbox.
- **Portability.** Export a sandbox and import it elsewhere, so a prepared
  environment travels between hosts.
- **Dev mode.** A builder-VM shell is the _one_ interactive surface we offer —
  and it is strictly a development convenience, never a path into a production
  workload.
- **Host services.** A running workload can call back to a small set of
  host-mediated services — time, cost, and appending to its own audit trail —
  over the same trusted channel, without ever reaching the raw host.
- **Live logs and observability.** Stream a workload's output as it runs — follow
  its logs live, even for a sealed production microVM, because the console is
  captured write-only with no path back in. On top of that, workloads emit
  metering and chain-signed audit entries, and a single `watch` command streams
  every network request, file write, and admission event as it happens. `doctor`
  reports the live security posture and per-backend capabilities of the host
  you're on. Metering and traces are emitted as standard, open instrumentation,
  so they plug straight into the observability tools teams already run, such as
  Prometheus.
- **AI-agent integration.** The project speaks MCP, so an AI agent can drive
  sandboxes as tools — which is exactly the untrusted-code-execution problem the
  whole system is built to make safe. The agent story carries all the way to the
  prompt-injection and egress guardrails covered in the security model: adversarial
  inputs are tracked by provenance, and tainted content can't escalate into a
  privileged action on its own.

## Two modes: development and production

Development and production are deliberately separated, and the difference is
enforced, not advisory. They exist to serve opposite needs, so we don't let one
leak into the other.

**Development mode** optimizes for iteration. It offers the interactive
builder-VM shell, live code execution through the runtime `Sandbox`, faster
feedback, and the relaxed conveniences you want while you're still figuring out
what the workload should be. It runs on a development-tier substrate that doesn't
carry the full hardening of a production image.

**Production mode** optimizes for safety. A production workload is sealed: its
root filesystem is verity-protected, the interactive console and shell agent
aren't even built into it, it runs only from a signed and admitted execution
plan, and dependency, egress, and provenance gates are all enforced. There is no
interactive way in, by construction.

The boundary is one-directional: development conveniences never carry over into
a production workload, and a sealed production microVM can't be dropped back into
an interactive dev session. Choosing production isn't a flag that loosens under
pressure — it's a different, hardened build.

## Ephemeral by default

A sandbox is meant to be disposable. When a session ends we destroy the
microVM — its memory and its filesystem go with it — and because each workload
runs on its own hardware-isolated guest, the next session starts from the sealed
image with no residual data from the last. There is no shared writable state to
leak between runs unless you explicitly attach a persistent volume. This is the
property regulated and agent workloads care about most: prove that when the work
is done, nothing is left behind. We treat it as a guarantee we can witness, not
just a side effect of teardown.

## Staying current: patching and safe rollout

Because we rebuild instead of patching in place, keeping a workload current is
the same operation as building it. We run established CVE scanners that alert us
when a dependency carries a known vulnerability, and surface the fixed version
for each finding — so when a CVE or a zero-day lands, the response isn't a frantic
live patch on a running machine. We rebuild the image with the patched component,
re-seal and re-sign it, and roll the new, known-good image out. The same path
handles a routine dependency bump and an emergency exploit response — there's no
separate, riskier "hotfix" mode that bypasses the gates.

Rollout is health-gated and conservative. We build and boot the replacement,
wait for its readiness probe to pass, and only then cut over — and we never tear
down a healthy running sandbox on the strength of a build that hasn't proven
itself. If the rebuild fails, or the new image errors or fails its health check,
the existing sandbox keeps serving and the rollout is abandoned cleanly. The goal
is simple: a service that needs to stay up stays up, and "update" can never be the
thing that takes it down.

## The security model

This is where the "most secure sandbox" claim has to be earned. We make a set of
specific, independently verifiable security guarantees, and we back them with
tests and continuous-integration gates so the claims can't quietly drift from
reality. Grouped by the property they protect, here is what we guarantee.

### No interactive access to production

There is no way into a sealed production workload. The guest agent that serves
an interactive shell simply isn't present in a production build, and the host
refuses to attach a console to a sealed image. The only interactive surface in
the entire system is the dev-mode builder shell, and it can never reach a
production microVM.

### Immutable and verified at boot

We never patch a running workload — we rebuild and replace. And a tampered image
can't boot: the root filesystem is cryptographically sealed, and a single
flipped block makes the kernel refuse to start userspace rather than run
modified code.

### Witnessed non-persistence

When a session ends, the guest is destroyed and its filesystem is gone — and
because each workload runs on its own hardware-isolated microVM, the next session
provably inherits no residual data from the last. This cold-state guarantee is
the isolation property containers can't offer, and it's one we verify
independently rather than ask anyone to take on faith.

Persistence is opt-in and explicit. When you do want state to survive, you attach
a persistent shared volume, and it mounts at a dedicated directory of its own —
never over a core system path. The data you deliberately keep is cleanly
separated from the sealed, disposable OS image: what you chose to persist
persists, and nothing else carries over.

### Signed, audited execution

Every workload runs from a signed, typed execution plan. We synthesize the plan,
sign it with the host's key, verify it, enforce its validity window, and only
then launch — and every admission, launch, and failure is written to a
chain-signed audit log that detects tampering. Every published artifact bundle
is content-addressed, pinned to a signing key, and re-verified both when it's
fetched and again at admission time.

### We own the wire

No untrusted workload reaches the network unless policy explicitly admits it —
the default is deny-all egress. Because we own the transport layer, secrets
never enter the guest at all: a workload holds only an opaque placeholder, and
the host substitutes the real credential on an outbound request, bound to a
single destination and never crossing back into the guest's memory. The
host-side services a workload can call are each gated to a signed binding in its
execution plan and audited on every call. For encrypted traffic we terminate TLS
at the boundary with a name-constrained certificate authority scoped to the
workload's admitted hosts — so we can substitute credentials and inspect content
on HTTPS egress while holding no certificate for anything the workload was never
allowed to reach.

Owning the wire also lets us scrub sensitive data as it crosses the boundary.
We inspect traffic on both ingress and egress and strip secrets and personally
identifiable information — both the values you declare explicitly and ones we
predict by detection — before they can leave a workload or reach one. Undeclared
sensitive data doesn't get a free pass: if it looks like a credential or PII, it
is redacted and the event is audited.

### Resisting prompt injection

The sandbox is built to run AI-agent code, which means a workload's inputs may
themselves be adversarial — a prompt-injection attempt riding in on data the
agent was asked to process. We handle content by its provenance: anything from
an untrusted source is tainted, and that taint follows it through the system.
Detection flags likely injection and likely data exfiltration — sharing the same
scanner that strips secrets and PII on egress — but detection is only the
advisory layer. The guarantee is deterministic: tainted content cannot, by
itself, authorize a privileged action. Reaching a host service or releasing a
secret requires an explicit signed binding in the workload's plan, and
untrusted-provenance content can never grant itself that capability — so an
injection that slips past detection still can't escalate.

### Encryption and key lifecycle

Every piece of data we hold on the host is encrypted at rest — volumes,
snapshots, and stored secrets — and every key has a defined lifecycle. Keys are
layered so the master key can be rotated without re-encrypting the data beneath
it, key material is zeroized when it's no longer needed, and each rebuild binds
fresh keys. Snapshots are content-addressed and signed, and a restored snapshot
reseeds its random-number generator so two clones of the same saved state can't
reuse key material. We apply confidentiality where it earns its keep — data at
rest, and any channel that crosses an untrusted boundary; the host-local control
channels are cryptographically authenticated rather than encrypted, because the
host already sees their plaintext.

### Sealed, audited dependencies

Every application-dependency volume is hash-locked, scanned for known
vulnerabilities, enumerated in a software bill of materials, attestation-checked,
and bound to the workload's audit chain. Dependencies are built once, sealed,
and mounted read-only — never fetched or installed inside a live workload.

### Provenance and traceability

When a workload comes from an OCI image, we record its full provenance — the
registry, repository, the reference you asked for, the resolved digest, the layer
set, the trust policy, and the signature verdict — into the same chain-signed
audit log, so every running image traces back to exactly what was admitted.

### Confining the guest

A compromised workload can't escape its box. Each service runs under its own
unprivileged user with a restrictive system-call filter and no ability to gain
new privileges, and it can't reach the host filesystem beyond the shares
explicitly granted to it. No guest binary can elevate itself to root. Shared
directories mount read-only by default, and user-supplied read-write volumes are
confined to dedicated mountpoints — they can mount at a working location like
`/work` or `~/.cache`, but never over a Unix-native system path such as `/bin`
or `/usr/bin`, so storage can't shadow or replace the trusted root filesystem.
Its CPU, memory, and disk are capped and its runtime is time-bounded, so a
runaway workload can't exhaust the host or outstay its welcome.

### The runtime runs rootless

The workload runtime never runs as root. Your code executes as an unprivileged
user, there is no root account to log into and no root shell to reach, and there
is no setuid path back to root — a compromised workload lands on an unprivileged
identity with nowhere to climb. Root privilege exists only briefly during early
boot, inside a fixed setup step that runs no workload code and gives it up for
good before anything you control comes alive.

### A hardened supply chain

The inputs are guarded too. The parsers that handle untrusted host-guest traffic
are continuously fuzzed; the pre-built developer image is hash-verified before
use; and every dependency in our own build is audited on every change, with a
reproducible double-build to catch anything non-deterministic that could mask an
injection.

### What we don't defend against — and how we shrink it

We're honest about the boundary, and we work to make it as small as possible.

The hardest case is a malicious host. The host runs the hypervisor, which by
definition can read a running guest's memory — so a host that is fully
compromised at that level is beyond what software alone can stop. But host access
does not hand over tenant data. Everything at rest — every volume, snapshot, and
secret — is encrypted, and the keys live in the operating system's secure
keystore or in memory that's wiped after use, never in plaintext on disk. Someone
who gets onto the host, copies its filesystem, or walks off with a backup or a
snapshot sees ciphertext, not tenant data. The only way past that — keeping a
workload's live memory unreadable even to the hypervisor itself — is hardware
confidential computing, the ceiling this property is measured against.

Two narrower lines round out the boundary: we run one workload per guest rather
than trying to make a single guest safe for multiple tenants, and we don't claim
hardware-backed key attestation. Everything inside those lines, we defend.
