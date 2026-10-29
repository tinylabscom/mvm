---
kind: design
issue: https://github.com/tinylabscom/mvm/issues/4577
status: accepted
---

# Libkrun tier in the single signed release archive, and backend selection at install

Backing: preview
Validation: none — this is a proposed design; no code implements it and no test exercises it.

Design attachment for #4577 (ship the libkrun tier, macOS 13-25) and #4578
(backend selection at install). The issues own scope and status. This
document records the decisions and the facts they rest on.

## Decisions

1. **No custom kernel.** The tier uses upstream libkrun and upstream
   libkrunfw, with libkrunfw's own bundled kernel. Both are pinned by
   release version and by the SHA-256 of the source tarball, built in the
   release workflow, and shipped in the same signed archive. The
   `mvm-images` kernel is not embedded into libkrunfw. This resolves the
   first work item of #4577: the source of truth for the kernel is the
   pinned upstream libkrunfw. It is recorded in the ADR that owns the
   backend matrix when this lands.
2. **macOS 26+ is unchanged.** HVF stays the auto-detect default and never
   loads, stages or verifies a libkrun file.
3. **Install detects the tier** (#4578): `install.sh` stages what the host
   needs from the one archive, asks nothing, and prints what it chose.

Intel macOS stays unsupported; libkrun on macOS is Apple Silicon only.

## What the code actually links

- `crates/deps/libkrun-sys/build.rs` probes for `libkrun.h` under
  `/opt/homebrew`, `/usr/local` and `/usr` and emits
  `cargo:rustc-link-lib=krun`, adding the sibling `lib` directory as a
  search path. The only override is `MVM_LIBKRUN_HEADER`, which names the
  header, not a library directory.
- `crates/deps/libkrun-sys/src/sys.rs` also declares
  `#[link(name = "krunfw")]` and calls `krunfw_get_kernel`. So
  `mvm-libkrun-supervisor` has **two direct dylib dependencies**,
  `libkrun.dylib` and `libkrunfw.5.dylib`. libkrun's own load of libkrunfw
  is a second, indirect reference to the same library.
- The supervisor binary has `required-features = ["libkrun-sys"]`
  (`crates/mvm-hostd/Cargo.toml`) and is the `RequiresLibkrun` row of
  `PER_VM_HOST_BINARIES` (`crates/mvm-cli/src/host_binaries/manifest.rs`).
- No Rust code calls `krun_set_gpu_options`; it only appears in the
  generated bindings. GPU work goes through the `mvm-gpu*` remoting shims.
  So **libkrun is built without its GPU feature, which removes virglrenderer,
  libepoxy and MoltenVK from the tier.** Stage 1 checks this with `otool -L`
  on the built dylib; if the check fails, the tier is not shipped until the
  dependency is accounted for, rather than quietly adding the GPU stack.

## Archive contents (macOS aarch64 archive only)

Beside `mvmctl`, in the existing `mvmctl-aarch64-apple-darwin.tar.gz`:

| Path | What | Notes |
| --- | --- | --- |
| `mvm-libkrun-supervisor` | per-VM supervisor | sits where `mvm-hvf-supervisor` sits; adjacent-to-exe resolver unchanged |
| `lib/libkrun.<n>.dylib` | libkrun | install name `@rpath/libkrun.<n>.dylib` |
| `lib/libkrunfw.5.dylib` | libkrunfw with the bundled kernel | install name `@rpath/libkrunfw.5.dylib` |
| `licenses/libkrun/`, `licenses/libkrunfw/` | licence texts | see below |
| `SOURCE_OFFER-libkrun.txt` | pinned source offer | see below |

The tier is a **single optional component set**, named in the component
table (below), not a second archive. It is in the signed archive on every
install, but `install.sh` and `mvmctl backend add` decide whether it is
placed in the active install on a given host.

### Relocation

- Supervisor: `LC_RPATH` of `@executable_path/lib`. Produced at link time
  with `-C link-arg=-Wl,-rpath,@executable_path/lib`, not patched after.
- libkrun: install name `@rpath/libkrun.<n>.dylib`; its reference to libkrunfw
  rewritten to `@rpath/libkrunfw.5.dylib` with `install_name_tool -change`;
  its own rpath `@loader_path`.
- libkrunfw: install name rewritten to `@rpath/libkrunfw.5.dylib`.
- This removes the need for `DYLD_LIBRARY_PATH`, which the dynamic loader
  strips for protected parents. No wrapper script, and `libkrun-sys` needs no
  change to find the library at run time (it never dlopens by bare name; the
  linker records the install name).
- Link-time: the release job builds the supervisor with `MVM_LIBKRUN_HEADER`
  pointing at the pinned source tree's header and a `RUSTFLAGS` link-search
  path at the staged `lib/`, so the Homebrew prefix is never probed. The probe
  list in `build.rs` stays for contributors.
- One deployment target for every Mach-O in the tier:
  `MACOSX_DEPLOYMENT_TARGET=13.0`, applied to libkrun, libkrunfw and the
  supervisor. Stage 1 checks with `vtool -show-build` / `otool -l` that no
  file in the tier has a higher `minos`. A file that cannot meet 13.0 is a
  finding that changes the tier's floor, recorded here, not worked around.
- **Post-build gate** (script run in the release job, also run by
  `verify_macos_package.py` against the final bytes): for every Mach-O in the
  archive, fail on any `otool -L` or `LC_RPATH` entry that begins with
  `/opt/homebrew`, `/usr/local`, `/Users`, or a runner temp path, and fail on
  any `@rpath` dependency that no `LC_RPATH` entry in that file or its loader
  resolves to a file in the archive.

### Build of the pinned libraries

- A new `scripts/release/` step fetches `libkrun-<ver>.tar.gz` and
  `libkrunfw-<ver>.tar.gz` from their upstream release URLs, checks both
  SHA-256 digests against values committed in one file (the pin), and
  refuses on mismatch. No floating tap, no `brew`.
- libkrunfw's kernel config and patch set come from that tarball unmodified.
  Unverified, to be settled in Stage 1: upstream builds the kernel image on
  Linux and compiles the wrapper on macOS. If the macOS build needs a
  Linux-generated `kernel.c`, the release workflow produces it in a Linux job
  from the same pinned tarball and passes it as a job artifact, still without
  any patch of ours. If upstream offers no such path at the pinned version,
  the tier does not ship at that version; it does not fall back to a Homebrew
  bottle.
- Dependencies of the build (Rust, `make`, a C toolchain) come from the
  runner; none of them end up as runtime dependencies, which the gate checks.
- Reproducibility: the pin file plus the toolchain versions are the inputs.
  Bit-reproducibility of the dylibs is not claimed.

## Signing, notarization, claim 20

Current macOS flow, from `release.yml` and `scripts/release/sign_macos.py`:
ad-hoc producer signing of every Mach-O (`--producer-adhoc`), then on tags
Developer ID signing and notarization of the staged payload, then
`verify_macos_package.py` inspects the final bytes, then the tarball and the
combined `checksums-sha256.txt` are cosign-signed keyless under the release
workflow identity.

Changes:

- `ROLES` in `sign_macos.py` already lists `mvm-libkrun-supervisor` with
  `com.apple.security.hypervisor`; it needs no new entry. The supervisor
  becomes a required role on the macOS archive, and the inventory check
  (`--require-cli-inventory`) must list it, so a missing supervisor fails the
  package rather than the user's launch.
- The two dylibs are signed by the existing "dylibs first, no `--deep`, no
  entitlement on a dylib" path. They carry the same Developer ID team as the
  supervisor, so library validation under the hardened runtime accepts them.
  Do **not** add `com.apple.security.cs.disable-library-validation` to the
  supervisor to make this work; if validation fails the signing order or the
  team is wrong. The hypervisor entitlement stays the only one on the
  supervisor.
- Notarization covers the whole staged directory exactly as today.
- Claim 20 is not changed in its rule, only in the set it covers. Every new
  file lives inside the already-signed tarball, so the tarball signature and
  the manifest entry authenticate them. Nothing is fetched outside the
  signature path. No verifier, flag or skip hatch is touched;
  `MVM_SKIP_COSIGN_VERIFY` and `MVM_SKIP_HASH_VERIFY` gain no new meaning.
- `verify-release-assets.sh` and `verify_macos_package.py` gain: presence and
  Mach-O type of the three files, the entitlement of the supervisor, the
  post-build gate above, the licence and source-offer files, and a check that
  the pin file's digests appear in the source offer.
- `mvmctl backend add` (below) never downloads a bare dylib. Anything it adds
  after install comes from a signed archive, verified by the same in-process
  verifier at the same tag, before a byte is placed. An optional component is
  therefore a *path set inside the signed archive*, not a separate signed
  object, which keeps one trust root. Whether `add` re-downloads the whole
  archive or reuses the cached one from install is the one open design point;
  the cached copy is acceptable only if install keeps it and re-verifies its
  digest against the manifest before use. The ~41 MB figure in #4577 is the
  right order of magnitude for the cost of re-download.

## Licence and source offer

- libkrun is Apache-2.0. libkrunfw is LGPL-2.1-only and embeds a Linux
  kernel, which is GPL-2.0-only. We distribute the dylib unmodified in the
  sense that matters: the pinned upstream source, built with upstream's
  config.
- The archive carries the licence texts for libkrun, libkrunfw and the kernel
  (the kernel's `COPYING` from the pinned tarball) under `licenses/`.
- `SOURCE_OFFER-libkrun.txt` names: the libkrunfw and libkrun versions and
  tarball SHA-256 digests; the upstream URLs; the kernel version libkrunfw
  embeds and the kernel config file's path inside the tarball; the exact mvm
  commit (as `THIRD_PARTY_NOTICES.txt` already does for `mvm-macho-sign`);
  and a statement that the corresponding source is available from the release
  page, which the release job satisfies by also uploading the two source
  tarballs as release assets. Offering a URL to someone else's repository
  alone is not relied on for the GPL part.
- LGPL relinking: the supervisor links libkrunfw dynamically and the dylib is
  replaceable on disk, which satisfies the relinking requirement. The notice
  says so and says that replacing it falls outside the notarized state.
- `THIRD_PARTY_NOTICES.txt` is extended, not replaced, and the existing MPL
  text stays. Counsel review of the notice text is a Stage 5 exit item; the
  design does not assert legal sufficiency.

## Backend selection at install (#4578)

### One component table

Grow `PER_VM_HOST_BINARIES` into a per-backend table keyed by backend:

- fields: backend id, host OS and arch, minimum OS, the files it needs
  (path inside the archive, kind, install location), licence notice files,
  whether it is `Default` for a tier;
- its backend id is the same `BackendKind` the `VmBackend`/`VmmDriver`
  implementations use, and a unit test iterates every `BackendKind` and
  fails if one has no table row or a row names no implementation. That test
  is what makes "adding a backend cannot leave one out" true;
- `install.sh`, `mvmctl backend list|add|remove`, `mvmctl doctor` and
  `xtask check-per-vm-host-binaries-sync` read it. `install.sh` cannot link
  Rust, so the table is also emitted as a small generated text file shipped
  in the archive (`components.tsv`), and a sync check fails if the generated
  file differs from the table. The shell reads the file; it does not
  duplicate the data.
- the existing `PerVmScope::RequiresLibkrun` and the `EXCLUDED_PAYLOADS`
  constant in `install.sh` are replaced by table rows. Today's installer
  deliberately leaves the libkrun supervisor out; that exclusion becomes
  "not selected for this tier" instead of "never".

### Detection

Reuse `auto_detect_default_for`; `install.sh` asks the just-extracted
`mvmctl` (`mvmctl backend detect --plain`), so the shell does not reimplement
the macOS-version logic. Caveat: today `auto_detect_default_for` answers HVF
on all Apple Silicon macOS and reports the macOS 26 floor as unavailable.
For install purposes the detector must answer libkrun on macOS 13-25 Apple
Silicon, which means the *install-time* detection takes the host version into
account while the *runtime* auto-detect stays as it is (explicit libkrun, no
fallback, per the builder-selection rules). The two are different functions
and the doc for the command says so.

Installer output on macOS 13-25 names the choice and the way to add others,
e.g. `Installed backend: libkrun (macOS 15, Apple Silicon). Add another with
mvmctl backend add <name>.` macOS 26+ prints HVF and stages no libkrun file.

### Options and prompt

- `--backend <name>` and `MVM_INSTALL_BACKEND=<name>` for scripted installs.
  An unknown or unsupported name for the host is a refusal that lists the
  valid ones; it never degrades to auto.
- Question-free by default. Interactive picker only when stdin or `/dev/tty`
  is a terminal **and** the host has two or more viable backends in the table.
  It reads `/dev/tty` (so `curl | sh` works when a terminal exists), prints the
  list with the auto choice marked, accepts Enter for it, and times out to it
  after a fixed interval. No terminal means auto, silently apart from the
  printed line. No viable backend means the install fails with the supported
  matrix, not a partial install.

### CLI

- `mvmctl backend list`: every backend in the table, with host support,
  installed or not, which is the default, and the reason for any "not
  available" (OS floor, missing component).
- `mvmctl backend add <name>`: verify and place the component set; refuse for
  an unsupported host; idempotent.
- `mvmctl backend remove <name>`: removes the files the table lists for it and
  its `.mvm-lib` markers; leaves state directories, caches, audit logs, and
  any VM created with it (and says so, naming the paths). Refuses to remove
  the current default unless another is installed.
- `mvmctl doctor` gains a `backend components` line per installed backend:
  present, signature state, minimum-OS fit.
- CLI reference (`public/src/content/docs/reference/cli-commands.md`) and BDD
  scenarios for `list`, `add` unsupported, `add` idempotent, `remove` leaving
  state.

## Surfaces that change when it ships

- **Supervisor-not-found message.** `missing_hint` in
  `crates/mvm-vmm/src/host/aux_bin.rs` currently tells the user to
  `brew install slp/krun/libkrun` and rebuild. When the tier ships it says:
  on a release install, run `mvmctl backend add libkrun`; on a source build,
  run the payload recipe. It distinguishes the two by the same
  "official release vs source checkout" signal the rest of the CLI uses, and
  a release install never prints a Homebrew instruction. The existing unit
  tests at the end of that file are updated with it.
- **Platform support.** `public/src/content/docs/reference/platform-support.md`
  row "macOS 13-25 Apple Silicon" moves from "Source build only" to
  "Supported" only after the witness below exists. Before that, at most
  "Preview". `public/src/content/docs/install/macos.md` currently states
  Apple Silicon on macOS 26 or newer and "no libkrun"; it gains a section for
  13-25 and the `--backend` option. The WSL2 row's "standard releases do not
  ship libkrun" is rechecked, since this tier is macOS only.
- `release.yml` comment "the optional libkrun integration is not part of
  standard release artifacts", `REQUIRED_HOSTBINS`, the build step, the
  staging step, the packaging grep, and `install.sh`'s `EXCLUDED_PAYLOADS`
  and entitlement helpers (`entitlement_profile`, `entitlement_required`,
  `required_entitlement_key`, which today only know the HVF supervisor).
- ADR-001's backend tier matrix and the libkrun-related claim rows if any
  witness text names the tier as source-only; ADR-030 gets the kernel
  decision. `check-claim-catalog` is rerun.

## Release workflow changes

All in the `aarch64-apple-darwin` leg unless stated.

1. New step before "Build per-VM host binaries": fetch, verify and build the
   pinned libkrunfw and libkrun with `MACOSX_DEPLOYMENT_TARGET=13.0` and no
   GPU; upload the two source tarballs as release assets.
2. Build `mvm-libkrun-supervisor` with `--features libkrun-sys`, `--release`
   (panic=unwind, same reasoning as the existing per-VM binaries), against the
   staged libraries.
3. Relocate, then run the post-build gate.
4. Staging: add the supervisor, `lib/`, `licenses/`, the source offer and
   `components.tsv`; fail closed on any missing file, like `REQUIRED_HOSTBINS`.
5. Signing and notarization steps are unchanged in shape; the payload just
   contains more Mach-O files.
6. `verify_macos_package.py` / `verify-release-assets.sh` extended as above.
7. Release smoke (`rust-registry-smoke`, installer compat) gets a macOS lane
   that installs the archive, asserts `otool -L` is clean, and asserts the
   supervisor starts far enough to print its probe answer
   (`exit_with_probe_answer_if_requested` is already in the supervisor main).

## The macOS 13-25 witness, honestly

The claim to witness is: a downloaded, notarized `mvmctl` on a real macOS
13-25 Apple Silicon host, installed with no Homebrew libkrun, boots a guest
with `--hypervisor libkrun` and reaches the guest agent.

**We have no macOS 13-25 runner.** The workflows use `macos-latest` (the
macOS 26 line for this project's purposes) and one `macos-14` job in
`rust-registry-smoke.yml`, which only exercises the registry client. We cannot
assume a GitHub-hosted `macos-14` or `macos-15` image provides nested
virtualization: hosted Apple Silicon runners are themselves virtual machines,
and Hypervisor.framework from inside one is not available on the images
currently in use. This is **unverified**, and Stage 3 starts by running a
probe job that tries `hv_vm_create` and records the result. If it fails, no
hosted runner can boot a libkrun guest.

What can be witnessed without a runner, and what cannot:

| Witness | Runner needed | Shows |
| --- | --- | --- |
| Post-build gate: no host paths, one deployment target, `minos` <= 13.0 | any macOS runner | relocation and floor of the bytes, not behaviour |
| Package inspection and signature/entitlement/notarization verification | any macOS runner | claim 20 coverage of the new files |
| Install on a clean runner and run the supervisor's probe (`exit_with_probe_answer_if_requested`) | any macOS runner | the dylibs resolve through `@rpath` from the final layout |
| Launch `--hypervisor libkrun` end to end on 13-25 | a real 13-25 Apple Silicon Mac | the actual claim |

The last row is a **maintainer-run witness** until a self-hosted or
dedicated 13-25 machine exists: a documented manual procedure and a recorded
log kept as committed evidence under `specs/evidence/`, repeated per
release. The platform-support row must say "Preview, witnessed manually on
macOS <version>" and not "Supported" while that is the only evidence. The
other three rows are the CI lane the issue asks for ("a CI lane that
exercises the packaged supervisor") and are honest about what they do not
show. Where the host must be a macOS version below the runner's, the
deployment-target check is the only automated proxy and is called that.

Support-matrix testing (#4578): the table drives a generated matrix of
(backend, host tier, install path) cells. Each cell is labelled *witnessed
by CI*, *witnessed manually (date, host)*, or *assumed*; `mvmctl backend list`
and the platform-support page may only say "Supported" for the first two, and
a test fails if the page claims a cell the matrix labels *assumed*.

## Risks

- **Floor not reachable.** libkrunfw or libkrun at the pinned version may need
  a macOS newer than 13. The tier's real floor is then higher and the
  platform-support row says so; we do not patch upstream to lower it.
- **Upstream macOS build path for libkrunfw** needs a Linux-generated kernel
  source; if it changes shape between versions, bumping the pin is a
  work item, not a one-line edit.
- **Library validation / notarization** surprises with nested dylibs; mitigated
  by signing dylibs first with the same identity and verifying the final bytes
  before upload, as the HVF flow already does.
- **Archive growth** (a libkrunfw dylib carries a kernel, tens of MB) taxes
  every macOS install, including 26+ users who never use it. Two options:
  accept the cost in exchange for one download, or let `install.sh` skip
  *extracting* the files on macOS 26+ (they stay in the archive). The latter
  is chosen; it saves disk, not bandwidth. The release size check
  (`xtask` size gate) needs a new ceiling and must be told why.
- **Security surface.** libkrun's TSI network mode must stay unused: the tier
  runs under the existing vsock-only, NIC-less rule, and
  `check-single-network-path` stays green. Shipping the dylib does not
  change that, but a reviewer should confirm the supervisor's configuration
  never enables TSI sockets for workloads.
- **Entitlement drift:** the supervisor needs only the hypervisor entitlement;
  adding others to make something load is a defect.
- **Licence:** source-offer wording and the GPL-covered kernel inside a
  notarized binary; needs review before the first release containing it.
- **Detection mismatch:** install-time choice and runtime auto-detect differ
  on macOS 13-25 (above). A user who installs libkrun and runs without
  `--hypervisor libkrun` must get a message that names the flag, not a "HVF
  unavailable" dead end. Whether libkrun should become the runtime default on
  13-25 is a separate decision and is out of scope here.
- **No runner:** the headline claim has manual evidence only.

## Test list

Unit and xtask:

- component table covers every `BackendKind`; generated `components.tsv`
  equals the table; `check-per-vm-host-binaries-sync` covers the new rows and
  the workflow's required-file list.
- `missing_hint` for the supervisor on release vs source (both strings; no
  `brew` on release).
- install-time detection: table of (OS, arch, version) to backend, including
  macOS 13, 25, 26, Intel, Linux with and without KVM.
- the pin file: both digests present, format valid, and the source offer
  renders them.

Scripts (`scripts/release`, Python tests like the existing
`test_sign_macos.py`, `test_verify_macos_package.py`):

- gate rejects a Mach-O with a Homebrew path, a `/usr/local` rpath, an
  unresolved `@rpath`, a `minos` above 13.0; accepts a clean fixture.
- package verifier rejects: missing supervisor, missing dylib, supervisor with
  extra entitlement, unsigned dylib, missing licence or source offer.
- `sign_macos.py` signs the dylibs without entitlements and the supervisor
  with only the hypervisor key.

Installer (`tests/install_sh.rs`):

- macOS 13-25 stages libkrun files, macOS 26+ stages none; `--backend`
  wrong for the host refuses and lists valid names; no terminal means no
  prompt; `/dev/tty` present and two viable backends means the picker; the
  printed line names the choice; an install over an older release removes
  the old files the table owned.
- signature refusal paths are untouched: the existing tests for unsigned
  archives and for `MVM_SKIP_HASH_VERIFY` not waiving the signature must
  still pass unchanged, and one new case shows a tampered `lib/` entry in the
  tarball is refused by the tarball digest.

CLI and BDD: `backend list|add|remove` scenarios listed above; `doctor` line.

CI lanes: macOS post-build gate; macOS install-and-probe; the hosted-runner
`hv_vm_create` probe (to settle runner capability); the manual 13-25 witness
procedure with its evidence file.

## Staged implementation

1. **Feasibility build.** Pin file, fetch-and-build script for libkrunfw and
   libkrun on a macOS runner, deployment target 13.0, no GPU; record `otool`
   and `minos` of the outputs and the Linux-kernel-source question. Output is
   a decision recorded here: ship, ship with a higher floor, or do not ship.
2. **Packaging and gate.** Relocation, the post-build gate, supervisor build
   against the staged libraries, staging in `release.yml`, signing and
   package-verifier extensions, licences and source offer, size ceiling.
3. **Witness plumbing.** Runner probe job, install-and-probe lane, manual 13-25
   procedure and evidence format. Platform-support row set to Preview.
4. **Component table.** Grow `PER_VM_HOST_BINARIES`, generated
   `components.tsv`, sync checks, `doctor` line, the not-found message.
5. **Installer.** Detection, `--backend`, picker, staging from the table,
   installer tests. Legal review of the notice text.
6. **`mvmctl backend` verbs.** `list`, `add`, `remove`, CLI reference, BDD.
7. **Promotion.** After a real 13-25 run is recorded, move the platform-support
   row and the install docs, update the ADR rows, and rerun the claim and
   spec gates.

Stages 1 to 3 satisfy #4577; stages 4 to 6 are #4578; stage 7 closes both.
