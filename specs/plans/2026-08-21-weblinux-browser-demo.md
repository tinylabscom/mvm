# Browser-hosted WebLinux demo

Backing: preview
Validation: none

**Status:** DRAFT — scoping complete, engine build verified on the aarch64-linux HVF builder VM, Phase 1 engine integration prototyped; a minimal `/demo/weblinux` page boots the smoke pack in a Worker and reaches `DEMO-RESULT: READY` in headless Chromium
**Opened:** 2026-08-21
**Depends on:** Plan 338 — WebLinux browser backend, builder, workbench, and `mvmd` deployment client
**Related:** ADRs 006, 024, 049

## Outcome

A self-contained browser demo that demonstrates the WebLinux path end to end:

```text
edit source in browser
    -> build in a WebLinux builder VM worker
    -> run the built artifact in a WebLinux runtime worker
    -> inspect logs and stop the guest
    -> export the artifact for a native backend
```

The demo does **not** require an `mvmd` account, a native builder VM, or any host-side `mvmctl` command. It runs entirely in the browser against pinned, digest-addressed inputs.

## Definition of done

1. A user can open a static page, pick a fixture workload, and click **Build**.
2. The build runs inside a browser Worker using the Nix-built QEMU-Wasm engine and the portable builder protocol.
3. The resulting artifact can be booted with **Run** in a separate WebLinux runtime Worker.
4. **Logs** and **Stop** work against the running guest through the portable lifecycle protocol.
5. The artifact can be exported as a digest-addressed bundle and imported back.
6. The exported artifact boots on at least one native `mvm` backend without rebuilding.
7. All demo inputs (engine, runtime pack, fixture source) are pinned and SBOM-licensed.
8. The demo page and its workers pass the existing TypeScript/Rust format and lint gates.

## How we know the builder VM is ready

Plan 338 added `nix/packages/qemu-wasm.nix` and exposed `.#qemu-wasm-engine` on Linux. The builder VM is ready for the demo when the following command succeeds on it:

```bash
nix build .#qemu-wasm-engine
ls result/libexec/qemu-wasm/qemu-system-x86_64.js \
   result/libexec/qemu-wasm/qemu-system-x86_64.wasm \
   result/libexec/qemu-wasm/qemu-system-x86_64.worker.js \
   result/bin/qemu-wasm-file-packager
```

Until that succeeds, the demo cannot proceed past scaffolding, because the browser has no other source for the engine artifacts. We will record the measured output hashes and use them as the demo's pinned engine reference.

### Recorded engine artifact hashes

Measured from the first successful `nix build .#qemu-wasm-engine` run inside
the aarch64-linux HVF builder VM (build path `libexec/qemu-wasm/`, BIOS under
`share/qemu-wasm/bios/`):

```text
016b2e62cb11ac05388b09c27aced4d7c4075c939ec59ba5df150b08e19f473f  qemu-system-x86_64.js
c444cd2c9115c87bcccb41a322b6ceb297fce29b4271145b28ac47a01e3deb9d  qemu-system-x86_64.wasm
e630b90bccea1eb3447357e56ddf520907200a61733b67624715210ba0ba995f  qemu-system-x86_64.worker.js
f1d4f396011197eb989029659cde250751cc711c336b8fbbe6f77cfe0dc5dcd8  bios/bios-256k.bin
651513519f9e0d5b99d3b051a8f5c68db69e987339b59a441d371068c34c146b  bios/vgabios-stdvga.bin
cdf057a71b07e3b52b19cbe210bdefa59250d01a9810b960f7fe1f98eed95a27  bios/kvmvapic.bin
9c49e255340c78fc12e54ed043462bca02fb7fca29b7cfab62ff88a5344b6950  bios/linuxboot_dma.bin
```

## Demo flow

### 1. Fixture workspace

- A small, editable fixture (e.g., `examples/wasm-hello` or `examples/sleeper`) loaded into an in-browser editor.
- Source is stored in the browser's OPFS workspace so the demo survives a reload.

### 2. Build

- User clicks **Build**.
- The page posts a `BuildRequest` to the builder Worker.
- The Worker resolves the pinned QEMU-Wasm engine and fixture source, runs the build, and returns a `BuilderArtifacts` bundle.
- The bundle is stored in the browser CAS.

### 3. Run

- User clicks **Run**.
- The page posts a `BackendRequest::Start` with the artifact set to the runtime Worker.
- The runtime Worker boots the artifact under the same QEMU-Wasm engine.
- The guest console is streamed back to the page.

### 4. Observe and stop

- **Logs** polls `BackendRequest::Logs`.
- **Stop** sends `BackendRequest::Stop` and waits for the Worker to tear down.

### 5. Export / import

- **Export** serializes the artifact set (manifest digest + objects) to a tarball the user can download.
- **Import** accepts a previously exported tarball and rehydrates it into the browser CAS.
- The same exported artifact boots with `mvmctl machine run --hypervisor wasm` on a supported host.

## Work breakdown

### Phase 0 — Demo scaffolding (ready now)

- [x] Add a new `public/demo/weblinux/` route or standalone page.
  Implemented as `public/src/pages/demo/weblinux.astro` (served with COOP/COEP
  headers) plus the static source under `web/weblinux-demo/`. A `build.sh`
  stages the Nix-built smoke pack and a `serve.py` serves it with the required
  cross-origin-isolation headers.
- [ ] OPFS workspace helper for fixture source and CAS objects.
- [ ] TypeScript types generated from the Rust `BackendRequest` / `BackendResponse` / `BuildRequest` / `BuildProgress` schemas.
- [x] A minimal editor component and a terminal/log pane, plus terminal
  polish (ANSI color rendering, bottom-docked input, command history) and a
  CLI preview that advertises the intended
  `mvmctl machine run --hypervisor web-linux ...` surface.

### Phase 1 — Engine integration (builder VM verified)

- [x] Run `nix build .#qemu-wasm-engine` on the Linux builder VM.
- [x] Record and pin the resulting `.js`, `.wasm`, and pc-bios file hashes.
- [ ] Add a fetch/cache helper that downloads the engine into the browser and verifies hashes.
- [x] Instantiate QEMU-Wasm in a Worker with the correct runtime settings.
  `web/weblinux-demo/worker.js` loads the engine, the Emscripten preload pack,
  and `xterm-pty`, then boots the smoke guest with the same args used by the
  upstream sample. Headless Chromium reaches `DEMO-RESULT: READY` in ~7 s.
  > Known limitation: host-bound SLIRP traffic (ping/TCP/UDP to the QEMU
  > user-mode gateway) triggers a WebSocket-forwarding divide-by-zero in the
  > Emscripten build, so automated smoke tests exercise loopback networking
  > (`ping 127.0.0.1`) and the `mvm.allow_host` /etc/hosts entry instead.

### Phase 2 — Builder Worker

- [ ] Implement `WebLinuxBuilderVm` as a browser Worker that accepts `BuildRequest` and emits `BuildProgress` / `BuilderArtifacts`.
- [ ] Resolve fixture source from OPFS, stage a runtime pack, and run the Nix-less build path inside the Worker.
- [ ] Store output objects in the browser CAS and produce a signed manifest.

### Phase 3 — Runtime Worker

- [ ] Implement `WebLinuxBackend` as a browser Worker that accepts `BackendRequest` and emits `BackendResponse`.
- [ ] Boot the artifact set produced by Phase 2.
- [ ] Wire console output to the page and handle `Stop` cleanly.

### Phase 4 — Export/import and native cross-boot

- [ ] Serialize artifact sets to a portable tarball.
- [ ] Deserialize tarballs back into the browser CAS.
- [ ] Demonstrate the same artifact booting with `mvmctl machine run --hypervisor wasm` on a host.

### Phase 5 — Hardening and gates

- [ ] Add Playwright or Vitest browser tests for the demo flow.
- [ ] Ensure the demo carries no production-authoritative claims.
- [ ] Run `cargo xtask check-stubs`, `check-no-string-backend-dispatch`, and `check-declared-backing` after any doc changes.

## Risks and open questions

- **Builder VM availability.** Resolved — the aarch64-linux HVF builder VM successfully evaluated and built `nix/packages/qemu-wasm.nix`. Remaining risk is reproducibility across rebuilds and hosts.
- **Emscripten memory limits.** Browser Workers have hard heap and thread limits; the engine may need a stripped-down firmware set or a smaller default guest memory for the demo.
- **Cross-origin isolation.** SharedArrayBuffer and pthreads require COOP/COEP headers on the demo host.
- **Artifact portability.** The browser-built artifact must use the same digest scheme and manifest format as native builders, or export/import becomes a conversion problem.
- **No native fallback in the browser.** If the engine fails to load, the demo fails closed; we should surface a clear error rather than silently fall back.

## Success criteria for the first demo milestone

A single screen recording or CI job that shows:

1. Fixture source edited in the browser.
2. Build completes and produces an artifact set.
3. Run boots the artifact and produces guest output in the log pane.
4. Stop terminates the guest.
5. Export produces a file that `mvmctl machine run --hypervisor wasm` can consume.
