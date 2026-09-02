# Plan 338 — QEMU-Wasm engine packaging research

This note records the upstream research and pinning decisions for Workstream 2
of Plan 338.

## Upstream projects

- Patched QEMU source: <https://github.com/ktock/qemu-wasm>
- Demo page: <https://ktock.github.io/qemu-wasm-demo/>
- Build sample repo: <https://github.com/ktock/qemu-wasm-sample>
- Container integration: <https://github.com/container2wasm/container2wasm>
- Patch series announcement (2025-04-07):
  <https://lists.gnu.org/archive/html/qemu-arm/2025-04/msg00153.html>

## How it works

qemu-wasm adds a TCG backend that lowers QEMU IR to WebAssembly.  Because Wasm
modules cannot jump into arbitrary generated code, each translation block is
compiled to a small Wasm instance.  To avoid browser instance-limit and
compilation-cost problems, the backend keeps a forked TCI interpreter as the
fast path and only compiles hot TBs (threshold ~1000 executions) to Wasm.

The browser host uses Emscripten pthreads/fibers (`-sPROXY_TO_PTHREAD=1`,
`--with-coroutine=fiber`), SharedArrayBuffer (`-pthread`), Asyncify, and a
32-bit Wasm memory model with a 64-bit guest-address workaround.

## Pinned revisions and dependencies

| Component | Version / revision | Source |
| --- | --- | --- |
| qemu-wasm source | `5a65998d47d78723115d1478a8a40f8d6d497f37` | GitHub tarball |
| QEMU version at that commit | `9.2.92` | `VERSION` file |
| Emscripten SDK | `3.1.50` | nixpkgs `c407032be28ca2236f45c49cfb2b8b3885294f7f` |
| zlib | `1.3.1` | upstream tarball |
| libffi | `v3.4.7` | GitHub tarball |
| pixman | `0.44.2` | freedesktop.gitlab tarball |
| glib | `2.84.0` | GNOME tarball |
| xterm-pty (JS glue) | `0.10.1` | npm tarball |

The Dockerfile that documents the upstream dependency versions is
`tests/docker/dockerfiles/emsdk-wasm32-cross.docker` in the qemu-wasm tree;
the README build command is in `ktock/qemu-wasm` `README.md`.

## Build command (upstream)

```bash
EXTRA_CFLAGS="-O3 -g -Wno-error=unused-command-line-argument -matomics -mbulk-memory -DNDEBUG -DG_DISABLE_ASSERT -D_GNU_SOURCE -sASYNCIFY=1 -pthread -sPROXY_TO_PTHREAD=1 -sFORCE_FILESYSTEM -sALLOW_TABLE_GROWTH -sTOTAL_MEMORY=2300MB -sWASM_BIGINT -sMALLOC=mimalloc --js-library=/build/node_modules/xterm-pty/emscripten-pty.js -sEXPORT_ES6=1 -sASYNCIFY_IMPORTS=ffi_call_js"
emconfigure /qemu/configure \
  --static --target-list=x86_64-softmmu --cpu=wasm32 --cross-prefix= \
  --without-default-features --enable-system --with-coroutine=fiber --enable-virtfs \
  --extra-cflags="$EXTRA_CFLAGS" --extra-cxxflags="$EXTRA_CFLAGS" \
  --extra-ldflags="-sEXPORTED_RUNTIME_METHODS=getTempRet0,setTempRet0,addFunction,removeFunction,TTY,FS"
emmake make -j$(nproc) qemu-system-x86_64
```

Outputs:

- `qemu-system-x86_64` (JS glue, extension-less)
- `qemu-system-x86_64.wasm`
- `qemu-system-x86_64.worker.js`

Guest images are packaged with Emscripten's `file_packager.py`:

```bash
/emsdk/upstream/emscripten/tools/file_packager.py qemu-system-x86_64.data \
  --preload pack > load.js
```

## Nix packaging approach

`nix/packages/qemu-wasm.nix` builds the engine inside the repository's existing
Nix builder boundary:

1. Imports the exact nixpkgs revision that ships Emscripten 3.1.50 via
   `builtins.fetchTarball` (tarball hash pinned).
2. Cross-compiles zlib, libffi, pixman, and glib into a shared prefix using
   the imported `emcc`/`emconfigure`/`emmake` toolchain.
3. Runs the upstream configure line against the patched QEMU source.
4. Installs the engine artifacts, required `pc-bios` files, a
   `qemu-wasm-file-packager` wrapper, and a `PINS` manifest.

The derivation is only exposed on Linux hosts and is only requested by the
WebLinux/browser feature path; default native workspace builds and packages do
not depend on it.

## Open risks / next steps

- The build is untested; it must be evaluated and fixed inside the Linux
  builder VM. Likely first failures will be Meson cross-compilation flags for
  glib/pixman and Emscripten cache paths in the Nix sandbox.
- `mimalloc` and `--js-library` paths must match the upstream expectation.
- Reproducibility: output `.wasm` may contain absolute build paths or
  timestamps; we need to measure and normalize if necessary.
- License/SBOM: QEMU is GPLv2; the runtime pack must ship corresponding-source
  notices for all vendored components.
- Emscripten's precompiled system library cache may write to `$HOME`; the
  derivation sets `HOME=$TMPDIR` and `EM_CACHE=$TMPDIR/.emscripten_cache`.
