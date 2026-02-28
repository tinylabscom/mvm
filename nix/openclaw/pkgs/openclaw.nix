# Local OpenClaw gateway derivation.
#
# Builds only the Node.js MCP gateway from source — no tools bundle,
# no whisper/triton/torch.  Replaces the nix-openclaw overlay which
# pulled in ML dependencies that cannot build on aarch64-linux.

{ lib
, stdenv
, fetchFromGitHub
, nodejs_22
, pnpm_10
, fetchPnpmDeps
, pnpmConfigHook
, python3
, pkg-config
, vips
, perl
, makeWrapper
}:

stdenv.mkDerivation (finalAttrs: {
  pname = "openclaw-gateway";
  version = "2026.2.26";

  src = fetchFromGitHub {
    owner = "openclaw";
    repo = "openclaw";
    rev = "v${finalAttrs.version}";
    hash = "sha256-9kej1aK7j3/FU2X/bN983YqQClfnWfFPvByEkQKlQ4E=";
  };

  pnpmDeps = fetchPnpmDeps {
    inherit (finalAttrs) pname version src;
    hash = "sha256-Jcj0i/2Mh8Z5lp909Fkotw/isfLTIVMxtJgWwAtctEw=";
    fetcherVersion = 3;
  };

  nativeBuildInputs = [
    nodejs_22
    pnpm_10
    pnpmConfigHook
    python3       # node-gyp needs python for native modules
    pkg-config
    perl          # some native deps (e.g. openssl bindings) need perl
    makeWrapper
  ];

  buildInputs = [
    vips          # sharp (image processing) links against libvips
  ];

  # Fail the build if python3 or perl leak into the runtime closure.
  # These are only needed at build time (node-gyp, native module compilation).
  disallowedReferences = [ python3 perl ];

  env = {
    SHARP_IGNORE_GLOBAL_LIBVIPS = "1";
    npm_config_nodedir = nodejs_22;
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = "1";
    PUPPETEER_SKIP_DOWNLOAD = "1";
    ELECTRON_SKIP_BINARY_DOWNLOAD = "1";
    LLAMA_SKIP_DOWNLOAD = "1";
    OPENCLAW_A2UI_SKIP_MISSING = "1";
    CI = "true";
  };

  postPatch = ''
    # Remove packageManager field to avoid pnpm version conflicts
    # between the lockfile's pinned version and nixpkgs' pnpm_10.
    sed -i '/"packageManager"/d' package.json

    # Strip native packages that try to download binaries at build time
    # and are not needed for the gateway (local LLM, PAM auth, Canvas, PTY).
    sed -i '/node-llama-cpp/d; /@lydell\/node-pty/d; /authenticate-pam/d; /@napi-rs\/canvas/d; /@matrix-org/d' \
      pnpm-workspace.yaml

    # Make Canvas A2UI bundling non-fatal — it needs rolldown which may
    # not resolve in the sandbox. The gateway works without it.
    if [ -f scripts/bundle-a2ui.sh ]; then
      cat > scripts/bundle-a2ui.sh <<'STUB'
    #!/usr/bin/env bash
    set -euo pipefail
    echo "A2UI bundling skipped (Nix build)"
    mkdir -p ui/a2ui-dist
    echo "/* A2UI not bundled */" > ui/a2ui-dist/a2ui.bundle.js
    STUB
    fi
  '';

  buildPhase = ''
    runHook preBuild

    # Remove native packages that try to download binaries (no network in sandbox).
    # node-llama-cpp tries to fetch llama.cpp; not needed for the gateway.
    rm -rf node_modules/.pnpm/node-llama-cpp*/
    find node_modules -name 'node-llama-cpp' -type d -exec rm -rf {} + 2>/dev/null || true

    # Rebuild only the native modules we actually need.
    pnpm rebuild esbuild sharp protobufjs koffi 2>/dev/null || true

    # Build TypeScript source + bundle UI assets.
    pnpm run build

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out/lib/openclaw $out/bin

    # Copy runtime artifacts.
    cp -r dist node_modules package.json openclaw.mjs $out/lib/openclaw/

    # Copy workspace sub-packages if they produced runtime output.
    for dir in ui extensions packages; do
      [ -d "$dir" ] && cp -r "$dir" $out/lib/openclaw/
    done

    # Remove dangling symlinks left by node-llama-cpp removal.
    find $out/lib/openclaw/node_modules -xtype l -delete 2>/dev/null || true

    # ── Closure size reduction ─────────────────────────────────────
    # The full node_modules is ~1.3 GB. Strip everything that isn't
    # needed at runtime to shrink the NixOS rootfs closure.

    # 1. Strip build-time references to python3/perl from node_modules.
    #    node-gyp/koffi leave .py scripts with Nix store shebangs that
    #    pull python3 (110 MB) into the runtime closure.
    find $out/lib/openclaw/node_modules -name '*.py' -exec sed -i '1s|^#!.*/nix/store/[^ ]*/bin/python[0-9.]*|#!/usr/bin/env python3|' {} + 2>/dev/null || true
    find $out/lib/openclaw/node_modules -name '*.pl' -exec sed -i '1s|^#!.*/nix/store/[^ ]*/bin/perl|#!/usr/bin/env perl|' {} + 2>/dev/null || true

    # 2. Remove build artifacts (gyp, cmake, makefiles).
    find $out/lib/openclaw/node_modules \( \
      -name '*.gyp' -o -name '*.gypi' -o -name 'binding.gyp' -o \
      -name 'Makefile' -o -name 'CMakeLists.txt' \
    \) -delete 2>/dev/null || true

    # 3. Remove TypeScript source and declaration files — only .js is needed.
    find $out/lib/openclaw/node_modules -name '*.ts' ! -name '*.d.ts' -delete 2>/dev/null || true
    find $out/lib/openclaw/node_modules -name '*.d.ts' -delete 2>/dev/null || true
    find $out/lib/openclaw/node_modules -name '*.ts.map' -delete 2>/dev/null || true
    find $out/lib/openclaw/node_modules -name '*.js.map' -delete 2>/dev/null || true

    # 4. Remove documentation, examples, tests — not needed at runtime.
    find $out/lib/openclaw/node_modules -type d \( \
      -name 'test' -o -name 'tests' -o -name '__tests__' -o \
      -name 'example' -o -name 'examples' -o -name 'demo' -o \
      -name 'docs' -o -name 'doc' -o -name '.github' \
    \) -exec rm -rf {} + 2>/dev/null || true

    # 5. Remove documentation files from package roots.
    find $out/lib/openclaw/node_modules \( \
      -name 'README*' -o -name 'CHANGELOG*' -o -name 'HISTORY*' -o \
      -name 'CHANGES*' -o -name 'AUTHORS*' -o -name 'CONTRIBUTORS*' -o \
      -name '*.md' -o -name 'LICENSE*' -o -name 'LICENCE*' \
    \) ! -path '*/node_modules/.pnpm/*/.modules.yaml' -delete 2>/dev/null || true

    # 6. Remove Python/C source files left by native module builds.
    find $out/lib/openclaw/node_modules \( -name '*.py' -o -name '*.c' -o -name '*.h' -o -name '*.cc' -o -name '*.cpp' \) -delete 2>/dev/null || true

    # 7. Remove empty directories left by pruning.
    find $out/lib/openclaw/node_modules -type d -empty -delete 2>/dev/null || true

    patchShebangs $out/lib/openclaw/node_modules/.bin/

    # The CLI entry point is openclaw.mjs (ES module wrapper).
    makeWrapper ${nodejs_22}/bin/node $out/bin/openclaw \
      --add-flags "$out/lib/openclaw/openclaw.mjs" \
      --set NODE_PATH "$out/lib/openclaw/node_modules"

    runHook postInstall
  '';

  meta = {
    description = "OpenClaw MCP gateway for Claude AI";
    homepage = "https://github.com/openclaw/openclaw";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "openclaw";
  };
})
