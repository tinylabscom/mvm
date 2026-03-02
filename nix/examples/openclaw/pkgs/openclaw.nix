# OpenClaw gateway derivation — wraps the pre-installed npm package.
#
# The pre-build.sh hook (run before nix build) installs OpenClaw via
# the official installer script (https://docs.openclaw.ai/install) to
# /opt/openclaw.  This derivation copies those files, creates a Node.js
# wrapper, and strips build-time artifacts to shrink the rootfs closure.
#
# Requires --impure (added automatically by dev_build when pre-build.sh exists).

{ lib
, stdenv
, nodejs_22
, makeWrapper
}:

let
  # Path where pre-build.sh installed the npm package.
  openclawPath = builtins.path {
    path = /opt/openclaw;
    name = "openclaw-source";
  };
in

stdenv.mkDerivation {
  pname = "openclaw-gateway";
  version = "2026.2.26";

  src = openclawPath;

  nativeBuildInputs = [ nodejs_22 makeWrapper ];

  # No build step — the installer provides pre-built files.
  dontBuild = true;

  installPhase = ''
    runHook preInstall

    mkdir -p $out/lib/openclaw $out/bin

    # Copy pre-built runtime files.
    cp -r . $out/lib/openclaw/

    # Remove dangling symlinks.
    find $out/lib/openclaw -xtype l -delete 2>/dev/null || true

    # ── Closure size reduction ─────────────────────────────────────
    # The npm install includes ~1+ GB of node_modules. Strip everything
    # not needed at runtime.
    if [ -d $out/lib/openclaw/node_modules ]; then

      # Remove build artifacts (gyp, cmake, makefiles).
      find $out/lib/openclaw/node_modules \( \
        -name '*.gyp' -o -name '*.gypi' -o -name 'binding.gyp' -o \
        -name 'Makefile' -o -name 'CMakeLists.txt' \
      \) -delete 2>/dev/null || true

      # Remove TypeScript source and declaration files.
      find $out/lib/openclaw/node_modules -name '*.ts' ! -name '*.d.ts' -delete 2>/dev/null || true
      find $out/lib/openclaw/node_modules -name '*.d.ts' -delete 2>/dev/null || true
      find $out/lib/openclaw/node_modules -name '*.ts.map' -delete 2>/dev/null || true
      find $out/lib/openclaw/node_modules -name '*.js.map' -delete 2>/dev/null || true

      # Remove documentation, examples, tests.
      find $out/lib/openclaw/node_modules -type d \( \
        -name 'test' -o -name 'tests' -o -name '__tests__' -o \
        -name 'example' -o -name 'examples' -o -name 'demo' -o \
        -name 'docs' -o -name '.github' \
      \) -exec rm -rf {} + 2>/dev/null || true

      # Remove documentation files from package roots.
      find $out/lib/openclaw/node_modules \( \
        -name 'README*' -o -name 'CHANGELOG*' -o -name 'HISTORY*' -o \
        -name 'CHANGES*' -o -name 'AUTHORS*' -o -name 'CONTRIBUTORS*' -o \
        -name '*.md' -o -name 'LICENSE*' -o -name 'LICENCE*' \
      \) -delete 2>/dev/null || true

      # Remove C/Python source files from native module builds.
      find $out/lib/openclaw/node_modules \( \
        -name '*.py' -o -name '*.c' -o -name '*.h' -o -name '*.cc' -o -name '*.cpp' \
      \) -delete 2>/dev/null || true

      # Remove empty directories.
      find $out/lib/openclaw/node_modules -type d -empty -delete 2>/dev/null || true

      patchShebangs $out/lib/openclaw/node_modules/.bin/ 2>/dev/null || true
    fi

    # Choose entry point (the npm package may have dist/entry.js or openclaw.mjs).
    if [ -f $out/lib/openclaw/dist/entry.js ]; then
      ENTRY="$out/lib/openclaw/dist/entry.js"
    elif [ -f $out/lib/openclaw/openclaw.mjs ]; then
      ENTRY="$out/lib/openclaw/openclaw.mjs"
    else
      echo "ERROR: no entry point found in OpenClaw package" >&2
      ls -la $out/lib/openclaw/ >&2
      exit 1
    fi

    makeWrapper ${nodejs_22}/bin/node $out/bin/openclaw \
      --add-flags "$ENTRY" \
      --set NODE_PATH "$out/lib/openclaw/node_modules"

    runHook postInstall
  '';

  meta = {
    description = "OpenClaw MCP gateway (installed via official script)";
    homepage = "https://github.com/openclaw/openclaw";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "openclaw";
  };
}
