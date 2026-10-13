#!/bin/sh
# Only the smoke script is copied from source; payloads come from registries.
set -eu
language=$1
version=$2
key=$3
smoke=$4
case "$version" in ''|*[!0-9.]*) echo "invalid SDK version" >&2; exit 2 ;; esac
case "$key" in darwin-arm64|linux-x64-gnu|linux-arm64-gnu|linux-x64-musl|linux-arm64-musl) ;; *) exit 2 ;; esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cp "$smoke" "$work/"
cd "$work"
unset MVM_HOSTLIB_PATH PYTHONPATH PYTHONHOME NODE_PATH NODE_OPTIONS MVM_SDK_DIR MVM_WORKSPACE_ROOT
unset LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH
export HOME="$work/home"
mkdir "$HOME"
case "$language" in
  python)
    "${PYTHON:-python3}" -m venv venv
    export PIP_CONFIG_FILE=/dev/null
    venv/bin/python -m pip --isolated install --no-cache-dir \
      --index-url https://pypi.org/simple --only-binary=:all: "mvm==$version"
    venv/bin/python -c "import importlib.metadata; assert importlib.metadata.version('mvm') == '$version'"
    venv/bin/python smoke_installed.py
    ;;
  node)
    # npm rejects loading the same config path twice, even /dev/null.
    export npm_config_userconfig="$work/user.npmrc" npm_config_globalconfig="$work/global.npmrc"
    : > "$npm_config_userconfig"
    : > "$npm_config_globalconfig"
    export npm_config_cache="$work/npm-cache"
    npm init -y >/dev/null
    npm install --registry=https://registry.npmjs.org --include=optional \
      --no-audit --no-fund --save-exact "@runmvm/mvm@$version"
    # Optional-dependency resolution must supply the platform package itself.
    node -e "for (const n of ['@runmvm/mvm','@runmvm/mvm-$key']) { const p=JSON.parse(require('fs').readFileSync('node_modules/'+n+'/package.json')); if(p.version !== '$version') throw Error(n+' version mismatch'); }"
    node smoke-installed.mjs "$key"
    ;;
  *) echo "expected python or node" >&2; exit 2 ;;
esac
printf '%s\n' "PASS registry install/load: $language $version $key" \
  "Guest boot NOT witnessed by install/load; this is not end-to-end SDK release acceptance."
