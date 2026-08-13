# `mvm-demo-web`

Browser-side wasm sandbox demo. Mirrors `web/audit-verify/`: it is excluded
from the main workspace so `wasm-bindgen` and the `wasm32` target never enter
`cargo build --workspace`, and it is built with `wasm-pack`.

## Build

```bash
wasm-pack build --target web --out-dir pkg
```

This requires the `wasm32-unknown-unknown` target. In the project builder VM
it is installed by the wasm CI lane; on a bare macOS host you may need to add
it to your toolchain.

## Run locally

After `wasm-pack build`, serve this directory with any static file server:

```bash
python3 -m http.server 8080
# open http://localhost:8080
```

## What it demonstrates

The page runs three curated scenarios against the same `mvm-contract`
governance code the host uses:

- **allowed** — destination is in the allow-list and the secret is bound to
  it; the destination receives the real credential while the module held only
  the opaque placeholder.
- **denied** — default-deny; the destination is never contacted.
- **unbound** — host is admitted but the secret is not bound to it; the
  request is forwarded with the placeholder dropped.

The audit-chain pane verifies (or tampers with) a pre-signed fixture chain
using `mvm_contract::verify`. Real chain signing in the browser is plan 320
E3.

## Honesty guardrails

The page states plainly:

- The browser's own wasm engine runs the code; the host `WasmBackend` is not
  exercised.
- This is a governance/portability demo, not an isolation boundary.
- The claims-bearing way to run a wasm workload is plan 321's engine-in-guest
  path.
