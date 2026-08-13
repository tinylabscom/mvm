# `mvm-demo-web`

Browser-side wasm shim for the live `/demo` sandbox on the website.

This crate is **excluded from the main workspace** so `wasm-bindgen` and the
`wasm32` target never enter `cargo build --workspace` or CI. Build it with
`wasm-pack` targeting `web`:

```bash
wasm-pack build --target web --out-dir pkg
```

The Astro site loads `pkg/mvm_demo_web.js` and `pkg/mvm_demo_web_bg.wasm`
from a Web Worker. The Worker owns both this governance core and the curated
WASI module; it supplies the module's `mvm:egress` import as a JS trampoline
into this crate.
