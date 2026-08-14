# Browser wasm sandbox demo

A live, claim-free governance demo that runs in the visitor's browser. It is
built from the same `mvm-contract` code the host uses for:

- egress policy decisions (`mvm-contract::policy::projection`),
- placeholder substitution / bind-checks (`mvm-contract::substitution`),
- audit-entry construction and chain signing (`mvm-contract::verify`).

This crate is deliberately **excluded from the root Cargo workspace** (see the
root `Cargo.toml`) so `wasm-bindgen` and the `wasm32-unknown-unknown` target
never enter `cargo build --workspace` or the main workspace CI lane.

## Build

```bash
./build.sh
```

The script:

1. Runs `wasm-pack build --target web`.
2. Runs `wasm-opt -Oz` on the wasm bundle.
3. Enforces a gzipped size budget of **300 KiB**.
4. Builds the three curated `wasm32-wasip1` fixtures.
5. Stages everything into `public/public/demo/` so Astro serves it at `/demo`.

## Run locally

After `./build.sh`, serve the `public/public/demo/` directory (for example with
`python3 -m http.server 8000 --directory public/public/demo`) and open
`/demo/`.

## Tests

```bash
cargo test
```

The tests assert the honesty guardrails required by Plan 320:

- the real secret value never appears in the compiled fixture modules,
- the three scenarios produce the same outcomes the host witness asserts,
- the capability notice and verifying key are stable Rust-owned values.
