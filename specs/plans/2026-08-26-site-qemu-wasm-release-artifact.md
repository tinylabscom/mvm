# Site QEMU-WASM release artifact

Backing: shipped-source
Validation: check-sprint-append

## Goal

Keep Cloudflare Pages deployments fast by building the immutable QEMU-WASM
runtime pack on the `boot-image/v*` release cadence, then downloading and
verifying that pack during each site deployment. The website's HTML and
JavaScript shell remains sourced from the deploying revision.

## Tasks

- [x] Add a `qemu-wasm-site-pack` job to the boot-image workflow and publish
      its archive, checksum, and keyless-signature bundle.
- [x] Replace the Pages workflow's Nix/QEMU build with latest-semver boot-image
      asset selection, release-identity verification, checksum verification,
      and safe staging through the existing WebLinux demo script.
- [x] Add a workflow contract test that prevents Pages from rebuilding QEMU or
      accepting an unsigned pack.
- [x] Compress the staged QEMU WebAssembly module below Cloudflare Pages'
      25 MiB per-file limit and explicitly decompress it in the browser worker.
- [x] Ignore Wrangler's repository-local cache and account metadata.
- [x] Pass the focused release-assets suite, actionlint, workspace tests,
      workspace check, and Clippy with warnings denied.

## Security invariants

- Site deployment verifies the checksum manifest against the
  `release-boot-image.yml@refs/tags/boot-image/v*` keyless identity before
  trusting the archive digest.
- A missing, unsigned, or digest-mismatched pack fails deployment; there is no
  fallback build or unsigned compatibility path.
- The archive is produced from the tagged Nix derivation and is never rebuilt
  from an unrelated site revision.
- The worker decompresses the staged gzip payload into `Module.wasmBinary`
  before Emscripten starts, independent of CDN content-encoding behavior.
