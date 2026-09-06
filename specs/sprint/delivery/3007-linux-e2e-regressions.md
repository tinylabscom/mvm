# The Linux e2e lane's three real failures

- [x] Fixed the fresh-pull path dropping every OCI image's declared `Env`,
      `WorkingDir` and `Entrypoint`; `/etc/mvm/image-runtime.json` was never
      written, so images fell back to `DEFAULT_PATH` and their own tools were
      off `PATH`. Verified on KVM hardware with `--image rust`.
- [x] Made the mount-image cache open lazily. Constructing it runs the
      encrypted-backing check, so every `machine run -d` was refused on a host
      without dm-crypt even with no volumes and no `--mount` — a production
      defect, not just a lane failure.
- [x] Repinned the SDK conformance fixture from an `arm64/v8` manifest digest
      to alpine:3.22's multi-arch index digest; the old pin could only ever
      pass on Apple Silicon and ENOEXEC'd on x86_64.
- [x] Rendered captured stderr in the Python and TypeScript `SandboxLiveError`,
      which is what made the original CI failure diagnosable at all.
- [x] Verified all three fixes end-to-end on the Hetzner KVM box.
- [ ] Confirm on the first Extended CI run after this lands.
- [ ] Merge the linked pull request through the queue.

Owning plan: `specs/plans/2026-09-05-linux-e2e-regressions.md`.
