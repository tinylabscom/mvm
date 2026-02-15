## Builder without SSH (Option B)

Goal: eliminate sshd/authorized_keys inside the builder VM. Use a small in-guest agent over vsock (or serial) and transfer artifacts via a shared volume/stream.

### Long-term production shape
- Immutable builder image (read-only rootfs) containing only:
  - vsock/serial agent binary
  - Nix + minimal deps
  - No sshd, no authorized_keys
- Per-build writable volume:
  - Mounted at `/build-out` (ext4, throwaway)
  - Receives all build artifacts and logs
- Host ↔ guest control plane:
  - vsock port `21470` (example) with a line/JSON protocol
  - Requests are signed by host (optional HMAC) to prevent spoofing
- Artifact export:
  - Host mounts `/build-out` after shutdown and copies `vmlinux`, `rootfs.ext4`, `fc-base.json`
  - Volume is then discarded

### Proposed flow
1) Launch builder with:
   - vsock device (preferred) or serial console
   - throwaway scratch volume mounted in-guest (e.g., `/build-out`)
2) In-guest agent (tiny Rust helper):
   - Listens on vsock port N
   - Accepts payload `{ flake_ref, build_attr, timeout }`
   - Runs `nix build … --no-link --print-out-paths`
   - Copies `vmlinux`, `rootfs.ext4`, `fc-base.json` into `/build-out/`
   - Returns status + paths over vsock
3) Host side:
   - Sends request over vsock (or serial) via a small client helper
   - Copies artifacts from the mounted scratch volume back to the host template/pool revision dir
4) Tear down VM as today

### Security & isolation
- No sshd or authorized_keys in the image
- Agent exposes only a minimal API on vsock/serial; restrict to local CID
- Scratch volume is per-build and disposable

### Fallback
- If vsock unavailable, use serial with a simple line protocol

### Incremental steps
- Add a small Rust agent binary to `mvm-guest` implementing the build + copy
- Add a host vsock client helper in `mvm-build`
- Keep current SSH path behind a feature flag until stable
- Add HMAC on request payload (host shares secret with agent baked into image)
- Bake agent + Nix into an immutable builder rootfs and stop mutating it at runtime

### Trade-offs
- Pros: removes SSH/key/perm churn; smaller attack surface
- Cons: custom protocol + agent maintenance; requires vsock support; adds volume plumbing

### Minimal agent API (draft)
- Request (JSON):  
  `{ "action": "build", "flake_ref": "<string>", "attr": "<string>", "timeout": 1800, "hmac": "<hex>" }`
- Responses (stdout on vsock):
  - `OK <path>` when artifacts placed in `/build-out`
  - `LOG <line>` streamed during build
  - `ERR <message>` on failure

### Migration plan
1) Build immutable builder image with agent + Nix; publish to `/var/lib/mvm/builder/builder-base.ext4`.
2) Host: add vsock client + per-build data volume; gate behind `MVM_BUILDER_MODE=vsock`.
3) Dual-path period: keep SSH as fallback.
4) Flip default to vsock once stable; remove sshd from the builder image.
