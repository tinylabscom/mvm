- [~] Experimental Obscura browser provider — an isolated pilot adds a
      digest-pinned, explicit `BrowserSandbox("obscura")` option without
      changing the Chromium default. Python and TypeScript now preserve typed
      manifest-versus-OCI sources, lower literal env and exact egress
      allowlists, reject unsupported live options before boot, fix Obscura to
      guest loopback plus the mvm proxy, and enforce bounded CDP readiness with
      cleanup. A cross-architecture Nix guest example pins both release
      archives. Language SDK, Rust lowering, example-contract, targeted
      Clippy, and the available `aarch64-linux` Nix guest-build gates pass;
      real-backend policy, compatibility, the full Nix matrix, a clean
      one-shot workspace test run, and native Linux gates remain open in the
      owning plan. The provider remains experimental and opt-in.
