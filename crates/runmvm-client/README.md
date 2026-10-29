# runmvm-client

A standalone Rust JSON client for the released `libmvm_hostlib` ABI 1.7.
It has no dependency on internal mvm crates and contains no compiler, VM
runtime, policy interpreter, downloader or process-spawn fallback.
The released native ABI and this client support 64-bit hosts.

Install a matching released host library **and its matching helper set**
separately. This crate does not provision them. Releases retain their existing
Sigstore verification and macOS ad-hoc signing; Developer ID signing and
notarization are not provided by this client.

```rust,no_run
use runmvm_client::{DiscoveryOptions, Hostlib};
// Safety: the operator controls PATH and the installed native library and
// dependencies, and trusts them to implement the documented hostlib ABI.
let host = unsafe { Hostlib::discover(DiscoveryOptions::from_env()) }?;
let result = host.call_value("manifest.list", Some(&serde_json::json!({})))?;
# Ok::<(), runmvm_client::Error>(())
```

`Hostlib::load(path)` and `Hostlib::discover(options)` are unsafe because loading
native code executes with the host account's authority. The caller must trust
the library and its dependencies, including its exact ABI and memory ownership
contract. Safe calls after loading do not sandbox that code.

`MVM_HOSTLIB_PATH` is exclusive, including when empty or invalid. Without it,
discovery finds the first executable `mvmctl` on PATH without running it and
checks for the library beside both that path and its canonical target.
There are no Cargo, source, Nix, Python or npm directory guesses.
`DiscoveryOptions` can instead supply explicit inputs without mutating the
process environment. Selected filesystem paths are canonicalized to absolute
paths before loading, so bare relative names do not trigger native loader
searches. Canonicalization is not TOCTOU protection: the caller must also trust
the filesystem and prevent untrusted replacement of the library or dependencies.

`call_json_bytes` preserves request byte lengths and returns copied JSON bytes.
`call_value` serializes and parses `serde_json::Value`; `None` sends no request.
Every returned native buffer is released once, including failure paths.
Errors preserve unknown numeric statuses and native JSON error fields without
inventing retry policy. Error formatting redacts native body content.

Approval callbacks are unsupported. This client neither installs nor resets
process-global approval policy. In an otherwise unconfigured process, `ask`
decisions are denied by the existing host policy; another binding in the same
process may have configured that policy.

Integration tests compile only the packaged, dependency-free Rust cdylib fixture
with `rustc`, offline. They never build or invoke the real host library or a VM.
