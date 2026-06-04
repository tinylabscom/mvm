//! In-rootfs paths the runtime expects to find at boot.
//!
//! The Nix factories (`nix/factories/*.nix`) and the runtime agree on
//! these constants; changing one without the other is a wire break.
//! The CI lane `wrapper-import-grep` keeps the dispatch fragments at
//! their declared filenames.

/// Where the factory bakes the parsed runtime config (a small JSON
/// document declaring `runtime`, `module`, `function`, `format`,
/// `source_path`).
pub const DEFAULT_CONFIG_PATH: &str = "/etc/mvm/runtime.json";

/// Directory holding the per-language dispatch fragments. The runtime
/// picks `dispatch.py` or `dispatch.mjs` from here based on the
/// runtime declared in the config.
pub const DEFAULT_DISPATCH_DIR: &str = "/usr/lib/mvm/runtime";
