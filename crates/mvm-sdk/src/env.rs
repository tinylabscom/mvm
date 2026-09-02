//! The Rust-owned registry of SDK environment-variable names.
//!
//! Every name the SDKs and the CLI agree on is declared exactly once,
//! here, and both language SDKs' copies are generated from it by
//! `cargo xtask gen-stubs`. Before this module `MVM_CLI_BIN` was spelled
//! out in four places — twice in this crate, once in each SDK — and
//! because all four agreed, nothing could detect it if one drifted.
//!
//! Each entry declares which language surfaces export it. That is not a
//! formality: a name is listed for a surface only when that surface
//! actually *reads* it, so the generated bindings cannot manufacture a
//! constant nobody uses and thereby claim a parity that does not exist.

/// A language surface that can export an environment-variable name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Surface {
    /// The Rust SDK and the CLI.
    Rust,
    /// The Python SDK (`crates/mvm-sdk/sdks/python`).
    Python,
    /// The TypeScript SDK (`crates/mvm-sdk/sdks/typescript`).
    TypeScript,
}

impl Surface {
    /// Lowercase wire spelling, as it appears in the emitted manifest.
    pub const fn as_str(self) -> &'static str {
        match self {
            Surface::Rust => "rust",
            Surface::Python => "python",
            Surface::TypeScript => "typescript",
        }
    }
}

/// One environment variable the SDK contract depends on.
#[derive(Debug, Clone, Copy)]
pub struct SdkEnvVar {
    /// The constant's identifier, identical in every language.
    pub ident: &'static str,
    /// The environment variable's actual name.
    pub name: &'static str,
    /// One-line description, rendered into each generated binding.
    pub doc: &'static str,
    /// The surfaces that export this name — see the module note.
    pub surfaces: &'static [Surface],
}

impl SdkEnvVar {
    /// Whether this name is exported by `surface`.
    pub fn exports_to(&self, surface: Surface) -> bool {
        // `[T]::contains` is not const-callable on this toolchain, and
        // the slices are three elements at most.
        let mut i = 0;
        while i < self.surfaces.len() {
            if self.surfaces[i] as u8 == surface as u8 {
                return true;
            }
            i += 1;
        }
        false
    }
}

/// Declare each variable once, producing both a `pub const` (so Rust
/// callers, rustdoc and go-to-definition keep working normally) and a
/// row in [`REGISTRY`] (so the emitters have a single table to walk).
macro_rules! sdk_env_vars {
    ($(
        $(#[doc = $doc:literal])+
        $ident:ident = $name:literal, [$($surface:ident),+ $(,)?];
    )+) => {
        $(
            $(#[doc = $doc])+
            pub const $ident: &str = $name;
        )+

        /// Every SDK environment variable, in declaration order.
        pub const REGISTRY: &[SdkEnvVar] = &[
            $(
                SdkEnvVar {
                    ident: stringify!($ident),
                    name: $name,
                    // Rustdoc splits a multi-line `///` block into one
                    // attribute per line; rejoin them for the manifest.
                    doc: concat!($($doc),+),
                    surfaces: &[$(Surface::$surface),+],
                },
            )+
        ];
    };
}

sdk_env_vars! {
    /// Overrides the path to the `mvmctl` binary the SDKs shell out to.
    MVM_CLI_BIN_ENV = "MVM_CLI_BIN", [Rust, Python, TypeScript];

    /// Selects the SDK's execution mode (for example `live` or `record`).
    MVM_SDK_MODE_ENV = "MVM_SDK_MODE", [Rust, Python, TypeScript];

    /// Carries an explicitly selected security profile from `mvmctl run`
    /// into the live SDK's nested `mvmctl machine run` invocation.
    MVM_SDK_RUN_PROFILE_ENV = "MVM_SDK_RUN_PROFILE", [Rust, Python, TypeScript];

    /// When set, the SDK writes its wire-shape recording JSON to this
    /// path on exit, so a caller need not parse stdout.
    MVM_SDK_OUT_PATH_ENV = "MVM_SDK_OUT_PATH", [Rust, Python, TypeScript];

    /// Overrides the per-call timeout, in seconds, applied to a
    /// `mvmctl machine` subprocess. Both language wrappers read it and
    /// give up at the deadline rather than waiting forever.
    MVM_MACHINE_TIMEOUT_ENV = "MVM_MACHINE_TIMEOUT_SEC", [Rust, Python, TypeScript];

    /// Overrides the cap, in bytes, on captured output from a `mvmctl
    /// machine` subprocess. Both language wrappers read it and report an
    /// overflow as an overflow.
    MVM_MACHINE_MAX_OUTPUT_ENV = "MVM_MACHINE_MAX_OUTPUT_BYTES", [Rust, Python, TypeScript];
}

/// The registry rows that `surface` exports, in declaration order.
pub fn exported_to(surface: Surface) -> impl Iterator<Item = &'static SdkEnvVar> {
    REGISTRY.iter().filter(move |v| v.exports_to(surface))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_rows_match_their_constants() {
        // The macro builds both from one declaration, so this can only
        // fail if the macro itself regresses — which is exactly the
        // failure that would silently desynchronise every SDK.
        let by_ident = |ident: &str| {
            REGISTRY
                .iter()
                .find(|v| v.ident == ident)
                .unwrap_or_else(|| panic!("{ident} missing from REGISTRY"))
        };
        assert_eq!(by_ident("MVM_CLI_BIN_ENV").name, MVM_CLI_BIN_ENV);
        assert_eq!(by_ident("MVM_SDK_MODE_ENV").name, MVM_SDK_MODE_ENV);
        assert_eq!(
            by_ident("MVM_SDK_RUN_PROFILE_ENV").name,
            MVM_SDK_RUN_PROFILE_ENV
        );
        assert_eq!(by_ident("MVM_SDK_OUT_PATH_ENV").name, MVM_SDK_OUT_PATH_ENV);
        assert_eq!(
            by_ident("MVM_MACHINE_TIMEOUT_ENV").name,
            MVM_MACHINE_TIMEOUT_ENV
        );
        assert_eq!(
            by_ident("MVM_MACHINE_MAX_OUTPUT_ENV").name,
            MVM_MACHINE_MAX_OUTPUT_ENV
        );
    }

    #[test]
    fn idents_and_names_are_unique() {
        for (i, a) in REGISTRY.iter().enumerate() {
            for b in &REGISTRY[i + 1..] {
                assert_ne!(a.ident, b.ident, "duplicate ident {}", a.ident);
                assert_ne!(a.name, b.name, "duplicate env name {}", a.name);
            }
        }
    }

    #[test]
    fn every_row_is_exported_by_rust() {
        // Rust is the owner of the registry; a row nothing in Rust reads
        // would be a name we are inventing for the SDKs rather than
        // sharing with them.
        for v in REGISTRY {
            assert!(v.exports_to(Surface::Rust), "{} not owned by Rust", v.ident);
        }
    }

    #[test]
    fn machine_vars_are_claimed_for_typescript() {
        // The honesty property, now pointing the other way: the TypeScript
        // machine wrapper bounds its subprocess with these two, so it must
        // export them. A row is listed for a surface only when that surface
        // reads it — so this fails if the behaviour is ever removed and the
        // claim is left behind.
        for ident in ["MVM_MACHINE_TIMEOUT_ENV", "MVM_MACHINE_MAX_OUTPUT_ENV"] {
            let v = REGISTRY.iter().find(|v| v.ident == ident).unwrap();
            assert!(
                v.exports_to(Surface::TypeScript),
                "{ident} is read by the TypeScript machine wrapper but not exported to it"
            );
        }
    }

    #[test]
    fn exported_to_filters_by_surface() {
        let ts: Vec<&str> = exported_to(Surface::TypeScript).map(|v| v.ident).collect();
        assert_eq!(
            ts,
            [
                "MVM_CLI_BIN_ENV",
                "MVM_SDK_MODE_ENV",
                "MVM_SDK_RUN_PROFILE_ENV",
                "MVM_SDK_OUT_PATH_ENV",
                "MVM_MACHINE_TIMEOUT_ENV",
                "MVM_MACHINE_MAX_OUTPUT_ENV"
            ]
        );
        assert_eq!(exported_to(Surface::Python).count(), 6);
    }
}
