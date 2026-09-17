fn main() {
    record_enabled_features();

    // On macOS, auto-sign the binary with the virtualization entitlement
    // after every build. Without this, Virtualization.framework will crash
    // with "The process doesn't have the com.apple.security.virtualization
    // entitlement."
    #[cfg(target_os = "macos")]
    {
        // This runs at build time. The actual signing needs to happen after
        // linking, so we use a post-build hook via cargo.
        // For now, print instructions — the pre-commit hook or a wrapper
        // script should handle signing.
        //
        // To auto-sign during development:
        //   cargo build && codesign --force --sign - --entitlements assets/mvmctl.entitlements target/debug/mvmctl
        println!("cargo:rustc-env=MVM_ENTITLEMENTS=assets/mvmctl.entitlements");
    }
}

/// Record the features this `mvmctl` is compiled with as `MVMCTL_ENABLED_FEATURES`.
///
/// A bootstrap helper the binary has to compile is built with the same set, and
/// only this package can see its own features. They come from Cargo's
/// `CARGO_FEATURE_<NAME>` variables rather than a list kept by hand, which would
/// go stale the first time a feature is added. Cargo reruns this script when the
/// feature set changes, so the value always matches the binary.
fn record_enabled_features() {
    let mut features: Vec<String> = std::env::vars()
        .filter_map(|(key, _)| {
            key.strip_prefix("CARGO_FEATURE_")
                .map(|name| name.to_ascii_lowercase().replace('_', "-"))
        })
        .collect();
    features.sort();
    println!(
        "cargo:rustc-env=MVMCTL_ENABLED_FEATURES={}",
        features.join(",")
    );
}
