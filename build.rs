fn main() {
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
