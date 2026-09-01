//! Contributor embedding is an explicit workflow. Keep its macOS LLVM loader
//! repair in the recipe contributors actually run.

#[test]
fn embed_recipe_exposes_the_pinned_rust_sysroot_to_macos_llvm_tools() {
    let justfile = include_str!("../../../Justfile");
    let recipe = justfile
        .split("embed *ARGS:")
        .nth(1)
        .expect("embed recipe")
        .split("embed-refresh:")
        .next()
        .expect("embed recipe body");

    assert!(recipe.contains("scripts/rustc-macos-loader.sh"), "{recipe}");
    assert!(recipe.contains("RUSTC_WRAPPER"), "{recipe}");
    assert!(recipe.contains("rustc --print sysroot"), "{recipe}");
    assert!(recipe.contains("DYLD_FALLBACK_LIBRARY_PATH"), "{recipe}");
    assert!(recipe.contains("$rust_sysroot/lib"), "{recipe}");
}

#[test]
fn embed_recipe_builds_native_vm_helpers_in_the_requested_profile() {
    let justfile = include_str!("../../../Justfile");
    let recipe = justfile
        .split("embed *ARGS:")
        .nth(1)
        .expect("embed recipe")
        .split("embed-refresh:")
        .next()
        .expect("embed recipe body");

    let helper_build = recipe
        .find("build -p mvm-hostd --bins {{ARGS}}")
        .expect("embed recipe builds native per-VM helpers");
    let mvmctl_build = recipe
        .find("build --features embed-host-bins {{ARGS}}")
        .expect("embed recipe builds embedded mvmctl");
    assert!(
        helper_build < mvmctl_build,
        "native helpers must be ready before mvmctl is linked: {recipe}"
    );
}

#[test]
fn macos_rustc_wrapper_restores_the_sysroot_loader_path() {
    let wrapper = include_str!("../../../scripts/rustc-macos-loader.sh");
    assert!(wrapper.contains("--print sysroot"), "{wrapper}");
    assert!(wrapper.contains("DYLD_FALLBACK_LIBRARY_PATH"), "{wrapper}");
    assert!(wrapper.contains("$rust_sysroot/lib"), "{wrapper}");
    assert!(wrapper.contains("$existing_loader_path"), "{wrapper}");
    assert!(wrapper.contains("exec \"$rustc_bin\" \"$@\""), "{wrapper}");
}
