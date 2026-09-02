//! Contributor embedding is an explicit workflow. Keep its macOS LLVM loader
//! repair reachable from every recipe that links host binaries.

const JUSTFILE: &str = include_str!("../../../Justfile");

/// The body of `name`, up to the recipe that follows it. Recipe bodies are the
/// unit these guards assert over, and slicing them by hand three times over is
/// how one of them ends up bounded by the wrong marker.
fn recipe_body(name: &str, next: &str) -> &'static str {
    JUSTFILE
        .split(name)
        .nth(1)
        .unwrap_or_else(|| panic!("{name} recipe"))
        .split(next)
        .next()
        .unwrap_or_else(|| panic!("{name} recipe body"))
}

/// The repair moved out of `embed` and into a shared script so a second recipe
/// could reuse it. Assert the reference, not the mechanism — the mechanism is
/// asserted once, against the script, below.
#[test]
fn embed_recipe_exposes_the_pinned_rust_sysroot_to_macos_llvm_tools() {
    let recipe = recipe_body("embed *ARGS:", "embed-refresh:");
    assert!(recipe.contains("scripts/macos-objcopy-env.sh"), "{recipe}");
}

/// `build-supervisors` links the same `mvm-hostd` binaries `embed` does. It
/// went without this repair and shipped every supervisor unstripped, which is
/// what this guard exists to catch a second time.
#[test]
fn build_supervisors_recipe_exposes_the_pinned_rust_sysroot_too() {
    let recipe = recipe_body("build-supervisors *ARGS:", "\nembed *ARGS:");
    assert!(recipe.contains("scripts/macos-objcopy-env.sh"), "{recipe}");
    assert!(
        recipe.contains("build -p mvm-hostd --bins {{ARGS}}"),
        "{recipe}"
    );
}

#[test]
fn macos_objcopy_env_seeds_the_loader_path_and_the_rustc_wrapper() {
    let env = include_str!("../../../scripts/macos-objcopy-env.sh");
    assert!(env.contains("rustc --print sysroot"), "{env}");
    assert!(env.contains("DYLD_FALLBACK_LIBRARY_PATH"), "{env}");
    assert!(env.contains("${_mvm_rust_sysroot}/lib"), "{env}");
    assert!(env.contains("scripts/rustc-macos-loader.sh"), "{env}");
    assert!(env.contains("RUSTC_WRAPPER"), "{env}");
    // A no-op off Darwin, or every Linux contributor inherits a macOS repair.
    assert!(env.contains(r#""$(uname -s)" != "Darwin""#), "{env}");
}

#[test]
fn embed_recipe_builds_native_vm_helpers_in_the_requested_profile() {
    let recipe = recipe_body("embed *ARGS:", "embed-refresh:");

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
