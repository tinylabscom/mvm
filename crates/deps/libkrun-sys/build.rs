//! Build script for mvm-libkrun.
//!
//! When the `libkrun-sys` cargo feature is on:
//!   1. Probe for `libkrun.h` at the three standard install locations
//!      (Apple Silicon Homebrew, Intel/manual, Linux distro).
//!   2. Run `bindgen` to emit Rust FFI bindings into `OUT_DIR/libkrun_sys.rs`.
//!   3. Emit `cargo:rustc-link-lib=krun` so the linker pulls in the shared
//!      library.
//!
//! When the feature is off, this script is a noop — the workspace builds
//! cleanly on hosts without libkrun installed.

use std::env;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=MVM_LIBKRUN_HEADER");

    if env::var_os("CARGO_FEATURE_LIBKRUN_SYS").is_none() {
        // Default build path — no FFI, no link, no bindgen invocation.
        return;
    }

    let header = locate_header().unwrap_or_else(|| {
        panic!(
            "libkrun-sys feature is enabled but libkrun.h was not found.\n\
             Checked: {}.\n\
             Install libkrun (`brew install libkrun` on macOS, distro package on Linux)\n\
             or point MVM_LIBKRUN_HEADER at the header path.",
            probe_paths()
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        )
    });

    println!("cargo:rerun-if-changed={}", header.display());

    let out_path =
        PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR set by cargo")).join("libkrun_sys.rs");

    let include_dir = header
        .parent()
        .expect("libkrun.h has a parent directory")
        .to_path_buf();

    bindgen::Builder::default()
        .header(header.to_string_lossy())
        .clang_arg(format!("-I{}", include_dir.display()))
        // Keep the generated surface small — only the symbols we wrap in
        // sys.rs plus the KRUN_* constants we need at the type level.
        // Plan 87: also surface NET_FEATURE_*` + `COMPAT_NET_FEATURES`
        // for the passt virtio-net backend (`krun_add_net_unixstream`'s
        // `features` arg expects a bitwise-or of those).
        .allowlist_function("krun_.*")
        .allowlist_var("KRUN_.*")
        .allowlist_var("NET_FEATURE_.*")
        .allowlist_var("COMPAT_NET_FEATURES")
        .allowlist_var("NET_FLAG_.*")
        .layout_tests(false)
        .generate_comments(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("bindgen failed to generate libkrun bindings")
        .write_to_file(&out_path)
        .expect("failed to write libkrun bindings");

    // Tell the linker to pull in libkrun. On macOS the dylib is found via
    // the standard Homebrew library path; on Linux via the distro install.
    println!("cargo:rustc-link-lib=krun");

    // Make sure the linker can find the dylib next to the header we probed.
    // Homebrew installs to /opt/homebrew/{include,lib}; the symmetric `lib`
    // sibling is the right hint without hardcoding paths in every consumer.
    if let Some(prefix) = include_dir.parent() {
        let lib_dir = prefix.join("lib");
        if lib_dir.exists() {
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
        }
    }
}

fn locate_header() -> Option<PathBuf> {
    if let Some(override_path) = env::var_os("MVM_LIBKRUN_HEADER") {
        let p = PathBuf::from(override_path);
        if p.is_file() {
            return Some(p);
        }
    }
    probe_paths().into_iter().find(|p| p.is_file())
}

fn probe_paths() -> Vec<PathBuf> {
    vec![
        Path::new("/opt/homebrew/include/libkrun.h").to_path_buf(),
        Path::new("/usr/local/include/libkrun.h").to_path_buf(),
        Path::new("/usr/include/libkrun.h").to_path_buf(),
    ]
}
