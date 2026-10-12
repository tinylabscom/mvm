//! Compiler stages consume contracts, never SDK facades or execution backends.

/// The compiler's full dependency tree (normal, build and dev edges), one
/// crate name per line.
fn dependency_tree() -> String {
    let output = std::process::Command::new(env!("CARGO"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "tree",
            "--locked",
            "--offline",
            "-p",
            "mvm-compiler",
            "--edges",
            "normal,build,dev",
            "--prefix",
            "none",
        ])
        .output()
        .expect("cargo tree runs");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("dependency tree is UTF-8")
}

fn names_crate(tree: &str, name: &str) -> bool {
    tree.lines()
        .any(|line| line.split_whitespace().next() == Some(name))
}

#[test]
fn compiler_does_not_link_authoring_or_execution_crates() {
    let tree = dependency_tree();
    for forbidden in [
        "mvm-sdk",
        "mvm-core",
        "mvm-client",
        "mvm-runtime",
        "mvm-build",
        "mvm-bundler",
        "mvm-agentd",
        "mvm-host-services",
    ] {
        assert!(
            !names_crate(&tree, forbidden),
            "compiler must not depend on {forbidden}:\n{tree}"
        );
    }
}

/// Compiling a workload or a pack never signs anything, so no signing key can
/// be handed to the compiler or to the builder input it produces. Signing stays
/// with the host signer and the bundler, which consume compiler output.
///
/// `mvm-contract` links `ed25519-dalek` to verify audit logs, so the crate is in
/// the tree; what the compiler must not do is reach a keystore or a TLS/PKI
/// stack, or name a signing key type in its own source.
#[test]
fn compiler_cannot_hold_or_use_a_signing_key() {
    let tree = dependency_tree();
    for forbidden in [
        "mvm-hostd",
        "mvm-hostlib",
        "keyring",
        "ring",
        "rcgen",
        "rustls",
    ] {
        assert!(
            !names_crate(&tree, forbidden),
            "compiler must not depend on key-custody crate {forbidden}:\n{tree}"
        );
    }

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    visit_rust_sources(&src, &mut |path, text| {
        for token in ["ed25519_dalek", "SigningKey", "signing_key", "Keypair"] {
            if text.contains(token) {
                offenders.push(format!("{} names {token}", path.display()));
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "compiler source must not handle signing keys:\n{}",
        offenders.join("\n")
    );
}

fn visit_rust_sources(dir: &std::path::Path, visit: &mut dyn FnMut(&std::path::Path, &str)) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .expect("compiler source directory is readable")
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            visit_rust_sources(&path, visit);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let text = std::fs::read_to_string(&path).expect("compiler source is UTF-8");
            visit(&path, &text);
        }
    }
}
