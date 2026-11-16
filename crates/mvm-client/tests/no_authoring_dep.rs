//! Execution consumers must not acquire authoring tools through a transitive edge.

#[test]
fn execution_graphs_exclude_authoring_on_supported_hosts() {
    for package in ["mvm-client", "mvm-runtime", "mvm-hostlib"] {
        for target in ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"] {
            for all_features in [false, true] {
                let mut command = std::process::Command::new("cargo");
                command.args([
                    "tree",
                    "--locked",
                    "--offline",
                    "-p",
                    package,
                    "--target",
                    target,
                    "-e",
                    "normal,build",
                    "--prefix",
                    "none",
                ]);
                if all_features {
                    command.arg("--all-features");
                }
                let output = command.output().expect("cargo tree runs");
                assert!(
                    output.status.success(),
                    "{package} {target} all_features={all_features}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let tree = String::from_utf8(output.stdout).expect("Cargo output is UTF-8");
                for name in tree
                    .lines()
                    .filter_map(|line| line.split_whitespace().next())
                {
                    assert!(
                        !matches!(name, "mvm-sdk" | "mvm-compiler" | "tree-sitter")
                            && !name.starts_with("tree-sitter-"),
                        "{package} {target} all_features={all_features} includes authoring dependency {name}"
                    );
                }
            }
        }
    }
}
