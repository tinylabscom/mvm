//! Static tripwire for the universal-agent ownership boundary.
//!
//! Linux bases and application root filesystems do not launch an mvm runtime.
//! Workload/dev boots use the CLI's verified runtime agent as initramfs PID 1;
//! builder PID 1 launches the agent from that runtime's overlay. Source wiring
//! is not boot evidence; completeness and privilege tests remain separate.

use anyhow::{Context, Result, bail};
use std::path::Path;

struct Boundary {
    path: &'static str,
    required: &'static [&'static str],
    forbidden: &'static [&'static str],
}

const BOUNDARIES: &[Boundary] = &[
    Boundary {
        path: "crates/mvm-core/src/image_set/validate.rs",
        required: &[
            "if !legacy",
            ".find(|member| member.role.is_retired())",
            "ImageSetError::RetiredRuntimeInLinuxSet",
            "super::BuilderBootAbi::NO_MVM_BINARY",
        ],
        forbidden: &[],
    },
    Boundary {
        path: "nix/lib/mk-guest.nix",
        required: &[
            "initSystem = \"initramfs-agent\";",
            "overlayAware = true;",
            "runtimeLean = true;",
            "cp ${baseImageContractFile} \"$out/etc/mvm/base-image-contract\"",
        ],
        forbidden: &[
            "MVM_AGENT_BIN",
            "$out/init",
            "${guestAgentPkg}/bin/mvm-guest-agent",
            "${guestAgentPkg}/bin/mvm-guest-netinit",
            "${guestAgentPkg}/bin/mvm-egress-client",
        ],
    },
    Boundary {
        path: "crates/mvm-build/src/runtime_pieces.rs",
        required: &[
            "runtime: &GuestRuntime",
            "crate::guest_runtime::install_release_guest_runtime(cache_root, archive, version, arch)?",
            "crate::runtime_overlay::build_runtime_overlay_from_guest_runtime(",
            "crate::initramfs::build_initramfs_from_guest_runtime(",
            "pack_sdk_sidecars(cache_root, version, arch, runtime)?",
        ],
        forbidden: &["resolve_image_set_initramfs("],
    },
    Boundary {
        path: "crates/mvm-build/src/initramfs.rs",
        required: &[
            "runtime: &crate::guest_runtime::GuestRuntime",
            "format!(\"{arch}/initramfs/mvm-guest-agent\")",
            "runtime.manifest.files.get(&member)",
            "sha256_hex(&agent_bytes) != *expected_digest",
            "assemble_initramfs_artifact(&agent_bytes, version, staging.path())?",
            "CpioEntry::file(\"./init\", 0o755, agent_bytes.to_vec())",
        ],
        forbidden: &[],
    },
    Boundary {
        path: "crates/mvm-build/src/guest_runtime.rs",
        required: &[
            "guest_agent_build::RUNTIME_OVERLAY_SEALED_BINS",
            ".chain(guest_agent_build::RUNTIME_OVERLAY_ADDON_BINS)",
            "required.insert(GuestBinsMember::InitramfsAgent { arch }.path());",
            "GuestRuntimeError::MissingRequired",
        ],
        forbidden: &[],
    },
    Boundary {
        path: "crates/mvm-build/src/bin/mvm-host-vm-init.rs",
        required: &[
            "fork_guest_agent();",
            "fn fork_guest_agent()",
            "crate::resolve_agent_binary(is_executable)",
            "crate::agent_spawn_command(&setpriv, &agent_bin, agent_uid)",
            "let candidates: &[&str] = &AGENT_BIN_CANDIDATES[..1];",
            ".arg(format!(\"--reuid={agent_uid}\"))",
            ".arg(format!(\"--regid={agent_uid}\"))",
            ".arg(\"--clear-groups\")",
            ".arg(\"--no-new-privs\")",
        ],
        forbidden: &[],
    },
    Boundary {
        path: "crates/mvm-agentd/src/bin/mvm-guest-agent.rs",
        required: &[
            "init::early_setup();",
            "bind_listener(cfg.port)",
            "init::apply_activation(&env, boot_state)",
        ],
        forbidden: &[],
    },
];

fn production_source(boundary: &Boundary, content: &str) -> String {
    use crate::rust_source::{CommentSyntax, blank_comments};
    if boundary.path.ends_with(".rs") {
        let blanked = crate::rust_source::blank_comments_and_strings(content);
        let ranges = crate::rust_source::cfg_test_item_ranges(&blanked);
        blank_comments(
            &crate::rust_source::blank_ranges(content, &ranges),
            CommentSyntax::Rust,
        )
    } else {
        blank_comments(content, CommentSyntax::NixShell)
    }
}

fn violations(boundary: &Boundary, content: &str) -> Vec<String> {
    let source = production_source(boundary, content);
    let mut errors = Vec::new();
    for marker in boundary.required {
        if !source.contains(marker) {
            errors.push(format!(
                "{} missing runtime witness `{marker}`",
                boundary.path
            ));
        }
    }
    for marker in boundary.forbidden {
        if source.contains(marker) {
            errors.push(format!(
                "{} couples base/application to runtime: `{marker}`",
                boundary.path
            ));
        }
    }
    errors
}

pub fn run(workspace: &Path) -> Result<()> {
    let mut errors = Vec::new();
    for boundary in BOUNDARIES {
        let content = std::fs::read_to_string(workspace.join(boundary.path))
            .with_context(|| format!("reading universal-agent boundary {}", boundary.path))?;
        errors.extend(violations(boundary, &content));
    }
    if !errors.is_empty() {
        bail!(
            "check-guest-agent-in-all-images: universal-agent ownership drift:\n  - {}\n\
             Bases carry Linux/workload files; the CLI-selected runtime supplies the \
             universal initramfs agent and builder overlay agent. Restore that wiring, \
             not a baked runtime or shell /init.",
            errors.join("\n  - ")
        );
    }
    eprintln!(
        "check-guest-agent-in-all-images: clean ({} split-runtime boundaries)",
        BOUNDARIES.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(boundary: &Boundary) -> String {
        boundary.required.join("\n")
    }

    #[test]
    fn proper_split_passes_without_shell_init_or_baked_agent() {
        for boundary in BOUNDARIES {
            assert!(violations(boundary, &fixture(boundary)).is_empty());
        }
    }

    #[test]
    fn each_runtime_witness_is_required() {
        for boundary in BOUNDARIES {
            for marker in boundary.required {
                let changed = fixture(boundary).replace(marker, "");
                assert!(
                    !violations(boundary, &changed).is_empty(),
                    "{}: {marker}",
                    boundary.path
                );
            }
        }
    }

    #[test]
    fn accidental_base_runtime_coupling_fails() {
        for boundary in BOUNDARIES {
            for marker in boundary.forbidden {
                let changed = format!("{}\n{marker}", fixture(boundary));
                assert!(
                    !violations(boundary, &changed).is_empty(),
                    "{}: {marker}",
                    boundary.path
                );
            }
        }
    }

    #[test]
    fn comments_and_tests_cannot_replace_production_wiring() {
        for boundary in BOUNDARIES {
            let markers = fixture(boundary);
            let prefix = if boundary.path.ends_with(".rs") {
                "//"
            } else {
                "#"
            };
            let comments = markers
                .lines()
                .map(|line| format!("{prefix} {line}\n"))
                .collect::<String>();
            assert!(!violations(boundary, &comments).is_empty());
            if boundary.path.ends_with(".rs") {
                let tests = format!("#[cfg(test)]\nmod tests {{\n{markers}\n}}");
                assert!(!violations(boundary, &tests).is_empty());
            }
            for marker in boundary.required {
                let missing = markers.replace(marker, "");
                let comments = [
                    format!("/* {marker} */"),
                    format!("/* outer /* {marker} */ still a comment */"),
                    format!("unrelated(); {prefix} {marker}"),
                ];
                for comment in comments {
                    assert!(
                        !violations(boundary, &format!("{missing}\n{comment}")).is_empty(),
                        "{} comment supplied witness {marker}",
                        boundary.path
                    );
                }
            }
        }
    }

    #[test]
    fn literal_arguments_survive_comment_blanking() {
        for boundary in BOUNDARIES {
            assert!(violations(boundary, &fixture(boundary)).is_empty());
            for marker in boundary.forbidden {
                let quoted = format!("{}\n\"# {marker}\"", fixture(boundary));
                assert!(!violations(boundary, &quoted).is_empty());
                let commented = format!("{}\n/* {marker} */", fixture(boundary));
                assert!(violations(boundary, &commented).is_empty());
            }
        }
        let boundary = &BOUNDARIES[1];
        let source = "value = \"# not a comment\"; # actual comment\n";
        assert!(production_source(boundary, source).contains("\"# not a comment\""));
        assert!(!production_source(boundary, source).contains("actual comment"));
    }

    #[test]
    fn nix_delimiters_inside_shell_comments_cannot_supply_missing_witnesses() {
        let boundary = &BOUNDARIES[1];
        let missing = fixture(boundary).replace("runtimeLean = true;", "");
        for script in [
            "script = ''# a shell comment'';",
            "script = ''# escaped ''${unfinished'';",
            "script = ''# escaped ''${unfinished\n'';",
            "script = ''# ${\"interpolation\"} shell comment'';",
        ] {
            let source = format!("{missing}\n{script}\n/* runtimeLean = true; */");
            assert!(
                !violations(boundary, &source).is_empty(),
                "comment supplied missing runtimeLean witness: {script}"
            );
            let live = format!("{source}\nruntimeLean = true;");
            assert!(violations(boundary, &live).is_empty(), "{script}");
        }
    }

    #[test]
    fn current_workspace_has_the_split_runtime_boundary() {
        run(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()).unwrap();
    }
}
