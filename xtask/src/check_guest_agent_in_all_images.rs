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
        path: "crates/mvm-builder-guest/src/bin/mvm-host-vm-init.rs",
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
        required: &["init::early_setup();", "bind_listener(cfg.port)"],
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
    if boundary.path == "crates/mvm-agentd/src/bin/mvm-guest-agent.rs"
        && !activation_adapter_connected(&source)
    {
        errors.push(format!(
            "{} disconnects native activation from the production dispatcher or its original arguments",
            boundary.path
        ));
    }
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

fn path_is(expression: &syn::Expr, names: &[&str]) -> bool {
    matches!(expression, syn::Expr::Path(path)
        if path.qself.is_none()
            && path.path.segments.len() == names.len()
            && path.path.segments.iter().zip(names).all(|(part, name)| part.ident == *name))
}

fn first_expression(block: &syn::Block) -> Option<&syn::Expr> {
    match block.stmts.first()? {
        syn::Stmt::Expr(expression, _) => Some(expression),
        _ => None,
    }
}

fn activation_arm(expression: &syn::Expr) -> bool {
    match expression {
        syn::Expr::Match(dispatch) if path_is(&dispatch.expr, &["req"]) => {
            dispatch.arms.iter().any(|arm| {
                let syn::Pat::TupleStruct(pattern) = &arm.pat else {
                    return false;
                };
                if pattern.path.segments.len() != 2
                    || pattern.path.segments[0].ident != "GuestRequest"
                    || pattern.path.segments[1].ident != "ActivateEnvironment"
                    || !matches!(pattern.elems.first(), Some(syn::Pat::Ident(binding)) if binding.ident == "env")
                {
                    return false;
                }
                let syn::Expr::Block(body) = arm.body.as_ref() else {
                    return false;
                };
                let Some(syn::Expr::Match(response)) = first_expression(&body.block) else {
                    return false;
                };
                let syn::Expr::MethodCall(call) = response.expr.as_ref() else {
                    return false;
                };
                call.method == "activate"
                    && path_is(&call.receiver, &["operations"])
                    && call.args.len() == 2
                    && matches!(&call.args[0], syn::Expr::Reference(environment)
                        if path_is(&environment.expr, &["env"]))
                    && path_is(&call.args[1], &["boot_state"])
            })
        }
        syn::Expr::Block(block) => block_has_activation(&block.block),
        syn::Expr::Loop(loop_) => block_has_activation(&loop_.body),
        syn::Expr::If(branch) => {
            block_has_activation(&branch.then_branch)
                || branch.else_branch.as_ref().is_some_and(|(_, next)| activation_arm(next))
        }
        _ => false,
    }
}

fn block_has_activation(block: &syn::Block) -> bool {
    block.stmts.iter().any(|statement| match statement {
        syn::Stmt::Expr(expression, _) => activation_arm(expression),
        syn::Stmt::Local(local) => local
            .init
            .as_ref()
            .is_some_and(|init| activation_arm(&init.expr)),
        _ => false,
    })
}

/// Inspect the actual implementation and its two connected production callers,
/// not a free-floating marker, string, unrelated function, or test fixture.
fn activation_adapter_connected(source: &str) -> bool {
    let Ok(file) = syn::parse_file(source) else {
        return false;
    };
    let native = file.items.iter().any(|item| {
        let syn::Item::Impl(implementation) = item else { return false };
        if !matches!(&implementation.trait_, Some((_, path, _)) if path.is_ident("ControlOperations"))
            || !matches!(implementation.self_ty.as_ref(), syn::Type::Path(path) if path.path.is_ident("NativeControlOperations"))
        {
            return false;
        }
        implementation.items.iter().any(|item| {
            let syn::ImplItem::Fn(method) = item else { return false };
            if method.sig.ident != "activate" {
                return false;
            }
            let Some(syn::Expr::Try(attempt)) = first_expression(&method.block) else { return false };
            let syn::Expr::Call(call) = attempt.expr.as_ref() else { return false };
            path_is(&call.func, &["init", "apply_activation"])
                && call.args.len() == 2
                && path_is(&call.args[0], &["environment"])
                && path_is(&call.args[1], &["boot"])
        })
    });
    let client = file.items.iter().any(|item| {
        let syn::Item::Fn(function) = item else {
            return false;
        };
        if function.sig.ident != "handle_client" {
            return false;
        }
        let Some(syn::Stmt::Expr(syn::Expr::Call(call), _)) = function.block.stmts.last() else {
            return false;
        };
        path_is(&call.func, &["handle_client_operations"])
            && call.args.len() == 7
            && path_is(&call.args[4], &["boot_state"])
            && matches!(&call.args[6], syn::Expr::Reference(adapter)
                if adapter.mutability.is_some()
                    && path_is(&adapter.expr, &["NativeControlOperations"]))
    });
    let dispatch = file.items.iter().any(|item| {
        matches!(item, syn::Item::Fn(function)
            if function.sig.ident == "handle_client_operations"
                && block_has_activation(&function.block))
    });
    native && client && dispatch
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
        if boundary.path == "crates/mvm-agentd/src/bin/mvm-guest-agent.rs" {
            return r#"
fn main() { init::early_setup(); bind_listener(cfg.port); }
impl ControlOperations for NativeControlOperations {
    fn activate(&mut self, environment: &Environment, boot: &Boot) {
        init::apply_activation(environment, boot)?;
    }
}
fn handle_client() {
    handle_client_operations(file, state, integration, probe, boot_state, key, &mut NativeControlOperations);
}
fn handle_client_operations() {
    loop {
        let response = if mediated { other() } else {
            match req {
                GuestRequest::ActivateEnvironment(env) => {
                    match operations.activate(&env, boot_state) { Ok(()) => ack(), Err(_) => refusal() }
                }
                _ => other(),
            }
        };
    }
}
"#.into();
        }
        boundary.required.join("\n")
    }

    #[test]
    fn activation_adapter_requires_real_call_original_arguments_and_connected_dispatch() {
        let boundary = BOUNDARIES.last().unwrap();
        let good = fixture(boundary);
        assert!(violations(boundary, &good).is_empty());
        for (original, replacement) in [
            ("init::apply_activation(environment, boot)?;", "other()?;"),
            (
                "init::apply_activation(environment, boot)",
                "init::apply_activation(other, boot)",
            ),
            (
                "init::apply_activation(environment, boot)",
                "init::apply_activation(environment, other)",
            ),
            ("&mut NativeControlOperations", "&mut OtherOperations"),
            (
                "operations.activate(&env, boot_state)",
                "operations.activate(&other, boot_state)",
            ),
            (
                "operations.activate(&env, boot_state)",
                "operations.activate(&env, other)",
            ),
            (
                "operations.activate(&env, boot_state)",
                "other.activate(&env, boot_state)",
            ),
        ] {
            let changed = good.replace(original, replacement);
            let decoys = format!(
                "{changed}\nfn unrelated() {{ init::apply_activation(environment, boot)?; }}\n\
                 const DECOY: &str = \"operations.activate(&env, boot_state)\";"
            );
            assert!(!violations(boundary, &decoys).is_empty(), "{original}");
        }
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
