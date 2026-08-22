use crate::ir::addon::{AddonRef, AddonTier, AddonUse};
use crate::ir::data::parse_lines;
use crate::ir::error_codes::ErrorCode;
use crate::ir::version::{VersionError, validate_schema_version};
use crate::ir::workload::{
    Concurrency, Entrypoint, EnvValue, InProcessMode, JsonSchemaShape, NetworkDns, NetworkMode,
    PortProto, PortTransform, Resources, Source, WarmProcessConfig, Workload,
};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use serde::Serialize;

/// Field-name pattern for secret-shaped declarations.
/// Curated list lives in `data/secret_field_tokens.txt`; see that file
/// for the two tiers (auth credentials, financial/government
/// identifiers) and the rationale for what is and isn't included.
///
/// Parsed fresh on every call rather than cached behind a lazy static —
/// this crate is `no_std` and has no synchronization primitive to guard
/// a one-time init safely without `unsafe`. The list is tiny and
/// validation is not a hot path, so the reparse cost is immaterial.
fn secret_field_tokens() -> Vec<&'static str> {
    parse_lines(include_str!("../../data/secret_field_tokens.txt"))
}

/// Languages mvm currently has Nix factory dispatch for. The IR
/// field is an open string but the host validator rejects values
/// not in this list with
/// `E_UNSUPPORTED_LANGUAGE`. Curated list lives in
/// `data/supported_languages.txt`; adding a language is append-here,
/// plus a per-language Nix factory in `nix/factories/`, dispatch
/// from `flake.rs`, and a corpus entry. Parsed fresh on every call — see
/// [`secret_field_tokens`] for why this isn't a lazy static.
pub fn supported_languages() -> Vec<&'static str> {
    parse_lines(include_str!("../../data/supported_languages.txt"))
}

/// Recognize wildcard / "any" host strings in an egress allowlist.
/// Callers must enumerate concrete hosts.
fn is_wildcard_host(host: &str) -> bool {
    matches!(
        host.trim(),
        "*" | "0.0.0.0" | "::" | "0.0.0.0/0" | "::/0" | "[::]" | ""
    ) || host.contains("/0")
}

/// Check one place the host will originate a connection to on the guest's
/// behalf — an egress allowlist entry or a pinned DNS resolver.
///
/// Both name a destination, so both are meaningless with a wildcard or empty
/// host, and both are meaningless on port 0: the OS reads 0 as "any port", so
/// it authorizes nothing while looking like an authorization. `u16` is the
/// closest a Rust signature gets to `1..=65535`, which leaves the zero to this
/// layer — the one layer every language surface's document passes through, so
/// the answer cannot depend on which SDK built it.
fn validate_dialable_destination(
    host: &str,
    port: u16,
    what: &str,
    base: &str,
    errors: &mut Vec<ValidationError>,
) {
    if is_wildcard_host(host) {
        errors.push(ValidationError {
            code: ErrorCode::NetworkWildcard,
            path: format!("{base}.host"),
            detail: format!(
                "{what} host {host:?} is empty or a wildcard; name one concrete host. \
                 Hint: replace with an explicit FQDN or single IP (e.g. \
                 \"api.example.com\", \"10.0.1.5\"). Wildcards / CIDRs \
                 like \"0.0.0.0/0\", \"*\", \"::/0\" are rejected for \
                 deny-default safety (ADR-0004 §Phase 5)."
            ),
        });
    }
    if port == 0 {
        errors.push(ValidationError {
            code: ErrorCode::NetworkInvalidPort,
            path: format!("{base}.port"),
            detail: format!(
                "{what} port must be in 1..=65535, got 0. Hint: port 0 means \
                 \"any port\" to the operating system, so it authorizes nothing \
                 while reading as an authorization. Name the port the workload \
                 actually dials (e.g. 443)."
            ),
        });
    }
}

fn is_secret_field_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    secret_field_tokens().iter().any(|tok| {
        lower == *tok || lower.ends_with(&format!("_{tok}")) || lower.ends_with(&format!("-{tok}"))
    })
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ValidationError {
    pub code: ErrorCode,
    pub path: String,
    pub detail: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}: {}", self.code, self.path, self.detail)
    }
}

/// Identifier pattern enforced for `workload.id` and `apps[].name`.
/// Lowercase ASCII letter / digit / hyphen; must start with a letter
/// (so an id never looks like a CLI flag); max 63 chars (DNS label).
/// Identifiers flow into `mvmctl invoke <id>` argv positions; anything
/// outside this set could be misparsed by the substrate or downstream
/// tooling.
fn is_valid_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

pub fn validate(workload: &Workload) -> Result<(), Vec<ValidationError>> {
    let mut errors = Vec::new();

    if let Err(e) = validate_schema_version(&workload.schema_version) {
        errors.push(version_error(e));
    }

    if !is_valid_id(&workload.id) {
        errors.push(ValidationError {
            code: ErrorCode::InvalidId,
            path: ".id".to_string(),
            detail: format!(
                "workload.id must match ^[a-z][a-z0-9-]{{0,62}}$ (got {:?}). \
                 Hint: lowercase ASCII letter, then letters/digits/hyphens; \
                 e.g. \"hello-func\", \"math-svc\".",
                workload.id
            ),
        });
    }

    if workload.apps.is_empty() {
        errors.push(ValidationError {
            code: ErrorCode::EmptyApps,
            path: ".apps".to_string(),
            detail: "workload must declare at least one app. \
                     Hint: add a `@mv.app(...)` decorator (or call `mv.func({...})`) \
                     in the entry module before `mvm emit`."
                .to_string(),
        });
    } else if workload.apps.len() > 1 {
        errors.push(ValidationError {
            code: ErrorCode::MultiAppDeferred,
            path: ".apps".to_string(),
            detail: format!(
                "v0 accepts exactly one app per workload; found {}. \
                 Hint: split into separate workloads (one `mv.workload(id=...)` + \
                 one `mv.app(...)` per file), or wait for ADR-0014 multi-function apps.",
                workload.apps.len()
            ),
        });
    }

    for (i, app) in workload.apps.iter().enumerate() {
        let base = format!(".apps[{i}]");
        if !is_valid_id(&app.name) {
            errors.push(ValidationError {
                code: ErrorCode::InvalidId,
                path: format!("{base}.name"),
                detail: format!(
                    "app name must match ^[a-z][a-z0-9-]{{0,62}}$ (got {:?}). \
                     Hint: lowercase ASCII letter, then letters/digits/hyphens.",
                    app.name
                ),
            });
        }
        validate_source(&app.source, &base, &mut errors);
        validate_env(&app.env, &format!("{base}.env"), &mut errors);
        if app.entrypoints.is_empty() {
            errors.push(ValidationError {
                code: ErrorCode::EmptyApps,
                path: format!("{base}.entrypoints"),
                detail: "app must declare at least one entrypoint. \
                         Hint: pass `entrypoint=mv.entrypoint(...)` (single) or \
                         `entrypoints=[...]` (multi-function, ADR-0014)."
                    .to_string(),
            });
        }
        let function_entries: Vec<&Entrypoint> = app
            .entrypoints
            .iter()
            .filter(|ep| matches!(ep, Entrypoint::Function { .. }))
            .collect();
        let is_function_entrypoint = !function_entries.is_empty();
        // Multi-function uniqueness + primary-flag invariants.
        if function_entries.len() > 1 {
            let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
            for ep in &function_entries {
                if let Entrypoint::Function {
                    module, function, ..
                } = ep
                {
                    let key = (module.as_str(), function.as_str());
                    if !seen.insert(key) {
                        errors.push(ValidationError {
                            code: ErrorCode::DuplicateEntrypointFunction,
                            path: format!("{base}.entrypoints"),
                            detail: format!(
                                "duplicate (module, function) pair ({module:?}, \
                                 {function:?}) — function names must be unique \
                                 within an app. Hint: rename one of the functions, \
                                 or split them into separate apps."
                            ),
                        });
                    }
                }
            }
        }
        let primary_count = function_entries
            .iter()
            .filter(|ep| matches!(ep, Entrypoint::Function { primary: true, .. }))
            .count();
        if function_entries.len() > 1 && primary_count == 0 {
            errors.push(ValidationError {
                code: ErrorCode::NoPrimaryEntrypoint,
                path: format!("{base}.entrypoints"),
                detail: "multi-function app must mark exactly one entrypoint as \
                         primary (the default for `mvmctl invoke <id>` with no \
                         --fn selector). Hint: pass `primary=True` to one of the \
                         `entrypoint_function(...)` declarations, or use `mv.func()` \
                         which marks its single entrypoint primary by default."
                    .to_string(),
            });
        }
        if primary_count > 1 {
            errors.push(ValidationError {
                code: ErrorCode::MultiplePrimaryEntrypoints,
                path: format!("{base}.entrypoints"),
                detail: format!(
                    "{primary_count} entrypoints marked `primary = true`; exactly one \
                     is allowed. Hint: drop `primary=True` from all but one of the \
                     `entrypoint_function(...)` declarations."
                ),
            });
        }
        for (ep_idx, ep) in app.entrypoints.iter().enumerate() {
            let ep_path = if app.entrypoints.len() == 1 {
                format!("{base}.entrypoint")
            } else {
                format!("{base}.entrypoints[{ep_idx}]")
            };
            let entrypoint_env = match ep {
                Entrypoint::Command { env, .. } => env,
                Entrypoint::Function { env, .. } => env,
            };
            if let Entrypoint::Command { command, .. } = ep
                && let Some(shell) = crate::entrypoint::detect_shell_entrypoint_argv(command)
            {
                errors.push(ValidationError {
                    code: ErrorCode::ShellEntrypointForbidden,
                    path: format!("{ep_path}.command"),
                    detail: format!(
                        "production command entrypoints may not launch a shell ({:?}). \
                         Use a direct argv entrypoint such as `[\"python\", \"-m\", \"app\"]`, \
                         or use a dev image plus `machine run -it -- {}` for interactive shells.",
                        shell.shell, shell.shell
                    ),
                });
            }
            if let Entrypoint::Function {
                args_schema,
                return_schema,
                language,
                concurrency,
                ..
            } = ep
            {
                let supported_languages = supported_languages();
                if !supported_languages.contains(&language.as_str()) {
                    errors.push(ValidationError {
                        code: ErrorCode::UnsupportedLanguage,
                        path: format!("{ep_path}.language"),
                        detail: format!(
                            "language {language:?} has no Nix factory in mvm; \
                             supported: {:?}. \
                             Hint: pass `language=\"python\"` (or \"node\" / \"wasm\") \
                             to `entrypoint_function(...)`, or add a per-language \
                             factory at `nix/factories/mk<Lang>FunctionService.nix` \
                             and append to `SUPPORTED_LANGUAGES` per ADR-0010 §4.",
                            supported_languages
                        ),
                    });
                }
                if let Some(schema) = args_schema {
                    walk_schema_for_secrets(schema, &format!("{ep_path}.args_schema"), &mut errors);
                }
                if let Some(schema) = return_schema {
                    walk_schema_for_secrets(
                        schema,
                        &format!("{ep_path}.return_schema"),
                        &mut errors,
                    );
                }
                if let Some(concurrency) = concurrency {
                    validate_concurrency(
                        concurrency,
                        language,
                        &app.resources,
                        &format!("{ep_path}.concurrency"),
                        &mut errors,
                    );
                }
            }
            validate_env(entrypoint_env, &format!("{ep_path}.env"), &mut errors);
        }
        if let Some(network) = &app.network {
            if network.mode == NetworkMode::None && !network.ports.is_empty() {
                errors.push(ValidationError {
                    code: ErrorCode::NetworkPortsWithNone,
                    path: format!("{base}.network.ports"),
                    detail: "ports must be empty when network.mode is \"none\". \
                             Hint: drop the `ports=[...]` argument, or change \
                             `network=mv.network(mode=...)` to \"bridge\" / \"host\" \
                             (host is forbidden for function workloads)."
                        .to_string(),
                });
            }
            let mut mapping_ids = BTreeSet::new();
            let mut listener_binds = BTreeSet::new();
            for (index, mapping) in network.ports.iter().enumerate() {
                let path = format!("{base}.network.ports[{index}]");
                if mapping.mapping_id == 0 {
                    errors.push(ValidationError {
                        code: ErrorCode::IngressInvalidMapping,
                        path: format!("{path}.mapping_id"),
                        detail: "ingress mapping_id must be non-zero".to_string(),
                    });
                } else if !mapping_ids.insert(mapping.mapping_id) {
                    errors.push(ValidationError {
                        code: ErrorCode::IngressDuplicateMapping,
                        path: format!("{path}.mapping_id"),
                        detail: format!(
                            "ingress mapping_id {} is declared more than once",
                            mapping.mapping_id
                        ),
                    });
                }

                if mapping.host == 0 || mapping.guest == 0 {
                    errors.push(ValidationError {
                        code: ErrorCode::NetworkInvalidPort,
                        path: path.clone(),
                        detail: "ingress host and guest ports must be in 1..65535".to_string(),
                    });
                }
                if mapping.host_addr.parse::<core::net::IpAddr>().is_err() {
                    errors.push(ValidationError {
                        code: ErrorCode::IngressInvalidMapping,
                        path: format!("{path}.host_addr"),
                        detail: "ingress host_addr must be an exact IPv4 or IPv6 address"
                            .to_string(),
                    });
                }
                let bind = (mapping.proto, mapping.host_addr.as_str(), mapping.host);
                if !listener_binds.insert(bind) {
                    errors.push(ValidationError {
                        code: ErrorCode::IngressDuplicateBind,
                        path: path.clone(),
                        detail: "ingress protocol/address/port bind is declared more than once"
                            .to_string(),
                    });
                }
                let guest_loopback = mapping
                    .guest_addr
                    .parse::<core::net::IpAddr>()
                    .is_ok_and(|addr| addr.is_loopback());
                if !guest_loopback {
                    errors.push(ValidationError {
                        code: ErrorCode::IngressGuestNotLoopback,
                        path: format!("{path}.guest_addr"),
                        detail: "ingress guest_addr must be an exact loopback address".to_string(),
                    });
                }
                if mapping.proto == PortProto::Udp && mapping.transform != PortTransform::Opaque {
                    errors.push(ValidationError {
                        code: ErrorCode::IngressUnsupportedTransform,
                        path: format!("{path}.transform"),
                        detail: "UDP ingress supports only the explicit opaque transform class"
                            .to_string(),
                    });
                }
                match (mapping.transform, mapping.tls_secret.as_deref()) {
                    (PortTransform::Tls, Some("")) => {
                        errors.push(ValidationError {
                            code: ErrorCode::IngressInvalidMapping,
                            path: format!("{path}.tls_secret"),
                            detail: "TLS ingress secret reference must not be empty".to_string(),
                        });
                    }
                    (PortTransform::Tls, None) => errors.push(ValidationError {
                        code: ErrorCode::IngressInvalidMapping,
                        path: format!("{path}.tls_secret"),
                        detail: "TLS ingress requires a plan-bound PEM secret reference"
                            .to_string(),
                    }),
                    (PortTransform::Opaque | PortTransform::Http, Some(_)) => {
                        errors.push(ValidationError {
                            code: ErrorCode::IngressInvalidMapping,
                            path: format!("{path}.tls_secret"),
                            detail: "only TLS ingress may declare a PEM secret reference"
                                .to_string(),
                        });
                    }
                    (PortTransform::Tls, Some(_))
                    | (PortTransform::Opaque | PortTransform::Http, None) => {}
                }
            }
            if is_function_entrypoint && network.mode == NetworkMode::Host {
                errors.push(ValidationError {
                    code: ErrorCode::FunctionNetworkHostForbidden,
                    path: format!("{base}.network.mode"),
                    detail: "function-call workloads may not declare network.mode = \"host\". \
                             Hint: omit `network=` (function workloads default to deny-all), \
                             or set `mode=\"bridge\"` with a granular `egress` allowlist \
                             (per ADR-0004 §Phase 5)."
                        .to_string(),
                });
            }
            // The allowlist must enumerate concrete host:port pairs; CIDRs and
            // sentinel "any" hosts get rejected with E_NETWORK_WILDCARD.
            if let Some(egress) = &network.egress {
                for (j, hp) in egress.allowlist.iter().enumerate() {
                    validate_dialable_destination(
                        &hp.host,
                        hp.port,
                        "egress allowlist",
                        &format!("{base}.network.egress.allowlist[{j}]"),
                        &mut errors,
                    );
                }
            }
            // A pinned resolver is a destination like any other: the same
            // rule, at the same layer, so the two cannot drift apart.
            if let Some(NetworkDns::Resolver { host, port }) = &network.dns {
                validate_dialable_destination(
                    host,
                    *port,
                    "dns resolver",
                    &format!("{base}.network.dns"),
                    &mut errors,
                );
            }
            // Validate peer IDs against the workload-id pattern.
            for (j, peer) in network.peers.iter().enumerate() {
                if !is_valid_id(peer) {
                    errors.push(ValidationError {
                        code: ErrorCode::InvalidId,
                        path: format!("{base}.network.peers[{j}]"),
                        detail: format!(
                            "peer id must match ^[a-z][a-z0-9-]{{0,62}}$ (got {peer:?}). \
                             Hint: peer ids share the workload-id pattern. Check the \
                             callee workload's `id=` declaration."
                        ),
                    });
                }
            }
        }
        // Function workloads must declare their
        // dependency posture explicitly — either point at a hash-pinned
        // lockfile or declare `no_deps()` for stdlib-only workloads.
        // The actual lockfile-content check (hash-pinning) runs in the
        // host crate at compile/up time once the bundled tree is on
        // disk; this layer just enforces the declaration.
        if is_function_entrypoint && app.dependencies.is_none() {
            errors.push(ValidationError {
                code: ErrorCode::DepsRequiredForFunctionWorkload,
                path: format!("{base}.dependencies"),
                detail: "function-entrypoint workloads must declare apps[*].dependencies. \
                         Hint: pass `dependencies=mv.no_deps()` for stdlib-only workloads, \
                         or `mv.python_deps(lockfile=\"uv.lock\")` / `mv.node_deps(\
                         lockfile=\"pnpm-lock.yaml\")` pointing at a hash-pinned lockfile \
                         (ADR-0009 / plan-0008)."
                    .to_string(),
            });
        }
        validate_addons(&app.addons, &base, &mut errors);
    }

    for (i, volume) in workload.volumes.iter().enumerate() {
        if volume.persist {
            errors.push(ValidationError {
                code: ErrorCode::PersistDeferred,
                path: format!(".volumes[{i}].persist"),
                detail: "persistent volumes are not supported in v0. \
                         Hint: drop `persist=True`. Persistent storage will be \
                         covered by a future ADR; track via `specs/backlog/`."
                    .to_string(),
            });
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// Validate the warm-process concurrency config.
///
/// Cross-field rules:
/// - `pool_size ∈ [1, 64]` (mvm substrate sanity cap)
/// - `max_calls_per_worker >= 100` (smaller defeats the warm-tier benefit)
/// - `max_rss_mb <= app.resources.memory_mb` (a worker can't exceed VM memory)
/// - `in_process != Concurrent` (reserved for follow-up ADR)
/// - `language != "wasm"` (warm-process is Python/Node only in v0.2)
fn validate_concurrency(
    concurrency: &Concurrency,
    language: &str,
    resources: &Resources,
    base: &str,
    errors: &mut Vec<ValidationError>,
) {
    if language == "wasm" {
        errors.push(ValidationError {
            code: ErrorCode::UnsupportedConcurrencyForLanguage,
            path: base.to_string(),
            detail: format!(
                "concurrency is not supported for language {language:?}; \
                 warm-process is Python/Node only in v0.2 (ADR-0011). \
                 Hint: drop the `concurrency=` argument for wasm functions, \
                 or implement the wasm warm-process tier behind a follow-up \
                 ADR before enabling it here."
            ),
        });
    }
    let Concurrency::WarmProcess(WarmProcessConfig {
        max_calls_per_worker,
        max_rss_mb,
        pool_size,
        in_process,
        max_queue_depth: _,
    }) = concurrency;
    if !(1..=64).contains(pool_size) {
        errors.push(ValidationError {
            code: ErrorCode::InvalidConcurrencyPoolSize,
            path: format!("{base}.pool_size"),
            detail: format!(
                "pool_size must be in [1, 64] (got {pool_size}). \
                 Hint: 1 is the typical value for v0.2 (one worker per VM); \
                 raise it only when you understand mvm's worker-pool semantics. \
                 ADR-0011 caps at 64 to match the substrate sanity limit."
            ),
        });
    }
    if *max_calls_per_worker < 100 {
        errors.push(ValidationError {
            code: ErrorCode::InvalidConcurrencyMaxCallsPerWorker,
            path: format!("{base}.max_calls_per_worker"),
            detail: format!(
                "max_calls_per_worker must be >= 100 (got {max_calls_per_worker}). \
                 Hint: smaller values defeat the warm-tier benefit because per-call \
                 worker recycling cost dominates dispatch savings. ADR-0011 sets \
                 the floor at 100; pick higher (e.g. 1000) for steady-state workloads."
            ),
        });
    }
    if *max_rss_mb > u64::from(resources.memory_mb) {
        errors.push(ValidationError {
            code: ErrorCode::InvalidConcurrencyMaxRssMb,
            path: format!("{base}.max_rss_mb"),
            detail: format!(
                "max_rss_mb ({max_rss_mb}) exceeds app.resources.memory_mb ({}); \
                 a worker cannot exceed the VM's total memory budget. \
                 Hint: lower max_rss_mb, or raise resources.memory_mb to give the \
                 VM headroom for the worker plus mvm/agent overhead.",
                resources.memory_mb
            ),
        });
    }
    if *in_process == InProcessMode::Concurrent {
        errors.push(ValidationError {
            code: ErrorCode::UnsupportedConcurrencyInProcessMode,
            path: format!("{base}.in_process"),
            detail: "in_process = \"concurrent\" is reserved and not implemented in v0.2 \
                     (ADR-0011). \
                     Hint: use in_process = \"serial\" — concurrent in-process dispatch \
                     awaits a follow-up ADR covering async-safe wrapper recycling."
                .to_string(),
        });
    }
}

/// Validate the consumer-side `addons[]` field on an `App`.
///
/// IR-side rules — checks that don't require fetching the addon's manifest:
/// - `name` and `alias` (if present) match the workload-id pattern.
/// - `(name, alias)` pairs are unique within the list.
/// - `tier == InVm` is rejected with `E_ADDON_TIER_NOT_IMPLEMENTED`
///   (the in-VM addon tier is not yet implemented).
/// - `sha256` is 64 hex chars (basic format check; cryptographic
///   verification happens in `addon::resolve_and_validate`).
/// - `AddonRef::Registry { url, version }` has non-empty fields.
/// - `AddonRef::Local { path }` has a non-empty relative path.
///
/// Manifest-aware rules (param schema match, env-var collision content,
/// signature validation) live in `mvm::addon::resolve_and_validate`,
/// which has the lockfile + cached artifact bytes available.
fn validate_addons(addons: &[AddonUse], base: &str, errors: &mut Vec<ValidationError>) {
    let mut seen: BTreeSet<(&str, Option<&str>)> = BTreeSet::new();
    for (i, addon) in addons.iter().enumerate() {
        let path = format!("{base}.addons[{i}]");
        if !is_valid_id(&addon.name) {
            errors.push(ValidationError {
                code: ErrorCode::InvalidId,
                path: format!("{path}.name"),
                detail: format!(
                    "addon name must match ^[a-z][a-z0-9-]{{0,62}}$ (got {:?}). \
                     Hint: lowercase ASCII letter, then letters/digits/hyphens; \
                     mirrors the workload-id pattern.",
                    addon.name
                ),
            });
        }
        if let Some(alias) = &addon.alias
            && !is_valid_id(alias)
        {
            errors.push(ValidationError {
                code: ErrorCode::InvalidId,
                path: format!("{path}.alias"),
                detail: format!(
                    "addon alias must match ^[a-z][a-z0-9-]{{0,62}}$ (got {alias:?}). \
                     Hint: aliases prefix every env var the addon exports \
                     (ADR-0018 §Env-var prefixing rule); they must be valid \
                     identifiers."
                ),
            });
        }
        let key = (addon.name.as_str(), addon.alias.as_deref());
        if !seen.insert(key) {
            errors.push(ValidationError {
                code: ErrorCode::AddonEnvCollision,
                path: path.clone(),
                detail: format!(
                    "duplicate addon-use ({:?}, alias={:?}) — every (name, alias) \
                     pair within addons[] must be unique. Hint: pass distinct \
                     `as_=` aliases for multiple uses of the same addon (e.g. \
                     `as_=\"primary\"` and `as_=\"replica\"`).",
                    addon.name, addon.alias
                ),
            });
        }
        if matches!(addon.tier, AddonTier::InVm) {
            errors.push(ValidationError {
                code: ErrorCode::AddonTierNotImplemented,
                path: format!("{path}.tier"),
                detail: format!(
                    "addon tier {:?} is reserved but not implemented in v1. \
                     Hint: only `tier = \"separate\"` is supported today; \
                     in-VM addons land via `specs/plans/0012-in-vm-addon-tier.md`.",
                    addon.tier
                ),
            });
        }
        if !is_valid_sha256(&addon.sha256) {
            errors.push(ValidationError {
                code: ErrorCode::AddonShaMismatch,
                path: format!("{path}.sha256"),
                detail: format!(
                    "addon sha256 must be 64 lowercase hex characters (got {}). \
                     Hint: the lockfile-managed sha matches the canonical-form \
                     artifact bytes; run `mvm addon lock` to regenerate.",
                    addon.sha256
                ),
            });
        }
        match &addon.r#ref {
            AddonRef::Registry { url, version } => {
                if url.is_empty() {
                    errors.push(ValidationError {
                        code: ErrorCode::AddonNotFound,
                        path: format!("{path}.ref.url"),
                        detail: "registry addon-ref must declare a non-empty url. \
                                 Hint: e.g. `url = \"addons.mvm.io/postgres\"`."
                            .to_string(),
                    });
                }
                if version.is_empty() {
                    errors.push(ValidationError {
                        code: ErrorCode::AddonNotFound,
                        path: format!("{path}.ref.version"),
                        detail: "registry addon-ref must declare a non-empty version. \
                                 Hint: e.g. `version = \"16.1.0\"`. SemVer-shaped \
                                 strings are required at lock time; the IR carries \
                                 the resolved (not requested) version."
                            .to_string(),
                    });
                }
            }
            AddonRef::Local { path: p } => {
                if p.is_empty() {
                    errors.push(ValidationError {
                        code: ErrorCode::AddonLocalPathDrift,
                        path: format!("{path}.ref.path"),
                        detail: "local addon-ref must declare a non-empty path. \
                                 Hint: e.g. `path = \"./addons/my-db\"`."
                            .to_string(),
                    });
                }
            }
        }
    }
}

fn is_valid_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Walk a JSON Schema-shaped value and reject any field name (under
/// `properties`) that matches the secret pattern. Recurses through
/// nested objects, arrays (`items`), and combinators (`oneOf`).
fn walk_schema_for_secrets(
    schema: &JsonSchemaShape,
    base: &str,
    errors: &mut Vec<ValidationError>,
) {
    walk_schema_value(&serde_json::Value::Object(schema.0.clone()), base, errors);
}

fn walk_schema_value(value: &serde_json::Value, base: &str, errors: &mut Vec<ValidationError>) {
    let serde_json::Value::Object(map) = value else {
        return;
    };
    if let Some(serde_json::Value::Object(props)) = map.get("properties") {
        for (key, sub) in props {
            if is_secret_field_name(key) {
                errors.push(ValidationError {
                    code: ErrorCode::SecretInSchema,
                    path: format!("{base}.properties.{key}"),
                    detail: format!(
                        "schema field name {key:?} matches the secret pattern \
                         (token / password / secret / apikey / credential / \
                         bearer / privatekey / authtoken). \
                         Hint: rename the field, or accept the secret via \
                         `/run/mvm-secrets/<svc>/` and read it from disk inside \
                         the wrapper. Function args travel through argv → \
                         application memory and aren't a safe channel for secrets \
                         (ADR-0009)."
                    ),
                });
            }
            walk_schema_value(sub, &format!("{base}.properties.{key}"), errors);
        }
    }
    if let Some(items) = map.get("items") {
        walk_schema_value(items, &format!("{base}.items"), errors);
    }
    if let Some(serde_json::Value::Array(branches)) = map.get("oneOf") {
        for (i, branch) in branches.iter().enumerate() {
            walk_schema_value(branch, &format!("{base}.oneOf[{i}]"), errors);
        }
    }
    if let Some(serde_json::Value::Array(branches)) = map.get("anyOf") {
        for (i, branch) in branches.iter().enumerate() {
            walk_schema_value(branch, &format!("{base}.anyOf[{i}]"), errors);
        }
    }
}

fn validate_source(source: &Source, base: &str, errors: &mut Vec<ValidationError>) {
    match source {
        Source::LocalPath { .. } => {}
        Source::NixDerivation { .. } => errors.push(ValidationError {
            code: ErrorCode::SourceKindDeferred,
            path: format!("{base}.source.kind"),
            detail: "source kind \"nix_derivation\" is reserved for post-v0. \
                     Hint: use `source=mv.local_path(\".\")` to bundle a local \
                     source tree. Pinned-derivation sources will be covered \
                     by a future ADR."
                .to_string(),
        }),
        Source::OciImage { .. } => errors.push(ValidationError {
            code: ErrorCode::SourceKindDeferred,
            path: format!("{base}.source.kind"),
            detail: "source kind \"oci_image\" is reserved for post-v0. \
                     Hint: use `source=mv.local_path(\".\")` to bundle a local \
                     source tree. OCI image sources will be covered by a \
                     future ADR."
                .to_string(),
        }),
    }
}

fn validate_env(env: &BTreeMap<String, EnvValue>, base: &str, errors: &mut Vec<ValidationError>) {
    for (key, value) in env {
        // A SecretRef is admitted once it declares a destination
        // binding. claim 12: a secret with no allowed_hosts could be substituted
        // toward any host the egress endpoint reaches, so refuse the unbound one.
        // `auth_type` is a typed enum (always valid); `name` is required by the
        // decorator that produces it.
        if let EnvValue::SecretRef { reference } = value
            && reference.allowed_hosts.is_empty()
        {
            errors.push(ValidationError {
                code: ErrorCode::SecretWithoutBinding,
                path: format!("{base}.{key}"),
                detail: format!(
                    "secret {:?} declares no allowed_hosts — an unbound secret is a \
                     claim-12 violation. Add hosts (e.g. [\"api.example.com\"] or \
                     [\"*.example.com\"]).",
                    reference.name
                ),
            });
        }
    }
}

fn version_error(e: VersionError) -> ValidationError {
    let path = ".schema_version".to_string();
    match e {
        VersionError::UnsupportedMajor { found, supported } => ValidationError {
            code: ErrorCode::UnsupportedMajor,
            path,
            detail: format!(
                "found major {found}, host supports {supported}. \
                 Hint: align mvm and mvm-sdk versions — check the \
                 compatibility table in `docs/src/content/docs/reference/\
                 compatibility.md`. SDK upgrades are usually drop-in across \
                 a minor; majors require coordinated mvm + sdk + (sometimes) mvm bumps."
            ),
        },
        VersionError::MinorTooHigh { found, max } => ValidationError {
            code: ErrorCode::MinorTooHigh,
            path,
            detail: format!(
                "found minor {found}, host supports at most {max}. \
                 Hint: upgrade the `mvm` host CLI to a version that \
                 supports schema_version {found} (newer host, same SDK), \
                 or downgrade the SDK to one that emits schema_version {max}."
            ),
        },
        VersionError::Malformed(s) => ValidationError {
            code: ErrorCode::MalformedVersion,
            path,
            detail: format!(
                "malformed version string: {s:?}. \
                 Hint: schema_version follows MAJOR.MINOR (e.g. \"0.1\"). \
                 If you're hand-editing IR, mirror the SDK constant — \
                 `mvm.SCHEMA_VERSION` (Python) or `mv.SCHEMA_VERSION` (TS)."
            ),
        },
    }
}
