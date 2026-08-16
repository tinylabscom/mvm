//! The Rust-owned declarative registry of SDK constructors.
//!
//! This is the artifact the WS-1 spike concluded was needed. The
//! constructors in [`crate::ctor`] cannot be the source of truth for the
//! language SDKs: Rust discharges statically what Python and TypeScript
//! must check at runtime, so `port: u16` carries no recoverable
//! `1..=65535`, and a default living in a sibling function
//! (`python_deps` → `python_deps_with(.., Uv)`) is not the same fact as
//! Python's `tool="uv"` keyword default.
//!
//! So each constructor is declared here as data — parameters, defaults,
//! **constraints**, and what it builds — and every emitter decides for
//! itself whether a constraint is discharged by the target language's
//! type system or needs a runtime check. Rust's own `ctor` functions
//! stay hand-written; a coverage gate binds them to this registry.
//!
//! Constraint messages are stored verbatim rather than derived. The two
//! existing enum messages disagree in shape — one reads "'uv' or
//! 'pip-tools'", the other "'pnpm' / 'npm' / 'yarn'" — and inventing a
//! rule that produces both would be fiction. Storing them makes the
//! inconsistency visible and keeps the generated Python byte-compatible
//! with the hand-written code it replaces.

use crate::env::Surface;

/// A parameter's language-neutral type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamType {
    /// A string.
    Str,
    /// An integer.
    Int,
    /// A homogeneous list of the named IR type.
    ListOf(&'static str),
}

/// A literal default value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Literal {
    /// Integer literal.
    Int(i64),
    /// String literal.
    Str(&'static str),
}

/// A runtime check the dynamic SDKs must perform. Rust discharges each
/// of these through its type system, which is exactly why they cannot be
/// recovered from the Rust source and must be declared.
#[derive(Debug, Clone, Copy)]
pub enum Constraint {
    /// The value must not be empty.
    NonEmpty {
        /// Verbatim error message.
        message: &'static str,
    },
    /// The value must satisfy `min < value < max` — expressed exclusive
    /// because that is how the Python source reads (`0 < port < 65536`).
    IntExclusiveRange {
        /// Exclusive lower bound.
        min: i64,
        /// Exclusive upper bound.
        max: i64,
        /// Error message; `{value}` is replaced per-language.
        message: &'static str,
    },
    /// The value must be one of `canonical`, after applying `aliases`.
    EnumMember {
        /// Accepted canonical values.
        canonical: &'static [&'static str],
        /// `(alias, canonical)` rewrites applied before the check.
        aliases: &'static [(&'static str, &'static str)],
        /// Error message; `{value}` is replaced per-language.
        message: &'static str,
    },
}

/// One constructor parameter.
#[derive(Debug, Clone, Copy)]
pub struct Param {
    /// Parameter name, identical in every language.
    pub name: &'static str,
    /// Language-neutral type.
    pub ty: ParamType,
    /// Default, if the parameter is optional.
    pub default: Option<Literal>,
    /// Whether Python takes this keyword-only.
    ///
    /// Python-only, like [`crate::error_taxonomy::ErrorBase::Warning`]:
    /// TypeScript has no keyword-only parameters, so its emitter renders
    /// these positionally. Recorded rather than dropped silently, because
    /// it is a real property of the Python surface.
    pub kw_only: bool,
    /// Runtime checks, in the order the hand-written code applies them.
    pub constraints: &'static [Constraint],
}

/// How a field of the constructed value is produced.
#[derive(Debug, Clone, Copy)]
pub enum FieldValue {
    /// The parameter, passed through.
    Param(&'static str),
    /// A copy of the parameter as a list.
    ParamList(&'static str),
    /// The parameter resolved into a member of the named IR enum union,
    /// after alias canonicalisation.
    ParamEnum {
        /// Source parameter.
        param: &'static str,
        /// IR union alias to resolve against.
        enum_type: &'static str,
    },
}

/// What a constructor builds.
#[derive(Debug, Clone, Copy)]
pub enum Target {
    /// A plain IR struct.
    Struct {
        /// IR type name.
        name: &'static str,
    },
    /// A tagged-union variant, selected by discriminant.
    Variant {
        /// IR union alias.
        union: &'static str,
        /// The `kind` value identifying the variant.
        discriminant: &'static str,
    },
}

/// One constructor in the SDK surface.
#[derive(Debug, Clone, Copy)]
pub struct Ctor {
    /// Function name, identical in every language.
    pub name: &'static str,
    /// One-line description rendered as a doc comment.
    pub doc: &'static str,
    /// Parameters, in positional order.
    pub params: &'static [Param],
    /// What it constructs.
    pub target: Target,
    /// Field name → how to produce it. The discriminant is implicit.
    pub fields: &'static [(&'static str, FieldValue)],
    /// Surfaces that carry this constructor.
    pub surfaces: &'static [Surface],
}

impl Ctor {
    /// Whether this constructor is emitted for `surface`.
    pub fn exports_to(&self, surface: Surface) -> bool {
        let mut i = 0;
        while i < self.surfaces.len() {
            if self.surfaces[i] as u8 == surface as u8 {
                return true;
            }
            i += 1;
        }
        false
    }
}

const ALL: &[Surface] = &[Surface::Rust, Surface::Python, Surface::TypeScript];

/// Every generated constructor.
pub const REGISTRY: &[Ctor] = &[
    Ctor {
        name: "host_port",
        doc: "A concrete host:port destination for an egress allowlist entry.",
        params: &[
            Param {
                name: "host",
                ty: ParamType::Str,
                default: None,
                kw_only: false,
                constraints: &[Constraint::NonEmpty {
                    message: "host_port host must be a non-empty string",
                }],
            },
            Param {
                name: "port",
                ty: ParamType::Int,
                default: None,
                kw_only: false,
                constraints: &[Constraint::IntExclusiveRange {
                    min: 0,
                    max: 65536,
                    message: "host_port port must be in 1..65535, got {value}",
                }],
            },
        ],
        target: Target::Struct { name: "HostPort" },
        fields: &[
            ("host", FieldValue::Param("host")),
            ("port", FieldValue::Param("port")),
        ],
        surfaces: ALL,
    },
    Ctor {
        name: "egress",
        doc: "Declare an egress allowlist. Each entry is a concrete host:port the \
              guest may dial; an empty list means no egress.",
        params: &[Param {
            name: "allowlist",
            ty: ParamType::ListOf("HostPort"),
            default: None,
            kw_only: false,
            constraints: &[],
        }],
        target: Target::Struct {
            name: "NetworkEgress",
        },
        fields: &[("allowlist", FieldValue::ParamList("allowlist"))],
        surfaces: ALL,
    },
    Ctor {
        name: "dns_none",
        doc: "No DNS resolver. Use when contacts are by IP literal only.",
        params: &[],
        target: Target::Variant {
            union: "NetworkDns",
            discriminant: "none",
        },
        fields: &[],
        surfaces: ALL,
    },
    Ctor {
        name: "dns_system",
        doc: "Inherit the substrate's default resolver.",
        params: &[],
        target: Target::Variant {
            union: "NetworkDns",
            discriminant: "system",
        },
        fields: &[],
        surfaces: ALL,
    },
    Ctor {
        name: "dns_resolver",
        doc: "Pin DNS resolution to a specific resolver host:port.",
        params: &[
            Param {
                name: "host",
                ty: ParamType::Str,
                default: None,
                kw_only: false,
                constraints: &[Constraint::NonEmpty {
                    message: "dns_resolver host must be a non-empty string",
                }],
            },
            Param {
                name: "port",
                ty: ParamType::Int,
                // Python defaults this to the DNS port; Rust requires it
                // explicitly. The default is a fact about the dynamic
                // surfaces, so it lives here rather than being inferred.
                default: Some(Literal::Int(53)),
                kw_only: false,
                constraints: &[],
            },
        ],
        target: Target::Variant {
            union: "NetworkDns",
            discriminant: "resolver",
        },
        fields: &[
            ("host", FieldValue::Param("host")),
            ("port", FieldValue::Param("port")),
        ],
        surfaces: ALL,
    },
    Ctor {
        name: "no_deps",
        doc: "Declare that the workload has no runtime dependencies beyond the \
              language standard library.",
        params: &[],
        target: Target::Variant {
            union: "Dependencies",
            discriminant: "none",
        },
        fields: &[],
        surfaces: ALL,
    },
    Ctor {
        name: "python_deps",
        doc: "Declare Python runtime dependencies. `lockfile` is interpreted \
              relative to the app source path.",
        params: &[
            Param {
                name: "lockfile",
                ty: ParamType::Str,
                default: None,
                kw_only: true,
                constraints: &[Constraint::NonEmpty {
                    message: "python_deps lockfile must be a non-empty string",
                }],
            },
            Param {
                name: "tool",
                ty: ParamType::Str,
                default: Some(Literal::Str("uv")),
                kw_only: true,
                constraints: &[Constraint::EnumMember {
                    canonical: &["uv", "pip_tools"],
                    aliases: &[("pip-tools", "pip_tools")],
                    message: "python_deps tool must be 'uv' or 'pip-tools', got {value}",
                }],
            },
        ],
        target: Target::Variant {
            union: "Dependencies",
            discriminant: "python",
        },
        fields: &[
            ("lockfile", FieldValue::Param("lockfile")),
            (
                "tool",
                FieldValue::ParamEnum {
                    param: "tool",
                    enum_type: "PythonTool",
                },
            ),
        ],
        surfaces: ALL,
    },
    Ctor {
        name: "node_deps",
        doc: "Declare Node runtime dependencies. `lockfile` is interpreted \
              relative to the app source path.",
        params: &[
            Param {
                name: "lockfile",
                ty: ParamType::Str,
                default: None,
                kw_only: true,
                constraints: &[Constraint::NonEmpty {
                    message: "node_deps lockfile must be a non-empty string",
                }],
            },
            Param {
                name: "tool",
                ty: ParamType::Str,
                default: Some(Literal::Str("pnpm")),
                kw_only: true,
                constraints: &[Constraint::EnumMember {
                    canonical: &["pnpm", "npm", "yarn"],
                    aliases: &[],
                    // Note the shape differs from python_deps' message.
                    // Stored verbatim rather than derived; see the module
                    // note.
                    message: "node_deps tool must be 'pnpm' / 'npm' / 'yarn', got {value}",
                }],
            },
        ],
        target: Target::Variant {
            union: "Dependencies",
            discriminant: "node",
        },
        fields: &[
            ("lockfile", FieldValue::Param("lockfile")),
            (
                "tool",
                FieldValue::ParamEnum {
                    param: "tool",
                    enum_type: "NodeTool",
                },
            ),
        ],
        surfaces: ALL,
    },
];

/// The registry rows `surface` carries, in declaration order.
pub fn exported_to(surface: Surface) -> impl Iterator<Item = &'static Ctor> {
    REGISTRY.iter().filter(move |c| c.exports_to(surface))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn names_are_unique() {
        let mut seen = BTreeSet::new();
        for c in REGISTRY {
            assert!(seen.insert(c.name), "duplicate constructor {}", c.name);
        }
    }

    #[test]
    fn every_field_references_a_declared_param() {
        for c in REGISTRY {
            let params: BTreeSet<&str> = c.params.iter().map(|p| p.name).collect();
            for (field, value) in c.fields {
                let referenced = match value {
                    FieldValue::Param(p) | FieldValue::ParamList(p) => *p,
                    FieldValue::ParamEnum { param, .. } => *param,
                };
                assert!(
                    params.contains(referenced),
                    "{}: field {field} references unknown param {referenced}",
                    c.name
                );
            }
        }
    }

    #[test]
    fn required_params_precede_defaulted_ones() {
        // Python and TypeScript both reject a required parameter after an
        // optional one, so a registry in the wrong order would emit source
        // that does not parse.
        for c in REGISTRY {
            let mut seen_default = false;
            for p in c.params {
                if p.default.is_some() {
                    seen_default = true;
                } else {
                    assert!(
                        !seen_default,
                        "{}: required param {} follows a defaulted one",
                        c.name, p.name
                    );
                }
            }
        }
    }

    #[test]
    fn a_constraint_message_names_its_constructor() {
        // The messages are user-facing and byte-compared against the
        // hand-written originals; each begins with the function name.
        for c in REGISTRY {
            for p in c.params {
                for constraint in p.constraints {
                    let message = match constraint {
                        Constraint::NonEmpty { message } => *message,
                        Constraint::IntExclusiveRange { message, .. } => *message,
                        Constraint::EnumMember { message, .. } => *message,
                    };
                    assert!(
                        message.starts_with(c.name),
                        "{}: message {message:?} does not name the constructor",
                        c.name
                    );
                }
            }
        }
    }

    #[test]
    fn enum_aliases_resolve_to_a_canonical_value() {
        for c in REGISTRY {
            for p in c.params {
                for constraint in p.constraints {
                    if let Constraint::EnumMember {
                        canonical, aliases, ..
                    } = constraint
                    {
                        for (alias, target) in *aliases {
                            assert!(
                                canonical.contains(target),
                                "{}: alias {alias} maps to non-canonical {target}",
                                c.name
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_value_placeholder_appears_only_where_a_value_exists() {
        // `{value}` is substituted per-language; NonEmpty messages do not
        // interpolate, matching the hand-written originals.
        for c in REGISTRY {
            for p in c.params {
                for constraint in p.constraints {
                    if let Constraint::NonEmpty { message } = constraint {
                        assert!(
                            !message.contains("{value}"),
                            "{}: NonEmpty message interpolates a value",
                            c.name
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn tier_a_is_complete() {
        let names: BTreeSet<&str> = REGISTRY.iter().map(|c| c.name).collect();
        for expected in [
            "host_port",
            "egress",
            "dns_none",
            "dns_system",
            "dns_resolver",
            "no_deps",
            "python_deps",
            "node_deps",
        ] {
            assert!(names.contains(expected), "Tier A is missing {expected}");
        }
    }
}
