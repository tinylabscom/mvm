//! Compiling an upstream tool namespace into capabilities admission can bind.
//!
//! A dynamic tool namespace — Model Context Protocol and its equivalents — is
//! admitted host-side only. The host runs the client; the
//! guest never speaks the protocol outward. This module is the seam where what
//! an upstream server *says* it offers becomes what this host is willing to
//! bind, and it is deliberately pure: no transport, no I/O, no clock.
//!
//! # Why compilation happens once, at admission
//!
//! Everything downstream keys off the descriptor digest. Compiling once and
//! binding the result is what makes an upstream server unable to widen a guest
//! that is already running: a server that adds, renames, or redefines a tool
//! afterwards produces a different descriptor set, which is a different digest,
//! which the running admission does not carry. The guest's catalog is derived
//! from the admission, so it simply does not move.
//!
//! # Why an unrepresentable name is refused rather than repaired
//!
//! Upstream chooses its own names. This host's verbs are `[a-z0-9_-]`. The
//! tempting repair is to lowercase and substitute, and it is the one thing this
//! module must not do: `getWeather`, `get_weather` and `Get Weather` all
//! collapse to the same repaired verb, and collapsing two upstream tools onto
//! one capability merges their authority. A name this host cannot represent
//! exactly is a refusal.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::agent_capability::{
    CapabilityDescriptor, CapabilityError, CapabilityId, CapabilityLimits, MAX_DESCRIPTION_BYTES,
    SchemaRef,
};
use super::broker::ServiceId;

/// How many tools one upstream namespace may contribute.
///
/// A guest's catalog is read into a model's context, so an unbounded namespace
/// is a denial of service against the planner as much as against the host.
pub const MAX_UPSTREAM_TOOLS: usize = 64;

/// One tool as an upstream server describes it, before this host has agreed to
/// anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamTool {
    /// The name upstream chose. Must already be a verb this host can represent.
    pub name: String,
    /// Upstream's human-readable description. Data, never an identifier.
    pub description: String,
    /// Input schema reference.
    pub input_schema: SchemaRef,
    /// Output schema reference.
    pub output_schema: SchemaRef,
}

/// A namespace of upstream tools, fetched once at admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamNamespace {
    /// The host-side service every tool in this namespace compiles under.
    pub service: ServiceId,
    /// The tools upstream advertised.
    pub tools: Vec<UpstreamTool>,
}

/// Why an upstream namespace was not admitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamCompileError {
    /// The namespace advertised more tools than a catalog may carry.
    TooManyTools {
        /// How many were advertised.
        count: usize,
    },
    /// A name this host cannot represent as a verb. Not repaired: see the
    /// module docs.
    NameNotRepresentable {
        /// The offending upstream name.
        name: String,
    },
    /// Two tools claimed the same verb. Refused rather than last-one-wins,
    /// which would silently pick which authority survives.
    DuplicateVerb {
        /// The verb claimed twice.
        verb: String,
    },
    /// A description outside the bound a descriptor may carry.
    DescriptionOutOfBounds {
        /// The tool whose description was refused.
        name: String,
    },
}

/// Compile an upstream namespace into the descriptors admission will bind.
///
/// The output is sorted by verb so the same namespace always compiles to the
/// same bytes: admission binds a digest, and a digest that depended on upstream
/// ordering would make an identical namespace admit differently run to run.
///
/// # Errors
///
/// Refuses the whole namespace rather than dropping the offending tool. A
/// partial namespace is one an operator did not review.
pub fn compile_namespace(
    namespace: &UpstreamNamespace,
    limits: CapabilityLimits,
) -> Result<Vec<CapabilityDescriptor>, UpstreamCompileError> {
    if namespace.tools.len() > MAX_UPSTREAM_TOOLS {
        return Err(UpstreamCompileError::TooManyTools {
            count: namespace.tools.len(),
        });
    }

    let mut descriptors: Vec<CapabilityDescriptor> = Vec::new();
    for tool in &namespace.tools {
        if tool.description.is_empty() || tool.description.len() > MAX_DESCRIPTION_BYTES {
            return Err(UpstreamCompileError::DescriptionOutOfBounds {
                name: tool.name.clone(),
            });
        }
        // Reuse the verb rule rather than restating it: two spellings of the
        // same rule drift, and the drift is invisible until one is wrong.
        let id =
            CapabilityId::new(namespace.service.clone(), tool.name.clone()).map_err(|error| {
                match error {
                    CapabilityError::EmptyVerb | CapabilityError::InvalidVerb => {
                        UpstreamCompileError::NameNotRepresentable {
                            name: tool.name.clone(),
                        }
                    }
                    _ => UpstreamCompileError::NameNotRepresentable {
                        name: tool.name.clone(),
                    },
                }
            })?;
        if descriptors.iter().any(|existing| existing.id == id) {
            return Err(UpstreamCompileError::DuplicateVerb {
                verb: tool.name.clone(),
            });
        }
        let descriptor = CapabilityDescriptor::builder()
            .id(id)
            .description(tool.description.clone())
            .input_schema(tool.input_schema.clone())
            .output_schema(tool.output_schema.clone())
            .limits(limits)
            .build()
            .map_err(|_| UpstreamCompileError::DescriptionOutOfBounds {
                name: tool.name.clone(),
            })?;
        descriptors.push(descriptor);
    }
    descriptors.sort_by(|a, b| a.id.verb.cmp(&b.id.verb));
    Ok(descriptors)
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;

    fn limits() -> CapabilityLimits {
        CapabilityLimits::new(1024, 1024, 5_000).expect("limits")
    }

    fn tool(name: &str) -> UpstreamTool {
        UpstreamTool {
            name: name.to_string(),
            description: "an upstream tool".to_string(),
            input_schema: SchemaRef::new("upstream.in.v1", [7; 32]).expect("schema"),
            output_schema: SchemaRef::new("upstream.out.v1", [8; 32]).expect("schema"),
        }
    }

    fn namespace(names: &[&str]) -> UpstreamNamespace {
        UpstreamNamespace {
            service: ServiceId::parse("host.upstream.v1").expect("service"),
            tools: names.iter().map(|n| tool(n)).collect(),
        }
    }

    #[test]
    fn a_namespace_compiles_to_one_descriptor_per_tool() {
        let compiled = compile_namespace(&namespace(&["search", "fetch_page"]), limits())
            .expect("a well-formed namespace compiles");
        let verbs: Vec<&str> = compiled.iter().map(|d| d.id.verb.as_str()).collect();
        assert_eq!(verbs, vec!["fetch_page", "search"]);
    }

    #[test]
    fn compilation_is_order_independent_so_the_digest_is_stable() {
        let one = compile_namespace(&namespace(&["search", "fetch_page"]), limits()).expect("one");
        let other =
            compile_namespace(&namespace(&["fetch_page", "search"]), limits()).expect("two");
        assert_eq!(
            one, other,
            "admission binds a digest; upstream ordering must not change it"
        );
    }

    #[test]
    fn a_name_this_host_cannot_represent_is_refused_not_repaired() {
        for bad in ["getWeather", "Get Weather", "search!", ""] {
            let err = compile_namespace(&namespace(&[bad]), limits())
                .expect_err("an unrepresentable name is refused");
            assert!(
                matches!(err, UpstreamCompileError::NameNotRepresentable { .. }),
                "{bad} produced {err:?}"
            );
        }
    }

    #[test]
    fn two_tools_claiming_one_verb_refuse_the_namespace() {
        let err = compile_namespace(&namespace(&["search", "search"]), limits())
            .expect_err("a duplicate verb is refused");
        assert!(
            matches!(err, UpstreamCompileError::DuplicateVerb { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn an_unbounded_namespace_is_refused() {
        let names: Vec<String> = (0..=MAX_UPSTREAM_TOOLS)
            .map(|i| alloc::format!("tool_{i}"))
            .collect();
        let refs: Vec<&str> = names.iter().map(|n| n.as_str()).collect();
        let err = compile_namespace(&namespace(&refs), limits())
            .expect_err("a catalog is read into a context window; it is bounded");
        assert!(
            matches!(err, UpstreamCompileError::TooManyTools { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn an_oversized_description_is_refused() {
        let mut ns = namespace(&["search"]);
        ns.tools[0].description = "x".repeat(MAX_DESCRIPTION_BYTES + 1);
        let err = compile_namespace(&ns, limits()).expect_err("bounded");
        assert!(
            matches!(err, UpstreamCompileError::DescriptionOutOfBounds { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_namespace_that_gains_a_tool_compiles_to_different_bindings() {
        let before = compile_namespace(&namespace(&["search"]), limits()).expect("before");
        let after =
            compile_namespace(&namespace(&["search", "exfiltrate"]), limits()).expect("after");

        let before_bindings: Vec<_> = before.iter().map(|d| d.binding()).collect();
        let after_bindings: Vec<_> = after.iter().map(|d| d.binding()).collect();
        assert_ne!(
            before_bindings, after_bindings,
            "an upstream server that grows a tool must not be able to widen an admission \
             already in flight"
        );
        assert!(
            !before_bindings
                .iter()
                .any(|b| b.capability.verb == "exfiltrate"),
            "the earlier admission never carried the new tool"
        );
    }

    #[test]
    fn a_refused_namespace_yields_nothing_rather_than_a_partial_set() {
        let err = compile_namespace(&namespace(&["search", "Get Weather"]), limits());
        assert!(
            err.is_err(),
            "one bad tool refuses the namespace; a partial set is one nobody reviewed"
        );
    }
}
