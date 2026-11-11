//! Ordered signed-pack references and separately selected launch commands.
//!
//! These are requests, not verified packs, a lock, a build result or permission
//! to launch. Consumers must verify each referenced manifest signature, digest,
//! publisher, revocation and compatibility before materializing the graph.
//! Neither a runtime nor a tool starts a service by being present in the graph.

use alloc::{collections::BTreeSet, string::String, vec::Vec};
use serde::{Deserialize, Serialize};

use crate::{
    pack_lock::lower_hex,
    pack_spec::{PackIdentity, PackTarget, relative_path},
};

/// New authored graph schema; existing v1 and v2 formats remain independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComposedGraphSchema {
    #[serde(rename = "mvm.pack-spec/v3")]
    V3,
}

/// A reference to the exact bytes of a signed registry manifest.
///
/// This does not attest to a valid signature: the consumer must verify it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPackPin {
    pub name: String,
    pub version: String,
    pub manifest_sha256: String,
}

impl SignedPackPin {
    /// Refuse ambiguous coordinates and non-canonical SHA-256 digests.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid name, version or digest.
    pub fn validate(&self) -> Result<(), ComposedGraphError> {
        PackIdentity {
            name: self.name.clone(),
            version: self.version.clone(),
        }
        .validate()
        .map_err(|_| ComposedGraphError::Pin)?;
        if self.version.contains('+') || !lower_hex(&self.manifest_sha256, 64) {
            return Err(ComposedGraphError::Pin);
        }
        Ok(())
    }
}

/// Ordered input layers. Entrypoints come from verified application manifests,
/// never from authored graph data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GraphNode {
    Application { pin: SignedPackPin },
    Runtime { pin: SignedPackPin },
    Tool { pin: SignedPackPin },
}

impl GraphNode {
    /// The pinned registry manifest for this layer.
    pub fn pin(&self) -> &SignedPackPin {
        match self {
            Self::Application { pin, .. } | Self::Runtime { pin } | Self::Tool { pin } => pin,
        }
    }
}

/// An ordered graph of explicitly named, digest-pinned registry packs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ComposedGraphWire")]
pub struct ComposedGraph {
    pub schema: ComposedGraphSchema,
    pub graph: Vec<GraphNode>,
}

/// One authored invocation binds the ordered graph, target and command request.
///
/// Base selection and host grants remain launch inputs, not pack declarations.
/// This document does not attest to publisher signatures or authorize a boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ComposedRunWire")]
pub struct ComposedRunRequest {
    pub schema: ComposedRunSchema,
    pub target: PackTarget,
    pub graph: ComposedGraph,
    pub entrypoint: EntrypointRequest,
}

/// The single-file invocation format for the v3 graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComposedRunSchema {
    #[serde(rename = "mvm.composed-run/v1")]
    V1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposedRunWire {
    schema: ComposedRunSchema,
    target: PackTarget,
    graph: ComposedGraph,
    entrypoint: EntrypointRequest,
}

impl TryFrom<ComposedRunWire> for ComposedRunRequest {
    type Error = ComposedGraphError;

    fn try_from(wire: ComposedRunWire) -> Result<Self, Self::Error> {
        let request = Self {
            schema: wire.schema,
            target: wire.target,
            graph: wire.graph,
            entrypoint: wire.entrypoint,
        };
        request.validate()?;
        Ok(request)
    }
}

impl ComposedRunRequest {
    /// Validate directly constructed invocations before acquiring any pack bytes.
    ///
    /// # Errors
    /// Refuses invalid graph pins or command requests.
    pub fn validate(&self) -> Result<(), ComposedGraphError> {
        self.graph.validate()?;
        self.entrypoint.validate()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposedGraphWire {
    schema: ComposedGraphSchema,
    graph: Vec<GraphNode>,
}

impl TryFrom<ComposedGraphWire> for ComposedGraph {
    type Error = ComposedGraphError;

    fn try_from(wire: ComposedGraphWire) -> Result<Self, Self::Error> {
        let graph = Self {
            schema: wire.schema,
            graph: wire.graph,
        };
        graph.validate()?;
        Ok(graph)
    }
}

/// The independent launch request schema; it cannot reinterpret a pack spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntrypointRequestSchema {
    #[serde(rename = "mvm.entrypoint-request/v1")]
    V1,
}

/// Optional, explicit command sources; neither a runtime nor a tool auto-starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "EntrypointRequestWire")]
pub struct EntrypointRequest {
    pub schema: EntrypointRequestSchema,
    /// Highest precedence, supplied by the runtime invocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_command_override: Option<Vec<String>>,
    /// User workload/config command, used when runtime did not override it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_command: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntrypointRequestWire {
    schema: EntrypointRequestSchema,
    #[serde(default)]
    runtime_command_override: Option<Vec<String>>,
    #[serde(default)]
    workload_command: Option<Vec<String>>,
}

impl TryFrom<EntrypointRequestWire> for EntrypointRequest {
    type Error = ComposedGraphError;

    fn try_from(wire: EntrypointRequestWire) -> Result<Self, Self::Error> {
        let request = Self {
            schema: wire.schema,
            runtime_command_override: wire.runtime_command_override,
            workload_command: wire.workload_command,
        };
        request.validate()?;
        Ok(request)
    }
}

/// Where the selected literal argv came from, without constructing a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectedEntrypoint<'a> {
    RuntimeOverride(&'a [String]),
    Workload(&'a [String]),
    Application {
        pin: &'a SignedPackPin,
        argv: &'a [String],
    },
}

/// Validation errors do not echo command arguments or registry coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ComposedGraphError {
    #[error("graph must contain between 1 and 128 layers including an application")]
    Graph,
    #[error("invalid or duplicate signed manifest pin")]
    Pin,
    #[error("pack kind conflicts with its registry namespace")]
    Kind,
    #[error("unsafe or empty launch command")]
    Command,
    #[error("could not serialize composed request")]
    Serialization,
}

impl ComposedGraph {
    /// Validate directly constructed graphs before use, including every layer.
    ///
    /// # Errors
    ///
    /// Refuses missing applications, duplicate names and mismatched kinds.
    pub fn validate(&self) -> Result<(), ComposedGraphError> {
        if self.graph.is_empty()
            || self.graph.len() > 128
            || !self
                .graph
                .iter()
                .any(|node| matches!(node, GraphNode::Application { .. }))
        {
            return Err(ComposedGraphError::Graph);
        }
        let mut names = BTreeSet::new();
        for node in &self.graph {
            let pin = node.pin();
            pin.validate()?;
            if !names.insert(pin.name.as_str()) {
                return Err(ComposedGraphError::Pin);
            }
            let correct_kind = match node {
                GraphNode::Application { .. } => {
                    !pin.name.starts_with("runtime/") && !pin.name.starts_with("tool/")
                }
                GraphNode::Runtime { .. } => pin.name.starts_with("runtime/"),
                GraphNode::Tool { .. } => pin.name.starts_with("tool/"),
            };
            if !correct_kind {
                return Err(ComposedGraphError::Kind);
            }
        }
        Ok(())
    }

    /// Select a command, or `None` if no source declared one.
    ///
    /// The runtime override wins over the workload/config command; otherwise
    /// the last *verified declaring* application wins, not necessarily the
    /// last layer. The caller supplies default argv from the verified signed
    /// manifest for each pin, or `None` if that manifest has no default.
    /// This callback is a trust boundary: the contract does not verify packs.
    /// The caller must also admit the selected command before execution.
    ///
    /// # Errors
    ///
    /// Refuses invalid directly constructed graphs or requests, even if an
    /// override would otherwise conceal an invalid application default.
    pub fn select_entrypoint<'a>(
        &'a self,
        request: &'a EntrypointRequest,
        mut application_default: impl FnMut(
            &SignedPackPin,
        ) -> Result<Option<&'a [String]>, ComposedGraphError>,
    ) -> Result<Option<SelectedEntrypoint<'a>>, ComposedGraphError> {
        self.validate()?;
        request.validate()?;
        let mut last_default = None;
        for node in &self.graph {
            if let GraphNode::Application { pin } = node
                && let Some(argv) = application_default(pin)?
            {
                validate_command(argv)?;
                last_default = Some(SelectedEntrypoint::Application { pin, argv });
            }
        }
        if let Some(argv) = &request.runtime_command_override {
            return Ok(Some(SelectedEntrypoint::RuntimeOverride(argv)));
        }
        if let Some(argv) = &request.workload_command {
            return Ok(Some(SelectedEntrypoint::Workload(argv)));
        }
        Ok(last_default)
    }

    /// Deterministic authored JSON, preserving semantic layer order.
    ///
    /// # Errors
    ///
    /// Refuses invalid graph data or serialization failure.
    pub fn canonical_json(&self) -> Result<Vec<u8>, ComposedGraphError> {
        self.validate()?;
        let mut value =
            serde_json::to_value(self).map_err(|_| ComposedGraphError::Serialization)?;
        value.sort_all_objects();
        serde_json::to_vec(&value).map_err(|_| ComposedGraphError::Serialization)
    }
}

impl EntrypointRequest {
    /// Validate both command sources even if one takes precedence.
    ///
    /// # Errors
    ///
    /// Refuses unsafe or empty argv in either source.
    pub fn validate(&self) -> Result<(), ComposedGraphError> {
        for argv in [&self.runtime_command_override, &self.workload_command]
            .into_iter()
            .flatten()
        {
            validate_command(argv)?;
        }
        Ok(())
    }

    /// Deterministic request JSON, with absent commands omitted.
    ///
    /// # Errors
    ///
    /// Refuses invalid commands or serialization failure.
    pub fn canonical_json(&self) -> Result<Vec<u8>, ComposedGraphError> {
        self.validate()?;
        let mut value =
            serde_json::to_value(self).map_err(|_| ComposedGraphError::Serialization)?;
        value.sort_all_objects();
        serde_json::to_vec(&value).map_err(|_| ComposedGraphError::Serialization)
    }
}

fn validate_command(argv: &[String]) -> Result<(), ComposedGraphError> {
    let Some(program) = argv.first() else {
        return Err(ComposedGraphError::Command);
    };
    if argv.len() > 128
        || argv.iter().map(String::len).sum::<usize>() > 16 * 1024
        || !program.starts_with('/')
        || !program.bytes().all(|byte| byte.is_ascii_graphic())
        || relative_path(&program[1..], false).is_err()
        || argv
            .iter()
            .any(|argument| argument.is_empty() || argument.chars().any(char::is_control))
    {
        return Err(ComposedGraphError::Command);
    }
    Ok(())
}
