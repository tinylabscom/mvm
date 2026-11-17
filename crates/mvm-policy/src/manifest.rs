//! A resolved workload policy document, revalidated before launch.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{merge::ResolvedPolicy, model::PolicyBody, source::PolicyError};

/// A resolved policy as a document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ResolvedManifest {
    /// The layers it was resolved from, lowest precedence first.
    /// Informational: reading the manifest back ignores it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_from: Vec<String>,
    /// The merged policy, denies already applied.
    #[serde(default)]
    pub policy: PolicyBody,
}

/// Keys an execution plan or a signed envelope carries and a resolved
/// manifest never does.
const PLAN_KEYS: &[&str] = &[
    "signature",
    "signer_id",
    "plan",
    "plan_id",
    "nonce",
    "image",
];

impl ResolvedManifest {
    /// Read a resolved manifest, refusing a plan or a signature, and
    /// re-validating the policy it carries.
    ///
    /// # Errors
    ///
    /// Not JSON, an execution plan or signed envelope, an unknown key, or a
    /// policy the merge refuses.
    pub fn read(path: &Path) -> Result<Self, PolicyError> {
        let label = format!("resolved manifest {}", path.display());
        let bytes = std::fs::read(path).map_err(|error| {
            PolicyError::new(&label, format!("reading: {error}")).in_file(Some(path))
        })?;
        Self::from_json(&bytes, &label, Some(path))
    }

    /// Parse and re-validate a resolved manifest.
    ///
    /// # Errors
    ///
    /// See [`read`](Self::read).
    pub fn from_json(bytes: &[u8], label: &str, file: Option<&Path>) -> Result<Self, PolicyError> {
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| PolicyError::new(label, format!("not JSON: {error}")).in_file(file))?;
        if let Some(key) = value
            .as_object()
            .and_then(|object| PLAN_KEYS.iter().find(|key| object.contains_key(**key)))
        {
            return Err(PolicyError::new(
                label,
                "this is an execution plan or a signed envelope, not a resolved manifest. A \
                 supplied plan or signature is never trusted: give `mvmctl policy resolve` \
                 output and admission synthesizes and signs the plan itself",
            )
            .in_file(file)
            .at_key(*key));
        }
        let manifest: Self = serde_json::from_value(value)
            .map_err(|error| PolicyError::new(label, error.to_string()).in_file(file))?;
        let revalidated = super::resolve::revalidate(label, file, manifest.policy.clone())?;
        Ok(Self {
            resolved_from: manifest.resolved_from,
            policy: revalidated.policy,
        })
    }

    /// The manifest for a resolved policy.
    #[must_use]
    pub fn from_resolved(resolved: &ResolvedPolicy) -> Self {
        Self {
            resolved_from: resolved.layers.iter().map(|l| l.label.clone()).collect(),
            policy: resolved.policy.clone(),
        }
    }

    /// Revalidate this complete policy and retain its explicit network selection.
    ///
    /// A resolved manifest is equivalent to its effective flags, not an authored
    /// partial layer. Even an empty network must not inherit application defaults.
    /// Explicit launch flags still compose through the ordinary policy fold.
    ///
    /// # Errors
    ///
    /// A policy that revalidation refuses.
    pub fn into_resolved(
        self,
        label: &str,
        file: Option<&Path>,
    ) -> Result<ResolvedPolicy, PolicyError> {
        let mut resolved = super::resolve::revalidate(label, file, self.policy)?;
        resolved
            .provenance
            .insert("network.selection".into(), label.into());
        Ok(resolved)
    }
}
