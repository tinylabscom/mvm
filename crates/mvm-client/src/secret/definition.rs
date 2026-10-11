//! Write-only definition preparation and ordered value/binding persistence.

use anyhow::Context;
use secrecy::ExposeSecret;
use std::path::PathBuf;

use super::{
    PutOutcome, SecretBindingMeta, SecretService, SecretServiceError, SecretSource,
    SecretValueInput, SourceResolver, validate_binding_meta,
};

mod binding;
pub use binding::{
    BindingShapeInput, OAuthBindingInput, ResolvedBindingShape, resolve_binding_shape,
    resolve_oauth_params, resolve_sigv4_params,
};

/// Opaque definition input: deliberately neither Debug nor Serialize. OAuth
/// token sets are constructed only inside the client, never returned to callers.
pub struct SecretDefinitionInput {
    binding: SecretBindingMeta,
    value: Option<SecretValueInput>,
    value_file: Option<PathBuf>,
    source: Option<SecretSource>,
    client_secret: Option<SecretValueInput>,
    client_secret_file: Option<PathBuf>,
    await_consent: bool,
}

impl SecretDefinitionInput {
    pub fn new(binding: SecretBindingMeta) -> Self {
        Self {
            binding,
            value: None,
            value_file: None,
            source: None,
            client_secret: None,
            client_secret_file: None,
            await_consent: false,
        }
    }

    pub fn with_value(mut self, value: SecretValueInput) -> Self {
        self.value = Some(value);
        self
    }

    pub fn with_source(mut self, source: SecretSource) -> Self {
        self.source = Some(source);
        self
    }

    pub fn with_client_secret(mut self, secret: SecretValueInput) -> Self {
        self.client_secret = Some(secret);
        self
    }

    pub fn with_value_file(mut self, path: PathBuf) -> Self {
        self.value_file = Some(path);
        self
    }

    pub fn with_client_secret_file(mut self, path: PathBuf) -> Self {
        self.client_secret_file = Some(path);
        self
    }

    pub fn awaiting_consent(mut self) -> Self {
        self.await_consent = true;
        self
    }

    fn prepare(mut self) -> anyhow::Result<(SecretBindingMeta, SecretValueInput)> {
        if self.binding.oauth.is_some() && self.binding.auth_type != super::AuthType::Bearer {
            anyhow::bail!("the --oauth-* flags are only valid with --type bearer");
        }
        let has_value = self.value.is_some() || self.value_file.is_some();
        let has_client_secret = self.client_secret.is_some() || self.client_secret_file.is_some();
        if self.await_consent && (has_value || self.source.is_some()) {
            anyhow::bail!("--oauth-login writes the value itself and takes no value source");
        }
        if self.binding.oauth.is_some() && self.source.is_some() {
            anyhow::bail!("--from cannot be combined with the --oauth-* binding flags");
        }
        if self.source.is_some() && has_value {
            anyhow::bail!("--from cannot be combined with --value or --value-file");
        }
        if has_client_secret && has_value {
            anyhow::bail!(
                "--oauth-client-secret* writes the value itself and takes no value source"
            );
        }
        if (self.await_consent || has_client_secret) && self.binding.oauth.is_none() {
            anyhow::bail!("oauth client secret and consent require an oauth binding");
        }
        if self.value.is_some() && self.value_file.is_some() {
            anyhow::bail!("--value and --value-file are mutually exclusive");
        }
        if self.client_secret.is_some() && self.client_secret_file.is_some() {
            anyhow::bail!(
                "--oauth-client-secret and --oauth-client-secret-file are mutually exclusive"
            );
        }
        if let Some(path) = self.client_secret_file {
            self.client_secret = Some(SecretValueInput::new(
                std::fs::read_to_string(&path).with_context(|| {
                    format!("reading oauth client secret from {}", path.display())
                })?,
            ));
        }
        if let Some(path) = self.value_file {
            self.value = Some(SecretValueInput::new(
                std::fs::read_to_string(&path)
                    .with_context(|| format!("reading secret value from {}", path.display()))?,
            ));
        }
        let client_secret = self
            .client_secret
            .as_ref()
            .map(|input| input.storage_value().expose_secret().as_str());
        let token_set = if self.await_consent {
            Some(mvm_hostd::keyholder::oauth::awaiting_consent_token_set(
                client_secret,
            ))
        } else {
            client_secret.map(mvm_hostd::keyholder::oauth::initial_token_set)
        };
        let value = match (token_set, self.value, self.source) {
            (Some(tokens), _, _) => SecretValueInput::new(
                serde_json::to_string(&tokens)
                    .context("serializing the initial oauth token set")?,
            ),
            (None, Some(value), None) => value,
            (None, None, Some(source)) => SourceResolver::host().resolve(&source)?,
            _ => anyhow::bail!("a secret definition requires a value source"),
        };
        Ok((self.binding, value))
    }
}

impl SecretService {
    /// Validate definition metadata before callers collect any secret input.
    /// Refusals use the same authoritative binding audit path as `define`.
    /// `define` revalidates independently for callers constructing inputs directly.
    pub fn prepare_definition(
        &self,
        tenant: &str,
        name: &str,
        binding: SecretBindingMeta,
    ) -> Result<SecretDefinitionInput, SecretServiceError> {
        self.validate_definition_binding(tenant, name, &binding)?;
        Ok(SecretDefinitionInput::new(binding))
    }

    fn validate_definition_binding(
        &self,
        tenant: &str,
        name: &str,
        binding: &SecretBindingMeta,
    ) -> Result<(), SecretServiceError> {
        let validated = validate_binding_meta(tenant, name, binding);
        if validated.is_err() {
            self.audit.record("bind", tenant, name, &validated)?;
        }
        validated
    }

    /// Validate before any mutation, then write the value before its binding.
    /// Storage failures are not transactional: as with put/bind, a failed binding
    /// write may leave the value, but never a newly dangling binding. Existing
    /// create/replace/bind audit events and machine reference semantics apply.
    pub fn define(
        &self,
        tenant: &str,
        name: &str,
        input: SecretDefinitionInput,
    ) -> Result<PutOutcome, SecretServiceError> {
        self.validate_definition_binding(tenant, name, &input.binding)?;
        let (binding, value) = input.prepare()?;
        let outcome = self.put(tenant, name, value)?;
        self.bind(tenant, name, binding)?;
        Ok(outcome)
    }
}
