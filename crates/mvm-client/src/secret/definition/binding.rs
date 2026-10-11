//! Preparation of public binding metadata, shared by host-local callers.

use anyhow::{Context, Result};
use mvm_contract::ir::{AuthType, Sigv4Params};
use mvm_contract::service_catalog;
use mvm_core::crypto::secret_binding::OAuthBindingMeta;

#[derive(Default)]
pub struct BindingShapeInput {
    pub provider: Option<String>,
    pub hosts: Vec<String>,
    pub auth_type: Option<AuthType>,
    pub aws_access_key_id: Option<String>,
    pub region: Option<String>,
    pub aws_service: Option<String>,
}

#[derive(Debug)]
pub struct ResolvedBindingShape {
    pub allowed_hosts: Vec<String>,
    pub auth_type: AuthType,
    pub sigv4: Option<Sigv4Params>,
    pub provider: Option<String>,
}

pub fn resolve_binding_shape(input: BindingShapeInput) -> Result<ResolvedBindingShape> {
    let BindingShapeInput {
        provider,
        hosts,
        auth_type,
        aws_access_key_id,
        region,
        aws_service,
    } = input;
    let Some(provider_name) = provider else {
        let auth_type = auth_type.context("--type is required when --provider is not given")?;
        let sigv4 = resolve_sigv4_params(auth_type, aws_access_key_id, region, aws_service)?;
        return Ok(ResolvedBindingShape {
            allowed_hosts: hosts,
            auth_type,
            sigv4,
            provider: None,
        });
    };
    if !hosts.is_empty() || auth_type.is_some() || aws_service.is_some() {
        anyhow::bail!("--provider cannot be combined with --host, --type or --service");
    }
    let catalog = service_catalog::builtin();
    let entry = catalog.find(&provider_name).with_context(|| {
        let known = catalog
            .all()
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "unknown provider {provider_name:?}; known providers: {known}. \
             Use --host/--type for a destination the catalog does not carry."
        )
    })?;
    let sigv4 = resolve_sigv4_params(
        entry.auth,
        aws_access_key_id,
        region,
        entry.sigv4_service.clone(),
    )?;
    Ok(ResolvedBindingShape {
        allowed_hosts: entry.hosts.clone(),
        auth_type: entry.auth,
        sigv4,
        provider: Some(entry.name.clone()),
    })
}

pub fn resolve_sigv4_params(
    auth_type: AuthType,
    access_key_id: Option<String>,
    region: Option<String>,
    service: Option<String>,
) -> Result<Option<Sigv4Params>> {
    match auth_type {
        AuthType::Sigv4 => {
            let access_key_id = access_key_id
                .filter(|s| !s.is_empty())
                .context("--type sigv4 requires --aws-access-key-id")?;
            let region = region
                .filter(|s| !s.is_empty())
                .context("--type sigv4 requires --region")?;
            let service = service
                .filter(|s| !s.is_empty())
                .context("--type sigv4 requires --service")?;
            Ok(Some(Sigv4Params {
                access_key_id,
                region,
                service,
            }))
        }
        AuthType::Hmac | AuthType::Bearer | AuthType::Basic => {
            if access_key_id.is_some() || region.is_some() || service.is_some() {
                anyhow::bail!(
                    "--aws-access-key-id/--region/--service are only valid with --type sigv4"
                );
            }
            Ok(None)
        }
    }
}

/// Only metadata and presence bits, never a client secret or access token.
#[derive(Default)]
pub struct OAuthBindingInput {
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub client_id: Option<String>,
    pub scopes: Vec<String>,
    pub response_access_token_pointer: Option<String>,
    pub has_client_secret: bool,
    pub login: bool,
}

pub fn resolve_oauth_params(
    auth_type: AuthType,
    args: &OAuthBindingInput,
) -> Result<Option<OAuthBindingMeta>> {
    let core = [
        args.authorization_url.as_ref(),
        args.token_url.as_ref(),
        args.client_id.as_ref(),
    ];
    let riders_present = !args.scopes.is_empty()
        || args.response_access_token_pointer.is_some()
        || args.has_client_secret
        || args.login;
    let present = core.iter().flatten().count();
    if present == 0 {
        if riders_present {
            anyhow::bail!(
                "the --oauth-scope/--oauth-response-access-token-pointer/--oauth-client-secret*/--oauth-login \
                 flags require --oauth-authorization-url, --oauth-token-url and --oauth-client-id"
            );
        }
        return Ok(None);
    }
    if present != 3 {
        anyhow::bail!(
            "--oauth-authorization-url, --oauth-token-url and --oauth-client-id must be given together"
        );
    }
    if auth_type != AuthType::Bearer {
        anyhow::bail!("the --oauth-* flags are only valid with --type bearer");
    }
    let authorization_url = args
        .authorization_url
        .clone()
        .filter(|value| !value.is_empty())
        .context("--oauth-authorization-url must not be empty")?;
    let token_url = args
        .token_url
        .clone()
        .filter(|value| !value.is_empty())
        .context("--oauth-token-url must not be empty")?;
    let client_id = args
        .client_id
        .clone()
        .filter(|value| !value.is_empty())
        .context("--oauth-client-id must not be empty")?;
    Ok(Some(OAuthBindingMeta {
        authorization_url,
        token_url,
        client_id,
        scopes: args.scopes.clone(),
        response_access_token_pointer: args.response_access_token_pointer.clone(),
    }))
}
