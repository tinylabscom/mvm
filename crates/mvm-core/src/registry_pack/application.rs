//! Closed application-descriptor data, separate from legacy policy manifests.
//!
//! Parsing does not authenticate a publisher, enroll a bundle key, check
//! revocation, fetch an archive or authorize execution. Integrators must verify
//! the original descriptor bytes, not a serialization of the parsed value.

use serde::{Deserialize, Deserializer, Serialize};

use super::{PackReference, RegistryPackVerificationError};
use crate::packs::Sha256Hex;
use crate::plan::KeyId;

/// The application wire format does not change the policy-manifest version.
pub const APPLICATION_MANIFEST_SCHEMA_VERSION: u32 = 2;
const MAX_DESCRIPTOR_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ApplicationManifestKind {
    #[serde(rename = "application")]
    Application,
}

impl<'de> Deserialize<'de> for ApplicationManifestKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match String::deserialize(deserializer)?.as_str() {
            "application" => Ok(Self::Application),
            _ => Err(serde::de::Error::custom("expected application kind")),
        }
    }
}

/// Unauthenticated descriptor data. The bundle key is an expectation, not trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryApplicationManifest {
    pub schema_version: u32,
    pub kind: ApplicationManifestKind,
    pub reference: PackReference,
    pub description: String,
    #[serde(deserialize_with = "deserialize_object")]
    pub application: RegistryApplication,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryApplication {
    pub schema_version: u32,
    pub guest_arch: String,
    #[serde(deserialize_with = "deserialize_object")]
    pub bundle: RegistryApplicationBundle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryApplicationBundle {
    pub source: String,
    pub archive_sha256: Sha256Hex,
    pub archive_size: u64,
    /// Must independently match a bundle verified under the recipient's trust.
    pub key_id: KeyId,
}

/// Parse bounded original bytes without a legacy, hybrid or default-role path.
///
/// The result contains data only. Publisher policy, signatures, digest pins,
/// current revocations and independent bundle verification remain mandatory
/// outside this parser. In particular, this never returns a verified product.
pub fn parse_application_manifest(
    bytes: &[u8],
) -> Result<RegistryApplicationManifest, RegistryPackVerificationError> {
    if bytes.len() > MAX_DESCRIPTOR_BYTES {
        return Err(invalid("application descriptor exceeds its size bound"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let manifest: RegistryApplicationManifest = deserialize_object(&mut deserializer)
        .map_err(|_| invalid("application descriptor has invalid JSON or a non-closed shape"))?;
    deserializer
        .end()
        .map_err(|_| invalid("application descriptor has trailing data"))?;
    if manifest.schema_version != APPLICATION_MANIFEST_SCHEMA_VERSION
        || manifest.application.schema_version != 1
    {
        return Err(invalid(
            "application requires manifest schema 2 and application schema 1",
        ));
    }
    if manifest
        .reference
        .version()
        .is_none_or(|version| version.as_str().contains('+'))
        || manifest.description.trim().is_empty()
    {
        return Err(invalid(
            "application requires an exact version without build metadata and a nonempty description",
        ));
    }
    if !matches!(
        manifest.application.guest_arch.as_str(),
        "x86_64" | "aarch64"
    ) {
        return Err(invalid("application guest architecture is not canonical"));
    }
    let bundle = &manifest.application.bundle;
    if bundle.archive_size == 0 || !lower_hex(&bundle.key_id.0, 32) {
        return Err(invalid(
            "application requires a positive archive size and a canonical bundle key ID",
        ));
    }
    validate_application_source(&bundle.source)?;
    Ok(manifest)
}

fn deserialize_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ObjectVisitor<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for ObjectVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(ObjectVisitor(std::marker::PhantomData))
}

/// Validate a locator without resolving it or granting permission to fetch it.
pub fn validate_application_source(source: &str) -> Result<(), RegistryPackVerificationError> {
    if source.is_empty()
        || source.len() > MAX_DESCRIPTOR_BYTES
        || source.bytes().any(|byte| !(33..127).contains(&byte))
        || source.contains('\\')
    {
        return Err(invalid(
            "application source must be a bounded ASCII HTTPS or digest-pinned OCI locator",
        ));
    }
    if let Some(rest) = source.strip_prefix("https://") {
        let url =
            url::Url::parse(source).map_err(|_| invalid("application HTTPS source is invalid"))?;
        let (authority, _) = rest
            .split_once('/')
            .ok_or_else(|| invalid("application HTTPS source requires an explicit path"))?;
        validate_authority(authority)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.as_str() != source
        {
            return Err(invalid(
                "application HTTPS source must already be canonical and credential-free",
            ));
        }
        return Ok(());
    }
    let reference = source
        .strip_prefix("oci://")
        .ok_or_else(|| invalid("application source must use HTTPS or digest-pinned OCI"))?;
    let (authority, _) = reference
        .split_once('/')
        .ok_or_else(|| invalid("application OCI source requires an explicit registry"))?;
    validate_authority(authority)?;
    if !(authority.contains('.') || authority.contains(':') || authority == "localhost") {
        return Err(invalid(
            "application OCI source requires an explicit registry",
        ));
    }
    let (_, digest) = reference
        .rsplit_once("@sha256:")
        .ok_or_else(|| invalid("application OCI source requires an exact SHA-256 digest"))?;
    if !lower_hex(digest, 64) {
        return Err(invalid("application OCI digest must be lowercase SHA-256"));
    }
    let parsed: mvm_contract::oci::ImageReference = reference
        .parse()
        .map_err(|_| invalid("application OCI source is invalid"))?;
    if parsed.digest.is_none()
        || parsed.tag.is_some()
        || parsed.registry != authority
        || parsed.canonical() != reference
        || parsed
            .repository
            .split('/')
            .any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(invalid(
            "application OCI source must already be canonical, explicit and digest-only",
        ));
    }
    Ok(())
}

fn validate_authority(authority: &str) -> Result<(), RegistryPackVerificationError> {
    if authority.is_empty()
        || authority != authority.to_ascii_lowercase()
        || authority.contains(['@', '%', '/', '?', '#', '\\'])
    {
        return Err(invalid("application source authority is not canonical"));
    }
    let url = url::Url::parse(&format!("https://{authority}/"))
        .map_err(|_| invalid("application source authority is invalid"))?;
    if url.host_str().is_none() || url.path() != "/" {
        return Err(invalid("application source requires an explicit host"));
    }
    let port = if let Some(address) = authority.strip_prefix('[') {
        let (host, suffix) = address
            .split_once(']')
            .ok_or_else(|| invalid("application source IPv6 authority is invalid"))?;
        host.parse::<std::net::Ipv6Addr>()
            .map_err(|_| invalid("application source IPv6 authority is invalid"))?;
        if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .ok_or_else(|| invalid("application source port is invalid"))?,
            )
        }
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        if host.is_empty()
            || !host.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
        {
            return Err(invalid("application source hostname is invalid"));
        }
        let last = host.trim_end_matches('.').rsplit('.').next().unwrap_or("");
        if (!last.is_empty() && last.bytes().all(|byte| byte.is_ascii_digit()))
            || last.starts_with("0x")
        {
            let address = host
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| invalid("application source IPv4 host is not canonical"))?;
            if address.to_string() != host {
                return Err(invalid("application source IPv4 host is not canonical"));
            }
        }
        port
    };
    if let Some(port) = port
        && (port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().ok().is_none_or(|port| port == 0))
    {
        return Err(invalid("application source port must be in 1..=65535"));
    }
    Ok(())
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid(reason: &str) -> RegistryPackVerificationError {
    RegistryPackVerificationError::ManifestParse(reason.to_owned())
}

#[cfg(test)]
mod tests;
