use std::collections::HashSet;
use std::fmt;
#[cfg(feature = "host-tls")]
use std::net::IpAddr;
#[cfg(feature = "host-tls")]
use std::net::Ipv4Addr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

#[cfg(feature = "host-netd")]
use sha2::{Digest, Sha256};

#[cfg(feature = "host-tls")]
use crate::proto::MAX_HOST_NAME_BYTES;
use crate::proto::PluginId;
#[cfg(feature = "host-tls")]
use mvm_core::egress_substitution::{SubstitutionVerdict, decide_substitution};
#[cfg(feature = "host-tls")]
use mvm_core::ingress_redaction::REDACTION_MASK;
#[cfg(feature = "host-tls")]
use mvm_core::policy::network_policy::is_mandatory_deny;
#[cfg(all(feature = "host-tls", test))]
use mvm_core::policy::secret_binding::MAX_TARGET_HOST_BYTES;
#[cfg(feature = "host-tls")]
use mvm_core::policy::secret_binding::{
    PLACEHOLDER_PREFIX, SecretBinding, validate_target_host_pattern,
};

const AUDIT_PLUGIN_ID: &str = "audit";
const METADATA_ENDPOINT_DENY_PLUGIN_ID: &str = "metadata-endpoint-deny";
const SECRET_REPLACEMENT_PLUGIN_ID: &str = "secret-replacement";
const RESPONSE_LEAK_GUARD_PLUGIN_ID: &str = "response-leak-guard";
#[cfg(test)]
const PANIC_CONSTRUCT_TEST_PLUGIN_ID: &str = "panic-construct-test";
#[cfg(test)]
const PANIC_PROCESS_TEST_PLUGIN_ID: &str = "panic-process-test";
#[cfg(test)]
const PANIC_FINISH_TEST_PLUGIN_ID: &str = "panic-finish-test";
#[cfg(test)]
const PANIC_FINISH_DIRECTION_TEST_PLUGIN_ID: &str = "panic-finish-direction-test";
#[cfg(test)]
const SLOW_CONSTRUCT_TEST_PLUGIN_ID: &str = "slow-construct-test";
#[cfg(test)]
const SLOW_PROCESS_TEST_PLUGIN_ID: &str = "slow-process-test";
#[cfg(test)]
const SLOW_FINISH_TEST_PLUGIN_ID: &str = "slow-finish-test";
#[cfg(test)]
const SLOW_FINISH_DIRECTION_TEST_PLUGIN_ID: &str = "slow-finish-direction-test";
#[cfg(test)]
const OVER_BUFFER_PROCESS_TEST_PLUGIN_ID: &str = "over-buffer-process-test";
#[cfg(test)]
const OVER_BUFFER_FINISH_TEST_PLUGIN_ID: &str = "over-buffer-finish-test";
#[cfg(test)]
const OVER_BUFFER_FINISH_DIRECTION_TEST_PLUGIN_ID: &str = "over-buffer-finish-direction-test";
#[cfg(test)]
const OBSERVE_INPUT_TEST_PLUGIN_ID: &str = "observe-input-test";
const DEFAULT_PLUGIN_TIMEOUT_BUDGET: Duration = Duration::from_millis(5);
const MAX_STREAM_TRANSFORM_PLUGINS: usize = 8;
pub const DEFAULT_MAX_STREAM_TRANSFORM_DETAIL_BYTES: usize = 8 * 1024;
pub const MAX_STREAM_TRANSFORM_DETAIL_BYTES: usize = DEFAULT_MAX_STREAM_TRANSFORM_DETAIL_BYTES;
#[cfg(feature = "host-tls")]
const MAX_SECRET_REPLACEMENT_BINDINGS: usize = 256;
#[cfg(feature = "host-tls")]
const MAX_SECRET_REPLACEMENT_TOTAL_VALUE_BYTES: usize = 256 * 1024;
#[cfg(feature = "host-tls")]
pub(crate) const MAX_SECRET_REPLACEMENT_PLACEHOLDER_BYTES: usize = 2 * 1024;
const MAX_RESPONSE_LEAK_GUARD_SECRET_VALUES: usize = 128;
const MAX_RESPONSE_LEAK_GUARD_TOTAL_VALUE_BYTES: usize = 256 * 1024;
#[cfg(feature = "host-tls")]
const HTTP_REQUEST_HEAD_INSPECTION_BYTES: usize = 8 * 1024;
#[cfg(feature = "host-tls")]
const METADATA_ENDPOINT_DENY_MAX_BUFFERED_BYTES: usize = HTTP_REQUEST_HEAD_INSPECTION_BYTES;
#[cfg(feature = "host-tls")]
const KNOWN_METADATA_HOSTS: &[&str] = &["metadata.google.internal", "instance-data.ec2.internal"];
pub(crate) const RESPONSE_LEAK_GUARD_MAX_BUFFERED_BYTES: usize = 64 * 1024;
#[cfg(feature = "host-tls")]
const HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
];
#[cfg(feature = "host-tls")]
const HTTP2_PRIOR_KNOWLEDGE_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamTransformError {
    UnknownPlugin(PluginId),
    PluginChainTooLong { count: usize, max: usize },
    PluginDenied { plugin: PluginId, detail: String },
}

impl fmt::Display for StreamTransformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPlugin(plugin) => {
                write!(f, "unknown TLS transform plugin {}", plugin.as_str())
            }
            Self::PluginChainTooLong { count, max } => {
                write!(
                    f,
                    "TLS transform plugin chain has {count} entries; maximum is {max}"
                )
            }
            Self::PluginDenied { plugin, detail } => {
                write!(
                    f,
                    "TLS transform plugin {} denied the flow: {detail}",
                    plugin.as_str()
                )
            }
        }
    }
}

impl std::error::Error for StreamTransformError {}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum StreamTransformDirection {
    GuestToUpstream,
    UpstreamToGuest,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum StreamTransformCapability {
    ObservePlaintext,
    MutatePlaintext,
    DenyFlow,
}

impl StreamTransformCapability {
    #[cfg(feature = "host-netd")]
    const fn digest_label(self) -> &'static str {
        match self {
            Self::ObservePlaintext => "observe_plaintext",
            Self::MutatePlaintext => "mutate_plaintext",
            Self::DenyFlow => "deny_flow",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamTransformManifest {
    id: PluginId,
    capabilities: Vec<StreamTransformCapability>,
    timeout_budget: Duration,
    max_buffered_bytes: usize,
}

impl StreamTransformManifest {
    fn new(
        id: PluginId,
        capabilities: Vec<StreamTransformCapability>,
        timeout_budget: Duration,
        max_buffered_bytes: usize,
    ) -> Self {
        Self {
            id,
            capabilities,
            timeout_budget,
            max_buffered_bytes,
        }
    }

    pub fn id(&self) -> &PluginId {
        &self.id
    }

    pub fn capabilities(&self) -> &[StreamTransformCapability] {
        &self.capabilities
    }

    pub const fn timeout_budget(&self) -> Duration {
        self.timeout_budget
    }

    pub const fn max_buffered_bytes(&self) -> usize {
        self.max_buffered_bytes
    }

    #[cfg(feature = "host-netd")]
    pub fn identity_digest_hex(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.id.as_str().as_bytes());
        hasher.update([0]);
        for capability in &self.capabilities {
            hasher.update(capability.digest_label().as_bytes());
            hasher.update([0]);
        }
        hasher.update(self.timeout_budget.as_millis().to_string().as_bytes());
        hasher.update([0]);
        hasher.update(self.max_buffered_bytes.to_string().as_bytes());
        hex_digest(hasher.finalize())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamTransformChunk {
    bytes: Vec<u8>,
    detail: Option<String>,
}

impl StreamTransformChunk {
    fn passthrough(bytes: &[u8], detail: Option<String>) -> Self {
        Self {
            bytes: bytes.to_vec(),
            detail,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct StreamTransformConfig {
    #[cfg(feature = "host-tls")]
    #[cfg_attr(feature = "serde", serde(default))]
    secret_replacement_bindings: Vec<SecretBinding>,
    #[cfg_attr(feature = "serde", serde(default))]
    response_leak_guard_secret_values: Vec<String>,
}

impl StreamTransformConfig {
    pub(crate) fn validate(&self) -> Result<(), StreamTransformError> {
        validate_stream_transform_config(self)
    }

    #[cfg(feature = "host-tls")]
    pub fn with_secret_replacement_bindings(
        mut self,
        bindings: impl IntoIterator<Item = SecretBinding>,
    ) -> Result<Self, StreamTransformError> {
        self.secret_replacement_bindings = bindings.into_iter().collect();
        validate_stream_transform_config(&self)?;
        Ok(self)
    }

    #[cfg(feature = "host-tls")]
    pub fn secret_replacement_bindings(&self) -> &[SecretBinding] {
        &self.secret_replacement_bindings
    }

    pub fn with_response_leak_guard_secret_values(
        mut self,
        secret_values: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, StreamTransformError> {
        self.response_leak_guard_secret_values =
            secret_values.into_iter().map(Into::into).collect();
        validate_stream_transform_config(&self)?;
        Ok(self)
    }

    pub fn response_leak_guard_secret_values(&self) -> &[String] {
        &self.response_leak_guard_secret_values
    }

    pub(crate) fn effective_plugin_chain(&self, plugin_ids: &[PluginId]) -> Vec<PluginId> {
        let mut chain =
            Vec::with_capacity(estimated_effective_plugin_chain_capacity(plugin_ids, self));
        chain.extend_from_slice(plugin_ids);
        #[cfg(feature = "host-tls")]
        if !self.secret_replacement_bindings.is_empty() {
            push_plugin_once(&mut chain, SECRET_REPLACEMENT_PLUGIN_ID);
        }
        if !self.response_leak_guard_secret_values.is_empty() {
            push_plugin_once(&mut chain, RESPONSE_LEAK_GUARD_PLUGIN_ID);
        }
        ensure_audit_precedes_all_plugins(&mut chain);
        #[cfg(feature = "host-tls")]
        ensure_secret_replacement_precedes_metadata_endpoint_deny(&mut chain);
        chain
    }
}

fn estimated_effective_plugin_chain_capacity(
    plugin_ids: &[PluginId],
    config: &StreamTransformConfig,
) -> usize {
    let mut additional = usize::from(!config.response_leak_guard_secret_values.is_empty());
    #[cfg(feature = "host-tls")]
    if !config.secret_replacement_bindings.is_empty() {
        additional += 1;
    }
    plugin_ids.len().saturating_add(additional)
}

fn push_plugin_once(chain: &mut Vec<PluginId>, plugin_id: &str) {
    if chain.iter().any(|existing| existing.as_str() == plugin_id) {
        return;
    }
    chain.push(PluginId::new(plugin_id).expect("built-in plugin id literal must be valid"));
}

fn ensure_audit_precedes_all_plugins(chain: &mut Vec<PluginId>) {
    move_plugin_to_front(chain, AUDIT_PLUGIN_ID);
}

fn move_plugin_to_front(chain: &mut Vec<PluginId>, plugin_id: &str) {
    let Some(index) = chain
        .iter()
        .position(|existing| existing.as_str() == plugin_id)
    else {
        return;
    };
    if index == 0 {
        return;
    }
    let plugin = chain.remove(index);
    chain.insert(0, plugin);
}

#[cfg(feature = "host-tls")]
fn ensure_secret_replacement_precedes_metadata_endpoint_deny(chain: &mut Vec<PluginId>) {
    let Some(secret_index) = chain
        .iter()
        .position(|plugin_id| plugin_id.as_str() == SECRET_REPLACEMENT_PLUGIN_ID)
    else {
        return;
    };
    let Some(metadata_index) = chain
        .iter()
        .position(|plugin_id| plugin_id.as_str() == METADATA_ENDPOINT_DENY_PLUGIN_ID)
    else {
        return;
    };
    if secret_index < metadata_index {
        return;
    }

    let secret_plugin = chain.remove(secret_index);
    let insert_at = chain
        .iter()
        .position(|plugin_id| plugin_id.as_str() == METADATA_ENDPOINT_DENY_PLUGIN_ID)
        .expect("metadata-endpoint-deny must remain present after removing secret-replacement");
    chain.insert(insert_at, secret_plugin);
}

fn builtin_plugin_timeout_budget(plugin_id: &PluginId) -> Duration {
    match plugin_id.as_str() {
        #[cfg(test)]
        SLOW_CONSTRUCT_TEST_PLUGIN_ID
        | SLOW_PROCESS_TEST_PLUGIN_ID
        | SLOW_FINISH_TEST_PLUGIN_ID
        | SLOW_FINISH_DIRECTION_TEST_PLUGIN_ID => Duration::from_millis(1),
        _ => DEFAULT_PLUGIN_TIMEOUT_BUDGET,
    }
}

#[derive(Debug, Default)]
pub struct StreamTransformChain {
    plugins: Vec<BuiltinStreamTransformPlugin>,
}

impl StreamTransformChain {
    pub fn from_plugin_ids(plugin_ids: &[PluginId]) -> Result<Self, StreamTransformError> {
        Self::from_plugin_ids_with_config(plugin_ids, &StreamTransformConfig::default())
    }

    pub fn from_plugin_ids_with_config(
        plugin_ids: &[PluginId],
        config: &StreamTransformConfig,
    ) -> Result<Self, StreamTransformError> {
        Self::from_plugin_ids_with_config_for_target(plugin_ids, config, None)
    }

    pub fn from_plugin_ids_with_config_for_target(
        plugin_ids: &[PluginId],
        config: &StreamTransformConfig,
        target_host: Option<&str>,
    ) -> Result<Self, StreamTransformError> {
        let effective_plugin_chain = validated_effective_plugin_chain(plugin_ids, config)?;
        let plugins = effective_plugin_chain
            .iter()
            .map(|plugin_id| {
                BuiltinStreamTransformPlugin::from_plugin_id(plugin_id, config, target_host)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { plugins })
    }

    pub fn validate_plugin_ids(plugin_ids: &[PluginId]) -> Result<(), StreamTransformError> {
        Self::validate_plugin_ids_with_config(plugin_ids, &StreamTransformConfig::default())
    }

    pub fn validate_plugin_ids_with_config(
        plugin_ids: &[PluginId],
        config: &StreamTransformConfig,
    ) -> Result<(), StreamTransformError> {
        Self::validate_plugin_ids_with_config_for_target(plugin_ids, config, None)
    }

    pub fn validate_plugin_ids_with_config_for_target(
        plugin_ids: &[PluginId],
        config: &StreamTransformConfig,
        target_host: Option<&str>,
    ) -> Result<(), StreamTransformError> {
        let effective_plugin_chain = validated_effective_plugin_chain(plugin_ids, config)?;
        effective_plugin_chain.iter().try_for_each(|plugin_id| {
            BuiltinStreamTransformPlugin::validate_plugin_id(plugin_id, config)
        })?;
        if effective_plugin_chain.is_empty() {
            return Ok(());
        }
        let _ = Self::from_plugin_ids_with_config_for_target(
            &effective_plugin_chain,
            config,
            target_host,
        )?;
        Ok(())
    }

    pub fn manifests(&self) -> Vec<&StreamTransformManifest> {
        self.plugins
            .iter()
            .map(BuiltinStreamTransformPlugin::manifest)
            .collect()
    }

    #[cfg(feature = "host-netd")]
    pub fn identity_digests(&self) -> Vec<(PluginId, String)> {
        self.plugins
            .iter()
            .map(BuiltinStreamTransformPlugin::identity_digest)
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    pub fn process(
        &mut self,
        direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        if bytes.is_empty() {
            return Ok(StreamTransformChunk::passthrough(bytes, None));
        }
        let mut current = None;
        let mut detail = None;
        for plugin in &mut self.plugins {
            let chunk = plugin.process(direction, current.as_deref().unwrap_or(bytes))?;
            append_detail_str(&mut detail, chunk.detail.as_deref());
            current = Some(chunk.into_bytes());
        }
        Ok(StreamTransformChunk {
            bytes: current.unwrap_or_else(|| bytes.to_vec()),
            detail,
        })
    }

    pub fn finish(&mut self) -> Result<Option<String>, StreamTransformError> {
        let mut detail = None;
        for plugin in &mut self.plugins {
            append_detail(&mut detail, plugin.finish()?);
        }
        Ok(detail)
    }

    pub fn finish_direction(
        &mut self,
        direction: StreamTransformDirection,
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        let mut current = Vec::new();
        let mut detail = None;
        for plugin in &mut self.plugins {
            let chunk = plugin.finish_direction(direction, &current)?;
            append_detail_str(&mut detail, chunk.detail.as_deref());
            current = chunk.into_bytes();
        }
        Ok(StreamTransformChunk {
            bytes: current,
            detail,
        })
    }
}

fn validated_effective_plugin_chain(
    plugin_ids: &[PluginId],
    config: &StreamTransformConfig,
) -> Result<Vec<PluginId>, StreamTransformError> {
    config.validate()?;
    let effective_plugin_chain = config.effective_plugin_chain(plugin_ids);
    if effective_plugin_chain.len() > MAX_STREAM_TRANSFORM_PLUGINS {
        return Err(StreamTransformError::PluginChainTooLong {
            count: effective_plugin_chain.len(),
            max: MAX_STREAM_TRANSFORM_PLUGINS,
        });
    }
    validate_no_duplicate_plugins(&effective_plugin_chain)?;
    Ok(effective_plugin_chain)
}

#[cfg(feature = "host-netd")]
fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}

fn validate_no_duplicate_plugins(plugin_ids: &[PluginId]) -> Result<(), StreamTransformError> {
    let mut seen = HashSet::with_capacity(plugin_ids.len());
    for plugin_id in plugin_ids {
        if !seen.insert(plugin_id.as_str()) {
            return Err(StreamTransformError::PluginDenied {
                plugin: plugin_id.clone(),
                detail: "duplicate plugin ids are not allowed in the transform chain".to_string(),
            });
        }
    }
    Ok(())
}

fn validate_stream_transform_config(
    config: &StreamTransformConfig,
) -> Result<(), StreamTransformError> {
    #[cfg(feature = "host-tls")]
    {
        let binding_count = config.secret_replacement_bindings().len();
        if binding_count > MAX_SECRET_REPLACEMENT_BINDINGS {
            return Err(StreamTransformError::PluginDenied {
                plugin: PluginId::new(SECRET_REPLACEMENT_PLUGIN_ID)
                    .expect("built-in plugin id literal must be valid"),
                detail: format_secret_replacement_binding_count_detail(binding_count),
            });
        }
        for binding in config.secret_replacement_bindings() {
            let binding_name = binding.env_var.trim();
            if binding_name.is_empty() {
                return Err(StreamTransformError::PluginDenied {
                    plugin: PluginId::new(SECRET_REPLACEMENT_PLUGIN_ID)
                        .expect("built-in plugin id literal must be valid"),
                    detail: "secret replacement binding name must not be empty".to_string(),
                });
            }
            if binding.env_var != binding_name {
                return Err(StreamTransformError::PluginDenied {
                    plugin: PluginId::new(SECRET_REPLACEMENT_PLUGIN_ID)
                        .expect("built-in plugin id literal must be valid"),
                    detail:
                        "secret replacement binding name must not contain surrounding whitespace"
                            .to_string(),
                });
            }
            if binding.value.as_ref().is_some_and(|value| value.is_empty()) {
                return Err(StreamTransformError::PluginDenied {
                    plugin: PluginId::new(SECRET_REPLACEMENT_PLUGIN_ID)
                        .expect("built-in plugin id literal must be valid"),
                    detail: format_secret_replacement_binding_empty_value_detail(binding_name),
                });
            }
            validate_secret_replacement_target_host(&binding.target_host).map_err(|detail| {
                StreamTransformError::PluginDenied {
                    plugin: PluginId::new(SECRET_REPLACEMENT_PLUGIN_ID)
                        .expect("built-in plugin id literal must be valid"),
                    detail,
                }
            })?;
            let placeholder = binding.placeholder();
            if placeholder.len() > MAX_SECRET_REPLACEMENT_PLACEHOLDER_BYTES {
                return Err(StreamTransformError::PluginDenied {
                    plugin: PluginId::new(SECRET_REPLACEMENT_PLUGIN_ID)
                        .expect("built-in plugin id literal must be valid"),
                    detail: format_secret_replacement_placeholder_too_long_detail(
                        binding_name,
                        placeholder.len(),
                    ),
                });
            }
        }
        let total_value_bytes = config
            .secret_replacement_bindings()
            .iter()
            .filter_map(|binding| binding.value.as_ref())
            .try_fold(0usize, |total, value| total.checked_add(value.len()))
            .unwrap_or(usize::MAX);
        if total_value_bytes > MAX_SECRET_REPLACEMENT_TOTAL_VALUE_BYTES {
            return Err(StreamTransformError::PluginDenied {
                plugin: PluginId::new(SECRET_REPLACEMENT_PLUGIN_ID)
                    .expect("built-in plugin id literal must be valid"),
                detail: format_secret_replacement_total_value_bytes_detail(total_value_bytes),
            });
        }
    }

    let secret_value_count = config.response_leak_guard_secret_values().len();
    if secret_value_count > MAX_RESPONSE_LEAK_GUARD_SECRET_VALUES {
        return Err(StreamTransformError::PluginDenied {
            plugin: PluginId::new(RESPONSE_LEAK_GUARD_PLUGIN_ID)
                .expect("built-in plugin id literal must be valid"),
            detail: format_response_leak_guard_secret_value_count_detail(secret_value_count),
        });
    }
    if config
        .response_leak_guard_secret_values()
        .iter()
        .any(String::is_empty)
    {
        return Err(StreamTransformError::PluginDenied {
            plugin: PluginId::new(RESPONSE_LEAK_GUARD_PLUGIN_ID)
                .expect("built-in plugin id literal must be valid"),
            detail: "response leak guard secret values must not be empty".to_string(),
        });
    }
    let mut seen_secret_values = HashSet::new();
    for secret_value in config.response_leak_guard_secret_values() {
        if !seen_secret_values.insert(secret_value) {
            return Err(StreamTransformError::PluginDenied {
                plugin: PluginId::new(RESPONSE_LEAK_GUARD_PLUGIN_ID)
                    .expect("built-in plugin id literal must be valid"),
                detail: "duplicate response leak guard secret values are not allowed".to_string(),
            });
        }
    }
    let total_secret_value_bytes = config
        .response_leak_guard_secret_values()
        .iter()
        .try_fold(0usize, |total, value| total.checked_add(value.len()))
        .unwrap_or(usize::MAX);
    if total_secret_value_bytes > MAX_RESPONSE_LEAK_GUARD_TOTAL_VALUE_BYTES {
        return Err(StreamTransformError::PluginDenied {
            plugin: PluginId::new(RESPONSE_LEAK_GUARD_PLUGIN_ID)
                .expect("built-in plugin id literal must be valid"),
            detail: format_response_leak_guard_total_value_bytes_detail(total_secret_value_bytes),
        });
    }
    let max_secret_value_bytes = config
        .response_leak_guard_secret_values()
        .iter()
        .map(String::len)
        .max()
        .unwrap_or(0);
    if max_secret_value_bytes > RESPONSE_LEAK_GUARD_MAX_BUFFERED_BYTES {
        return Err(StreamTransformError::PluginDenied {
            plugin: PluginId::new(RESPONSE_LEAK_GUARD_PLUGIN_ID)
                .expect("built-in plugin id literal must be valid"),
            detail: "known secret value exceeds response leak guard buffering budget".to_string(),
        });
    }

    Ok(())
}

#[cfg(feature = "host-tls")]
fn validate_secret_replacement_target_host(target_host: &str) -> Result<(), String> {
    validate_target_host_pattern(target_host).map_err(|err| {
        err.to_string()
            .replace("target host", "secret replacement target host")
    })
}

#[derive(Debug)]
enum BuiltinStreamTransformPlugin {
    Audit(AuditStreamTransformPlugin),
    #[cfg(test)]
    Panic(PanicStreamTransformPlugin),
    #[cfg(test)]
    Slow(SlowStreamTransformPlugin),
    #[cfg(test)]
    OverBuffer(OverBufferStreamTransformPlugin),
    #[cfg(test)]
    ObserveInput(ObserveInputStreamTransformPlugin),
    #[cfg(feature = "host-tls")]
    MetadataEndpointDeny(MetadataEndpointDenyPlugin),
    #[cfg(feature = "host-tls")]
    SecretReplacement(SecretReplacementPlugin),
    #[cfg(feature = "host-tls")]
    ResponseLeakGuard(ResponseLeakGuardPlugin),
}

impl BuiltinStreamTransformPlugin {
    fn validate_plugin_id(
        plugin_id: &PluginId,
        config: &StreamTransformConfig,
    ) -> Result<(), StreamTransformError> {
        match plugin_id.as_str() {
            AUDIT_PLUGIN_ID => Ok(()),
            #[cfg(test)]
            PANIC_CONSTRUCT_TEST_PLUGIN_ID
            | PANIC_PROCESS_TEST_PLUGIN_ID
            | PANIC_FINISH_TEST_PLUGIN_ID
            | PANIC_FINISH_DIRECTION_TEST_PLUGIN_ID => Ok(()),
            #[cfg(test)]
            SLOW_CONSTRUCT_TEST_PLUGIN_ID
            | SLOW_PROCESS_TEST_PLUGIN_ID
            | SLOW_FINISH_TEST_PLUGIN_ID
            | SLOW_FINISH_DIRECTION_TEST_PLUGIN_ID => Ok(()),
            #[cfg(test)]
            OVER_BUFFER_PROCESS_TEST_PLUGIN_ID
            | OVER_BUFFER_FINISH_TEST_PLUGIN_ID
            | OVER_BUFFER_FINISH_DIRECTION_TEST_PLUGIN_ID
            | OBSERVE_INPUT_TEST_PLUGIN_ID => Ok(()),
            METADATA_ENDPOINT_DENY_PLUGIN_ID => {
                #[cfg(feature = "host-tls")]
                {
                    let _ = config;
                    Ok(())
                }
                #[cfg(not(feature = "host-tls"))]
                {
                    let _ = config;
                    Err(StreamTransformError::PluginDenied {
                        plugin: plugin_id.clone(),
                        detail: "metadata endpoint denial requires host-tls support".to_string(),
                    })
                }
            }
            SECRET_REPLACEMENT_PLUGIN_ID => {
                #[cfg(feature = "host-tls")]
                {
                    if config.secret_replacement_bindings().is_empty() {
                        return Err(StreamTransformError::PluginDenied {
                            plugin: plugin_id.clone(),
                            detail: "no secret replacement bindings are configured".to_string(),
                        });
                    }
                    Ok(())
                }
                #[cfg(not(feature = "host-tls"))]
                {
                    let _ = config;
                    Err(StreamTransformError::PluginDenied {
                        plugin: plugin_id.clone(),
                        detail: "secret replacement requires host-tls support".to_string(),
                    })
                }
            }
            RESPONSE_LEAK_GUARD_PLUGIN_ID => {
                #[cfg(feature = "host-tls")]
                {
                    if config.response_leak_guard_secret_values().is_empty() {
                        return Err(StreamTransformError::PluginDenied {
                            plugin: plugin_id.clone(),
                            detail: "no known secret values are configured for response leak guard"
                                .to_string(),
                        });
                    }
                    let max_secret_len = config
                        .response_leak_guard_secret_values()
                        .iter()
                        .map(String::len)
                        .max()
                        .unwrap_or(0);
                    if max_secret_len > RESPONSE_LEAK_GUARD_MAX_BUFFERED_BYTES {
                        return Err(StreamTransformError::PluginDenied {
                            plugin: plugin_id.clone(),
                            detail:
                                "known secret value exceeds response leak guard buffering budget"
                                    .to_string(),
                        });
                    }
                    Ok(())
                }
                #[cfg(not(feature = "host-tls"))]
                {
                    let _ = config;
                    Err(StreamTransformError::PluginDenied {
                        plugin: plugin_id.clone(),
                        detail: "response leak guard requires host-tls support".to_string(),
                    })
                }
            }
            _ => Err(StreamTransformError::UnknownPlugin(plugin_id.clone())),
        }
    }

    fn from_plugin_id(
        plugin_id: &PluginId,
        config: &StreamTransformConfig,
        target_host: Option<&str>,
    ) -> Result<Self, StreamTransformError> {
        let timeout_budget = builtin_plugin_timeout_budget(plugin_id);
        let started = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| {
            Self::from_plugin_id_inner(plugin_id, config, target_host)
        }))
        .map_err(|_| StreamTransformError::PluginDenied {
            plugin: plugin_id.clone(),
            detail: "plugin panicked during initialization".to_string(),
        })?;
        if started.elapsed() > timeout_budget {
            return Err(StreamTransformError::PluginDenied {
                plugin: plugin_id.clone(),
                detail: "plugin exceeded timeout budget during initialization".to_string(),
            });
        }
        result
    }

    fn from_plugin_id_inner(
        plugin_id: &PluginId,
        config: &StreamTransformConfig,
        target_host: Option<&str>,
    ) -> Result<Self, StreamTransformError> {
        match plugin_id.as_str() {
            AUDIT_PLUGIN_ID => Ok(Self::Audit(AuditStreamTransformPlugin::new(
                plugin_id.clone(),
            ))),
            #[cfg(test)]
            PANIC_CONSTRUCT_TEST_PLUGIN_ID => panic!("panic-construct-test plugin panicked"),
            #[cfg(test)]
            PANIC_PROCESS_TEST_PLUGIN_ID => Ok(Self::Panic(PanicStreamTransformPlugin::new(
                plugin_id.clone(),
                true,
                false,
                false,
            ))),
            #[cfg(test)]
            PANIC_FINISH_TEST_PLUGIN_ID => Ok(Self::Panic(PanicStreamTransformPlugin::new(
                plugin_id.clone(),
                false,
                true,
                false,
            ))),
            #[cfg(test)]
            PANIC_FINISH_DIRECTION_TEST_PLUGIN_ID => Ok(Self::Panic(
                PanicStreamTransformPlugin::new(plugin_id.clone(), false, false, true),
            )),
            #[cfg(test)]
            SLOW_CONSTRUCT_TEST_PLUGIN_ID => {
                std::thread::sleep(Duration::from_millis(20));
                Ok(Self::Slow(SlowStreamTransformPlugin::new(
                    plugin_id.clone(),
                    false,
                    false,
                    false,
                )))
            }
            #[cfg(test)]
            SLOW_PROCESS_TEST_PLUGIN_ID => Ok(Self::Slow(SlowStreamTransformPlugin::new(
                plugin_id.clone(),
                true,
                false,
                false,
            ))),
            #[cfg(test)]
            SLOW_FINISH_TEST_PLUGIN_ID => Ok(Self::Slow(SlowStreamTransformPlugin::new(
                plugin_id.clone(),
                false,
                true,
                false,
            ))),
            #[cfg(test)]
            SLOW_FINISH_DIRECTION_TEST_PLUGIN_ID => Ok(Self::Slow(SlowStreamTransformPlugin::new(
                plugin_id.clone(),
                false,
                false,
                true,
            ))),
            #[cfg(test)]
            OVER_BUFFER_PROCESS_TEST_PLUGIN_ID => Ok(Self::OverBuffer(
                OverBufferStreamTransformPlugin::new(plugin_id.clone(), true, false, false),
            )),
            #[cfg(test)]
            OVER_BUFFER_FINISH_TEST_PLUGIN_ID => Ok(Self::OverBuffer(
                OverBufferStreamTransformPlugin::new(plugin_id.clone(), false, true, false),
            )),
            #[cfg(test)]
            OVER_BUFFER_FINISH_DIRECTION_TEST_PLUGIN_ID => Ok(Self::OverBuffer(
                OverBufferStreamTransformPlugin::new(plugin_id.clone(), false, false, true),
            )),
            #[cfg(test)]
            OBSERVE_INPUT_TEST_PLUGIN_ID => Ok(Self::ObserveInput(
                ObserveInputStreamTransformPlugin::new(plugin_id.clone()),
            )),
            METADATA_ENDPOINT_DENY_PLUGIN_ID => {
                #[cfg(feature = "host-tls")]
                {
                    let _ = (config, target_host);
                    Ok(Self::MetadataEndpointDeny(MetadataEndpointDenyPlugin::new(
                        plugin_id.clone(),
                    )))
                }
                #[cfg(not(feature = "host-tls"))]
                {
                    let _ = (config, target_host);
                    Err(StreamTransformError::PluginDenied {
                        plugin: plugin_id.clone(),
                        detail: "metadata endpoint denial requires host-tls support".to_string(),
                    })
                }
            }
            SECRET_REPLACEMENT_PLUGIN_ID => {
                #[cfg(feature = "host-tls")]
                {
                    Ok(Self::SecretReplacement(SecretReplacementPlugin::new(
                        plugin_id.clone(),
                        target_host,
                        config.secret_replacement_bindings().to_vec(),
                    )?))
                }
                #[cfg(not(feature = "host-tls"))]
                {
                    let _ = (config, target_host);
                    Err(StreamTransformError::PluginDenied {
                        plugin: plugin_id.clone(),
                        detail: "secret replacement requires host-tls support".to_string(),
                    })
                }
            }
            RESPONSE_LEAK_GUARD_PLUGIN_ID => {
                #[cfg(feature = "host-tls")]
                {
                    Ok(Self::ResponseLeakGuard(ResponseLeakGuardPlugin::new(
                        plugin_id.clone(),
                        config.response_leak_guard_secret_values().to_vec(),
                    )?))
                }
                #[cfg(not(feature = "host-tls"))]
                {
                    let _ = config;
                    Err(StreamTransformError::PluginDenied {
                        plugin: plugin_id.clone(),
                        detail: "response leak guard requires host-tls support".to_string(),
                    })
                }
            }
            _ => Err(StreamTransformError::UnknownPlugin(plugin_id.clone())),
        }
    }

    fn manifest(&self) -> &StreamTransformManifest {
        match self {
            Self::Audit(plugin) => plugin.manifest(),
            #[cfg(test)]
            Self::Panic(plugin) => plugin.manifest(),
            #[cfg(test)]
            Self::Slow(plugin) => plugin.manifest(),
            #[cfg(test)]
            Self::OverBuffer(plugin) => plugin.manifest(),
            #[cfg(test)]
            Self::ObserveInput(plugin) => plugin.manifest(),
            #[cfg(feature = "host-tls")]
            Self::MetadataEndpointDeny(plugin) => plugin.manifest(),
            #[cfg(feature = "host-tls")]
            Self::SecretReplacement(plugin) => plugin.manifest(),
            #[cfg(feature = "host-tls")]
            Self::ResponseLeakGuard(plugin) => plugin.manifest(),
        }
    }

    #[cfg(feature = "host-netd")]
    fn identity_digest(&self) -> (PluginId, String) {
        let manifest = self.manifest();
        (manifest.id().clone(), manifest.identity_digest_hex())
    }

    fn process(
        &mut self,
        direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        let plugin = self.manifest().id().clone();
        let timeout_budget = self.manifest().timeout_budget();
        let started = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| self.process_inner(direction, bytes)))
            .map_err(|_| StreamTransformError::PluginDenied {
                plugin: plugin.clone(),
                detail: "plugin panicked during plaintext transform".to_string(),
            })?;
        if started.elapsed() > timeout_budget {
            return Err(StreamTransformError::PluginDenied {
                plugin,
                detail: "plugin exceeded timeout budget during plaintext transform".to_string(),
            });
        }
        match result {
            Ok(chunk) => {
                if self.buffered_bytes() > self.manifest().max_buffered_bytes() {
                    return Err(StreamTransformError::PluginDenied {
                        plugin,
                        detail:
                            "plugin buffered plaintext beyond configured budget during transform"
                                .to_string(),
                    });
                }
                Ok(chunk)
            }
            Err(err) => Err(err),
        }
    }

    fn process_inner(
        &mut self,
        direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        match self {
            Self::Audit(plugin) => plugin.process(direction, bytes),
            #[cfg(test)]
            Self::Panic(plugin) => plugin.process(direction, bytes),
            #[cfg(test)]
            Self::Slow(plugin) => plugin.process(direction, bytes),
            #[cfg(test)]
            Self::OverBuffer(plugin) => plugin.process(direction, bytes),
            #[cfg(test)]
            Self::ObserveInput(plugin) => plugin.process(direction, bytes),
            #[cfg(feature = "host-tls")]
            Self::MetadataEndpointDeny(plugin) => plugin.process(direction, bytes),
            #[cfg(feature = "host-tls")]
            Self::SecretReplacement(plugin) => plugin.process(direction, bytes),
            #[cfg(feature = "host-tls")]
            Self::ResponseLeakGuard(plugin) => plugin.process(direction, bytes),
        }
    }

    fn finish(&mut self) -> Result<Option<String>, StreamTransformError> {
        let plugin = self.manifest().id().clone();
        let timeout_budget = self.manifest().timeout_budget();
        let started = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| self.finish_inner())).map_err(|_| {
            StreamTransformError::PluginDenied {
                plugin: plugin.clone(),
                detail: "plugin panicked during flow finalization".to_string(),
            }
        })?;
        if started.elapsed() > timeout_budget {
            return Err(StreamTransformError::PluginDenied {
                plugin,
                detail: "plugin exceeded timeout budget during flow finalization".to_string(),
            });
        }
        match result {
            Ok(detail) => {
                if self.buffered_bytes() > self.manifest().max_buffered_bytes() {
                    return Err(StreamTransformError::PluginDenied {
                        plugin,
                        detail:
                            "plugin buffered plaintext beyond configured budget during finalization"
                                .to_string(),
                    });
                }
                Ok(detail)
            }
            Err(err) => Err(err),
        }
    }

    fn finish_inner(&mut self) -> Result<Option<String>, StreamTransformError> {
        match self {
            Self::Audit(plugin) => Ok(plugin.finish()),
            #[cfg(test)]
            Self::Panic(plugin) => Ok(plugin.finish()),
            #[cfg(test)]
            Self::Slow(plugin) => Ok(plugin.finish()),
            #[cfg(test)]
            Self::OverBuffer(plugin) => Ok(plugin.finish()),
            #[cfg(test)]
            Self::ObserveInput(plugin) => Ok(plugin.finish()),
            #[cfg(feature = "host-tls")]
            Self::MetadataEndpointDeny(plugin) => plugin.finish(),
            #[cfg(feature = "host-tls")]
            Self::SecretReplacement(plugin) => plugin.finish(),
            #[cfg(feature = "host-tls")]
            Self::ResponseLeakGuard(plugin) => plugin.finish(),
        }
    }

    fn buffered_bytes(&self) -> usize {
        match self {
            Self::Audit(_) => 0,
            #[cfg(test)]
            Self::Panic(_) => 0,
            #[cfg(test)]
            Self::Slow(_) => 0,
            #[cfg(test)]
            Self::OverBuffer(plugin) => plugin.buffered_bytes(),
            #[cfg(test)]
            Self::ObserveInput(plugin) => plugin.buffered_bytes(),
            #[cfg(feature = "host-tls")]
            Self::MetadataEndpointDeny(plugin) => plugin.buffered_bytes(),
            #[cfg(feature = "host-tls")]
            Self::SecretReplacement(plugin) => plugin.buffered_bytes(),
            #[cfg(feature = "host-tls")]
            Self::ResponseLeakGuard(plugin) => plugin.buffered_bytes(),
        }
    }

    fn finish_direction(
        &mut self,
        direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        #[cfg(not(feature = "host-tls"))]
        let _ = direction;
        let plugin = self.manifest().id().clone();
        let timeout_budget = self.manifest().timeout_budget();
        let started = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.finish_direction_inner(direction, bytes)
        }))
        .map_err(|_| StreamTransformError::PluginDenied {
            plugin: plugin.clone(),
            detail: "plugin panicked during directional finalization".to_string(),
        })?;
        if started.elapsed() > timeout_budget {
            return Err(StreamTransformError::PluginDenied {
                plugin,
                detail: "plugin exceeded timeout budget during directional finalization"
                    .to_string(),
            });
        }
        match result {
            Ok(chunk) => {
                if self.buffered_bytes() > self.manifest().max_buffered_bytes() {
                    return Err(StreamTransformError::PluginDenied {
                        plugin,
                        detail: "plugin buffered plaintext beyond configured budget during directional finalization".to_string(),
                    });
                }
                Ok(chunk)
            }
            Err(err) => Err(err),
        }
    }

    fn finish_direction_inner(
        &mut self,
        direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        #[cfg(not(any(test, feature = "host-tls")))]
        let _ = direction;
        match self {
            Self::Audit(_) => Ok(StreamTransformChunk::passthrough(bytes, None)),
            #[cfg(test)]
            Self::Panic(plugin) => plugin.finish_direction(direction, bytes),
            #[cfg(test)]
            Self::Slow(plugin) => plugin.finish_direction(direction, bytes),
            #[cfg(test)]
            Self::OverBuffer(plugin) => plugin.finish_direction(direction, bytes),
            #[cfg(test)]
            Self::ObserveInput(plugin) => plugin.finish_direction(direction, bytes),
            #[cfg(feature = "host-tls")]
            Self::MetadataEndpointDeny(_) => Ok(StreamTransformChunk::passthrough(bytes, None)),
            #[cfg(feature = "host-tls")]
            Self::SecretReplacement(_) => Ok(StreamTransformChunk::passthrough(bytes, None)),
            #[cfg(feature = "host-tls")]
            Self::ResponseLeakGuard(plugin) => plugin.finish_direction(direction, bytes),
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
struct PanicStreamTransformPlugin {
    manifest: StreamTransformManifest,
    panic_on_process: bool,
    panic_on_finish: bool,
    panic_on_finish_direction: bool,
}

#[cfg(test)]
impl PanicStreamTransformPlugin {
    fn new(
        id: PluginId,
        panic_on_process: bool,
        panic_on_finish: bool,
        panic_on_finish_direction: bool,
    ) -> Self {
        Self {
            manifest: StreamTransformManifest::new(
                id,
                vec![StreamTransformCapability::ObservePlaintext],
                DEFAULT_PLUGIN_TIMEOUT_BUDGET,
                0,
            ),
            panic_on_process,
            panic_on_finish,
            panic_on_finish_direction,
        }
    }

    fn manifest(&self) -> &StreamTransformManifest {
        &self.manifest
    }

    fn process(
        &mut self,
        _direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        if self.panic_on_process {
            panic!("panic-process-test plugin panicked");
        }
        Ok(StreamTransformChunk::passthrough(bytes, None))
    }

    fn finish(&mut self) -> Option<String> {
        if self.panic_on_finish {
            panic!("panic-finish-test plugin panicked");
        }
        Some("plugin=panic-test finished".to_string())
    }

    fn finish_direction(
        &mut self,
        _direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        if self.panic_on_finish_direction {
            panic!("panic-finish-direction-test plugin panicked");
        }
        Ok(StreamTransformChunk::passthrough(bytes, None))
    }
}

#[cfg(test)]
#[derive(Debug)]
struct SlowStreamTransformPlugin {
    manifest: StreamTransformManifest,
    sleep_on_process: bool,
    sleep_on_finish: bool,
    sleep_on_finish_direction: bool,
}

#[cfg(test)]
impl SlowStreamTransformPlugin {
    fn new(
        id: PluginId,
        sleep_on_process: bool,
        sleep_on_finish: bool,
        sleep_on_finish_direction: bool,
    ) -> Self {
        Self {
            manifest: StreamTransformManifest::new(
                id,
                vec![StreamTransformCapability::ObservePlaintext],
                Duration::from_millis(1),
                0,
            ),
            sleep_on_process,
            sleep_on_finish,
            sleep_on_finish_direction,
        }
    }

    fn manifest(&self) -> &StreamTransformManifest {
        &self.manifest
    }

    fn process(
        &mut self,
        _direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        if self.sleep_on_process {
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(StreamTransformChunk::passthrough(bytes, None))
    }

    fn finish(&mut self) -> Option<String> {
        if self.sleep_on_finish {
            std::thread::sleep(Duration::from_millis(20));
        }
        Some("plugin=slow-test finished".to_string())
    }

    fn finish_direction(
        &mut self,
        _direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        if self.sleep_on_finish_direction {
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(StreamTransformChunk::passthrough(bytes, None))
    }
}

#[cfg(test)]
#[derive(Debug)]
struct OverBufferStreamTransformPlugin {
    manifest: StreamTransformManifest,
    buffer: Vec<u8>,
    over_buffer_on_process: bool,
    over_buffer_on_finish: bool,
    over_buffer_on_finish_direction: bool,
}

#[cfg(test)]
impl OverBufferStreamTransformPlugin {
    fn new(
        id: PluginId,
        over_buffer_on_process: bool,
        over_buffer_on_finish: bool,
        over_buffer_on_finish_direction: bool,
    ) -> Self {
        Self {
            manifest: StreamTransformManifest::new(
                id,
                vec![StreamTransformCapability::ObservePlaintext],
                DEFAULT_PLUGIN_TIMEOUT_BUDGET,
                1,
            ),
            buffer: Vec::new(),
            over_buffer_on_process,
            over_buffer_on_finish,
            over_buffer_on_finish_direction,
        }
    }

    fn manifest(&self) -> &StreamTransformManifest {
        &self.manifest
    }

    fn process(
        &mut self,
        _direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        if self.over_buffer_on_process {
            self.buffer.extend_from_slice(b"xx");
        } else {
            self.buffer.extend_from_slice(b"x");
        }
        Ok(StreamTransformChunk::passthrough(bytes, None))
    }

    fn finish(&mut self) -> Option<String> {
        if self.over_buffer_on_finish {
            self.buffer.extend_from_slice(b"x");
        }
        Some("plugin=over-buffer-test finished".to_string())
    }

    fn finish_direction(
        &mut self,
        _direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        if self.over_buffer_on_finish_direction {
            self.buffer.extend_from_slice(b"xx");
        }
        Ok(StreamTransformChunk::passthrough(bytes, None))
    }

    fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
#[derive(Debug)]
struct ObserveInputStreamTransformPlugin {
    manifest: StreamTransformManifest,
    first_input_ptr: Option<usize>,
    first_input_len: Option<usize>,
}

#[cfg(test)]
impl ObserveInputStreamTransformPlugin {
    fn new(id: PluginId) -> Self {
        Self {
            manifest: StreamTransformManifest::new(
                id,
                vec![StreamTransformCapability::ObservePlaintext],
                DEFAULT_PLUGIN_TIMEOUT_BUDGET,
                0,
            ),
            first_input_ptr: None,
            first_input_len: None,
        }
    }

    fn manifest(&self) -> &StreamTransformManifest {
        &self.manifest
    }

    fn process(
        &mut self,
        _direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        if self.first_input_ptr.is_none() {
            self.first_input_ptr = Some(bytes.as_ptr() as usize);
            self.first_input_len = Some(bytes.len());
        }
        Ok(StreamTransformChunk::passthrough(bytes, None))
    }

    fn finish(&mut self) -> Option<String> {
        None
    }

    fn finish_direction(
        &mut self,
        _direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        Ok(StreamTransformChunk::passthrough(bytes, None))
    }

    fn buffered_bytes(&self) -> usize {
        0
    }
}

#[derive(Debug)]
struct AuditStreamTransformPlugin {
    manifest: StreamTransformManifest,
    guest_to_upstream_bytes: u64,
    upstream_to_guest_bytes: u64,
}

impl AuditStreamTransformPlugin {
    fn new(id: PluginId) -> Self {
        Self {
            manifest: StreamTransformManifest::new(
                id,
                vec![StreamTransformCapability::ObservePlaintext],
                DEFAULT_PLUGIN_TIMEOUT_BUDGET,
                0,
            ),
            guest_to_upstream_bytes: 0,
            upstream_to_guest_bytes: 0,
        }
    }

    fn manifest(&self) -> &StreamTransformManifest {
        &self.manifest
    }

    fn process(
        &mut self,
        direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        let byte_count: u64 =
            bytes
                .len()
                .try_into()
                .map_err(|_| StreamTransformError::PluginDenied {
                    plugin: self.manifest.id().clone(),
                    detail: "plaintext chunk length overflowed audit accounting".to_string(),
                })?;
        let detail = match direction {
            StreamTransformDirection::GuestToUpstream => {
                self.guest_to_upstream_bytes = self
                    .guest_to_upstream_bytes
                    .checked_add(byte_count)
                    .ok_or_else(|| StreamTransformError::PluginDenied {
                        plugin: self.manifest.id().clone(),
                        detail: "guest-to-upstream plaintext byte counter overflowed".to_string(),
                    })?;
                format_audit_process_detail(
                    "guest_to_upstream",
                    bytes.len(),
                    self.guest_to_upstream_bytes,
                    self.upstream_to_guest_bytes,
                )
            }
            StreamTransformDirection::UpstreamToGuest => {
                self.upstream_to_guest_bytes = self
                    .upstream_to_guest_bytes
                    .checked_add(byte_count)
                    .ok_or_else(|| StreamTransformError::PluginDenied {
                        plugin: self.manifest.id().clone(),
                        detail: "upstream-to-guest plaintext byte counter overflowed".to_string(),
                    })?;
                format_audit_process_detail(
                    "upstream_to_guest",
                    bytes.len(),
                    self.guest_to_upstream_bytes,
                    self.upstream_to_guest_bytes,
                )
            }
        };
        Ok(StreamTransformChunk::passthrough(bytes, Some(detail)))
    }

    fn finish(&mut self) -> Option<String> {
        Some(format_audit_finish_detail(
            self.guest_to_upstream_bytes,
            self.upstream_to_guest_bytes,
        ))
    }
}

fn format_audit_process_detail(
    direction: &str,
    chunk_bytes: usize,
    guest_to_upstream_bytes: u64,
    upstream_to_guest_bytes: u64,
) -> String {
    let mut detail = String::with_capacity(
        "plugin=audit direction= chunk_bytes= totals=/".len() + direction.len() + 3 * 20,
    );
    detail.push_str("plugin=audit direction=");
    detail.push_str(direction);
    detail.push_str(" chunk_bytes=");
    append_usize_decimal(&mut detail, chunk_bytes);
    detail.push_str(" totals=");
    append_u64_decimal(&mut detail, guest_to_upstream_bytes);
    detail.push('/');
    append_u64_decimal(&mut detail, upstream_to_guest_bytes);
    detail
}

fn format_audit_finish_detail(
    guest_to_upstream_bytes: u64,
    upstream_to_guest_bytes: u64,
) -> String {
    let mut detail = String::with_capacity(
        "plugin=audit totals guest_to_upstream= upstream_to_guest=".len() + 2 * 20,
    );
    detail.push_str("plugin=audit totals guest_to_upstream=");
    append_u64_decimal(&mut detail, guest_to_upstream_bytes);
    detail.push_str(" upstream_to_guest=");
    append_u64_decimal(&mut detail, upstream_to_guest_bytes);
    detail
}

fn append_usize_decimal(formatted: &mut String, value: usize) {
    if value == 0 {
        formatted.push('0');
        return;
    }
    let mut digits = [0u8; usize::BITS as usize];
    let mut len = 0usize;
    let mut remaining = value;
    while remaining > 0 {
        digits[len] = (remaining % 10) as u8;
        remaining /= 10;
        len += 1;
    }
    while len > 0 {
        len -= 1;
        formatted.push((b'0' + digits[len]) as char);
    }
}

fn append_u64_decimal(formatted: &mut String, value: u64) {
    if value == 0 {
        formatted.push('0');
        return;
    }
    let mut digits = [0u8; u64::BITS as usize];
    let mut len = 0usize;
    let mut remaining = value;
    while remaining > 0 {
        digits[len] = (remaining % 10) as u8;
        remaining /= 10;
        len += 1;
    }
    while len > 0 {
        len -= 1;
        formatted.push((b'0' + digits[len]) as char);
    }
}

fn initial_plugin_buffer(max_buffered_bytes: usize) -> Vec<u8> {
    Vec::with_capacity(max_buffered_bytes)
}

fn initial_plugin_output_buffer(buffered_bytes: usize) -> Vec<u8> {
    Vec::with_capacity(buffered_bytes)
}

fn consume_buffer_prefix_in_place(buffer: &mut Vec<u8>, consumed: usize) {
    if consumed == 0 {
        return;
    }
    if consumed >= buffer.len() {
        buffer.clear();
        return;
    }
    buffer.copy_within(consumed.., 0);
    buffer.truncate(buffer.len() - consumed);
}

#[cfg(feature = "host-tls")]
#[derive(Debug)]
struct SecretReplacementPlugin {
    manifest: StreamTransformManifest,
    replacements: Vec<(String, String)>,
    pending_guest_to_upstream: Vec<u8>,
    total_substituted_hits: usize,
}

#[cfg(feature = "host-tls")]
impl SecretReplacementPlugin {
    fn new(
        id: PluginId,
        target_host: Option<&str>,
        bindings: Vec<SecretBinding>,
    ) -> Result<Self, StreamTransformError> {
        let target_host = target_host.ok_or_else(|| StreamTransformError::PluginDenied {
            plugin: id.clone(),
            detail: "secret replacement requires target host context".to_string(),
        })?;
        let mut replacements = bindings
            .into_iter()
            .filter_map(|binding| match decide_substitution(&binding, target_host) {
                SubstitutionVerdict::Substitute { .. } => Some(binding),
                SubstitutionVerdict::Withhold { .. } => None,
            })
            .map(|binding| {
                let value =
                    binding
                        .resolve_value()
                        .map_err(|err| StreamTransformError::PluginDenied {
                            plugin: id.clone(),
                            detail: err.to_string(),
                        })?;
                if value.is_empty() {
                    return Err(StreamTransformError::PluginDenied {
                        plugin: id.clone(),
                        detail: format_secret_replacement_empty_value_detail(&binding.env_var),
                    });
                }
                Ok((binding.placeholder(), value))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut seen_placeholders = HashSet::new();
        for (placeholder, _) in &replacements {
            if !seen_placeholders.insert(placeholder.clone()) {
                return Err(StreamTransformError::PluginDenied {
                    plugin: id.clone(),
                    detail: format_secret_replacement_duplicate_placeholder_detail(
                        placeholder,
                        target_host,
                    ),
                });
            }
        }
        if replacements.is_empty() {
            return Err(StreamTransformError::PluginDenied {
                plugin: id.clone(),
                detail: format_secret_replacement_no_bindings_for_target_detail(target_host),
            });
        }
        replacements.sort_by_key(|(placeholder, _)| std::cmp::Reverse(placeholder.len()));
        let max_buffered_bytes = replacements
            .iter()
            .map(|(placeholder, _)| placeholder.len().saturating_sub(1))
            .max()
            .unwrap_or(0)
            .max(PLACEHOLDER_PREFIX.len().saturating_sub(1));
        Ok(Self {
            manifest: StreamTransformManifest::new(
                id,
                vec![
                    StreamTransformCapability::MutatePlaintext,
                    StreamTransformCapability::ObservePlaintext,
                    StreamTransformCapability::DenyFlow,
                ],
                DEFAULT_PLUGIN_TIMEOUT_BUDGET,
                max_buffered_bytes,
            ),
            replacements,
            pending_guest_to_upstream: initial_plugin_buffer(max_buffered_bytes),
            total_substituted_hits: 0,
        })
    }

    fn manifest(&self) -> &StreamTransformManifest {
        &self.manifest
    }

    fn process(
        &mut self,
        direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        match direction {
            StreamTransformDirection::UpstreamToGuest => {
                Ok(StreamTransformChunk::passthrough(bytes, None))
            }
            StreamTransformDirection::GuestToUpstream => {
                self.pending_guest_to_upstream.extend_from_slice(bytes);
                let (rewritten, consumed, hits) = self.rewrite_guest_plaintext(false)?;
                consume_buffer_prefix_in_place(&mut self.pending_guest_to_upstream, consumed);
                self.total_substituted_hits = self
                    .total_substituted_hits
                    .checked_add(hits)
                    .ok_or_else(|| StreamTransformError::PluginDenied {
                        plugin: self.manifest.id().clone(),
                        detail: "secret replacement counter overflowed".to_string(),
                    })?;
                let detail = if hits == 0 {
                    None
                } else {
                    Some(format_secret_replacement_process_detail(hits, bytes.len()))
                };
                Ok(StreamTransformChunk {
                    bytes: rewritten,
                    detail,
                })
            }
        }
    }

    fn finish(&mut self) -> Result<Option<String>, StreamTransformError> {
        let (_rewritten, consumed, hits) = self.rewrite_guest_plaintext(true)?;
        consume_buffer_prefix_in_place(&mut self.pending_guest_to_upstream, consumed);
        debug_assert!(self.pending_guest_to_upstream.is_empty());
        self.total_substituted_hits =
            self.total_substituted_hits
                .checked_add(hits)
                .ok_or_else(|| StreamTransformError::PluginDenied {
                    plugin: self.manifest.id().clone(),
                    detail: "secret replacement counter overflowed".to_string(),
                })?;
        Ok(Some(format_secret_replacement_finish_detail(
            self.total_substituted_hits,
        )))
    }

    fn rewrite_guest_plaintext(
        &self,
        eof: bool,
    ) -> Result<(Vec<u8>, usize, usize), StreamTransformError> {
        let buffer = &self.pending_guest_to_upstream;
        let mut rewritten = initial_plugin_output_buffer(buffer.len());
        let mut hits = 0usize;
        let mut index = 0usize;
        while index < buffer.len() {
            if let Some((placeholder_len, value)) =
                full_replacement_match(buffer, index, &self.replacements)
            {
                rewritten.extend_from_slice(value.as_bytes());
                index += placeholder_len;
                hits = hits
                    .checked_add(1)
                    .ok_or_else(|| StreamTransformError::PluginDenied {
                        plugin: self.manifest.id().clone(),
                        detail: "secret replacement counter overflowed".to_string(),
                    })?;
                continue;
            }

            let remaining = &buffer[index..];
            if PLACEHOLDER_PREFIX.as_bytes().starts_with(remaining)
                && remaining.len() < PLACEHOLDER_PREFIX.len()
            {
                if eof {
                    return Err(StreamTransformError::PluginDenied {
                        plugin: self.manifest.id().clone(),
                        detail: "guest plaintext ended with an incomplete managed secret placeholder prefix"
                            .to_string(),
                    });
                }
                break;
            }

            if replacement_prefix_match(remaining, &self.replacements) {
                if eof {
                    return Err(StreamTransformError::PluginDenied {
                        plugin: self.manifest.id().clone(),
                        detail:
                            "guest plaintext ended with an incomplete managed secret placeholder"
                                .to_string(),
                    });
                }
                break;
            }

            if remaining.starts_with(PLACEHOLDER_PREFIX.as_bytes()) {
                return Err(StreamTransformError::PluginDenied {
                    plugin: self.manifest.id().clone(),
                    detail:
                        "guest plaintext still carries an unresolved managed secret placeholder"
                            .to_string(),
                });
            }

            rewritten.push(buffer[index]);
            index += 1;
        }

        Ok((rewritten, index, hits))
    }

    fn buffered_bytes(&self) -> usize {
        self.pending_guest_to_upstream.len()
    }
}

#[cfg(feature = "host-tls")]
#[derive(Debug)]
struct ResponseLeakGuardPlugin {
    manifest: StreamTransformManifest,
    secret_values: Vec<String>,
    pending_upstream_to_guest: Vec<u8>,
    max_secret_len: usize,
    total_redacted_hits: usize,
}

#[cfg(feature = "host-tls")]
impl ResponseLeakGuardPlugin {
    fn new(id: PluginId, secret_values: Vec<String>) -> Result<Self, StreamTransformError> {
        if secret_values.is_empty() {
            return Err(StreamTransformError::PluginDenied {
                plugin: id,
                detail: "no known secret values are configured for response leak guard".to_string(),
            });
        }
        let mut secret_values = secret_values;
        secret_values.sort_by_key(|value| std::cmp::Reverse(value.len()));
        let max_secret_len = secret_values.iter().map(String::len).max().unwrap_or(0);
        if max_secret_len > RESPONSE_LEAK_GUARD_MAX_BUFFERED_BYTES {
            return Err(StreamTransformError::PluginDenied {
                plugin: id,
                detail: "known secret value exceeds response leak guard buffering budget"
                    .to_string(),
            });
        }
        Ok(Self {
            manifest: StreamTransformManifest::new(
                id,
                vec![
                    StreamTransformCapability::MutatePlaintext,
                    StreamTransformCapability::ObservePlaintext,
                ],
                DEFAULT_PLUGIN_TIMEOUT_BUDGET,
                max_secret_len.saturating_sub(1),
            ),
            secret_values,
            pending_upstream_to_guest: initial_plugin_buffer(max_secret_len.saturating_sub(1)),
            max_secret_len,
            total_redacted_hits: 0,
        })
    }

    fn manifest(&self) -> &StreamTransformManifest {
        &self.manifest
    }

    fn process(
        &mut self,
        direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        match direction {
            StreamTransformDirection::GuestToUpstream => {
                Ok(StreamTransformChunk::passthrough(bytes, None))
            }
            StreamTransformDirection::UpstreamToGuest => {
                self.pending_upstream_to_guest.extend_from_slice(bytes);
                let (redacted, consumed, hits) = self.redact_upstream_plaintext(false)?;
                consume_buffer_prefix_in_place(&mut self.pending_upstream_to_guest, consumed);
                self.total_redacted_hits =
                    self.total_redacted_hits.checked_add(hits).ok_or_else(|| {
                        StreamTransformError::PluginDenied {
                            plugin: self.manifest.id().clone(),
                            detail: "response leak guard redaction counter overflowed".to_string(),
                        }
                    })?;
                let detail = if hits == 0 {
                    None
                } else {
                    Some(format_response_leak_guard_process_detail(hits, bytes.len()))
                };
                Ok(StreamTransformChunk {
                    bytes: redacted,
                    detail,
                })
            }
        }
    }

    fn finish_direction(
        &mut self,
        direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        match direction {
            StreamTransformDirection::GuestToUpstream => {
                Ok(StreamTransformChunk::passthrough(bytes, None))
            }
            StreamTransformDirection::UpstreamToGuest => {
                self.pending_upstream_to_guest.extend_from_slice(bytes);
                let (redacted, consumed, hits) = self.redact_upstream_plaintext(true)?;
                consume_buffer_prefix_in_place(&mut self.pending_upstream_to_guest, consumed);
                debug_assert!(self.pending_upstream_to_guest.is_empty());
                self.total_redacted_hits =
                    self.total_redacted_hits.checked_add(hits).ok_or_else(|| {
                        StreamTransformError::PluginDenied {
                            plugin: self.manifest.id().clone(),
                            detail: "response leak guard redaction counter overflowed".to_string(),
                        }
                    })?;
                Ok(StreamTransformChunk {
                    bytes: redacted,
                    detail: None,
                })
            }
        }
    }

    fn finish(&mut self) -> Result<Option<String>, StreamTransformError> {
        if !self.pending_upstream_to_guest.is_empty() {
            return Err(StreamTransformError::PluginDenied {
                plugin: self.manifest.id().clone(),
                detail:
                    "response leak guard still has retained upstream plaintext; directional finalization is required before flow finalization"
                        .to_string(),
            });
        }
        Ok(Some(format_response_leak_guard_finish_detail(
            self.total_redacted_hits,
        )))
    }

    fn redact_upstream_plaintext(
        &self,
        eof: bool,
    ) -> Result<(Vec<u8>, usize, usize), StreamTransformError> {
        let buffer = &self.pending_upstream_to_guest;
        let mut redacted = initial_plugin_output_buffer(buffer.len());
        let mut hits = 0usize;
        let mut index = 0usize;
        while index < buffer.len() {
            if let Some(secret_len) = full_secret_value_match(buffer, index, &self.secret_values) {
                redacted.extend_from_slice(REDACTION_MASK);
                index += secret_len;
                hits = hits
                    .checked_add(1)
                    .ok_or_else(|| StreamTransformError::PluginDenied {
                        plugin: self.manifest.id().clone(),
                        detail: "response leak guard redaction counter overflowed".to_string(),
                    })?;
                continue;
            }

            let remaining = &buffer[index..];
            if !eof
                && remaining.len() < self.max_secret_len
                && secret_value_prefix_match(remaining, &self.secret_values)
            {
                break;
            }

            redacted.push(buffer[index]);
            index += 1;
        }

        Ok((redacted, index, hits))
    }

    fn buffered_bytes(&self) -> usize {
        self.pending_upstream_to_guest.len()
    }
}

#[cfg(feature = "host-tls")]
fn format_secret_replacement_process_detail(substituted_hits: usize, chunk_bytes: usize) -> String {
    let mut detail = String::with_capacity(
        "plugin=secret-replacement substituted_hits= chunk_bytes=".len() + 2 * 20,
    );
    detail.push_str("plugin=secret-replacement substituted_hits=");
    append_usize_decimal(&mut detail, substituted_hits);
    detail.push_str(" chunk_bytes=");
    append_usize_decimal(&mut detail, chunk_bytes);
    detail
}

#[cfg(feature = "host-tls")]
fn format_secret_replacement_finish_detail(total_substituted_hits: usize) -> String {
    let mut detail =
        String::with_capacity("plugin=secret-replacement total_substituted_hits=".len() + 20);
    detail.push_str("plugin=secret-replacement total_substituted_hits=");
    append_usize_decimal(&mut detail, total_substituted_hits);
    detail
}

#[cfg(feature = "host-tls")]
fn format_secret_replacement_empty_value_detail(binding_name: &str) -> String {
    let mut detail = String::with_capacity(
        "secret replacement binding  resolved to an empty value".len() + binding_name.len(),
    );
    detail.push_str("secret replacement binding ");
    detail.push_str(binding_name);
    detail.push_str(" resolved to an empty value");
    detail
}

#[cfg(feature = "host-tls")]
fn format_secret_replacement_binding_count_detail(binding_count: usize) -> String {
    let mut detail = String::with_capacity(
        "secret replacement config has  bindings; maximum is ".len() + 2 * 20,
    );
    detail.push_str("secret replacement config has ");
    append_usize_decimal(&mut detail, binding_count);
    detail.push_str(" bindings; maximum is ");
    append_usize_decimal(&mut detail, MAX_SECRET_REPLACEMENT_BINDINGS);
    detail
}

#[cfg(feature = "host-tls")]
fn format_secret_replacement_binding_empty_value_detail(binding_name: &str) -> String {
    let mut detail = String::with_capacity(
        "secret replacement binding  must not resolve to an empty value".len() + binding_name.len(),
    );
    detail.push_str("secret replacement binding ");
    detail.push_str(binding_name);
    detail.push_str(" must not resolve to an empty value");
    detail
}

#[cfg(feature = "host-tls")]
fn format_secret_replacement_placeholder_too_long_detail(
    binding_name: &str,
    placeholder_len: usize,
) -> String {
    let mut detail = String::with_capacity(
        "secret replacement placeholder for  is  bytes; maximum is ".len()
            + binding_name.len()
            + 2 * 20,
    );
    detail.push_str("secret replacement placeholder for ");
    detail.push_str(binding_name);
    detail.push_str(" is ");
    append_usize_decimal(&mut detail, placeholder_len);
    detail.push_str(" bytes; maximum is ");
    append_usize_decimal(&mut detail, MAX_SECRET_REPLACEMENT_PLACEHOLDER_BYTES);
    detail
}

#[cfg(feature = "host-tls")]
fn format_secret_replacement_total_value_bytes_detail(total_value_bytes: usize) -> String {
    let mut detail = String::with_capacity(
        "secret replacement config has  configured secret-value bytes; maximum is ".len() + 2 * 20,
    );
    detail.push_str("secret replacement config has ");
    append_usize_decimal(&mut detail, total_value_bytes);
    detail.push_str(" configured secret-value bytes; maximum is ");
    append_usize_decimal(&mut detail, MAX_SECRET_REPLACEMENT_TOTAL_VALUE_BYTES);
    detail
}

#[cfg(feature = "host-tls")]
fn format_secret_replacement_duplicate_placeholder_detail(
    placeholder: &str,
    target_host: &str,
) -> String {
    let mut detail = String::with_capacity(
        "multiple secret replacement bindings resolve to placeholder  for target host ".len()
            + placeholder.len()
            + target_host.len(),
    );
    detail.push_str("multiple secret replacement bindings resolve to placeholder ");
    detail.push_str(placeholder);
    detail.push_str(" for target host ");
    detail.push_str(target_host);
    detail
}

#[cfg(feature = "host-tls")]
fn format_secret_replacement_no_bindings_for_target_detail(target_host: &str) -> String {
    let mut detail = String::with_capacity(
        "no secret replacement bindings are configured for target host ".len() + target_host.len(),
    );
    detail.push_str("no secret replacement bindings are configured for target host ");
    detail.push_str(target_host);
    detail
}

#[cfg(feature = "host-tls")]
fn format_response_leak_guard_process_detail(redacted_hits: usize, chunk_bytes: usize) -> String {
    let mut detail = String::with_capacity(
        "plugin=response-leak-guard redacted_hits= chunk_bytes=".len() + 2 * 20,
    );
    detail.push_str("plugin=response-leak-guard redacted_hits=");
    append_usize_decimal(&mut detail, redacted_hits);
    detail.push_str(" chunk_bytes=");
    append_usize_decimal(&mut detail, chunk_bytes);
    detail
}

#[cfg(feature = "host-tls")]
fn format_response_leak_guard_finish_detail(total_redacted_hits: usize) -> String {
    let mut detail =
        String::with_capacity("plugin=response-leak-guard total_redacted_hits=".len() + 20);
    detail.push_str("plugin=response-leak-guard total_redacted_hits=");
    append_usize_decimal(&mut detail, total_redacted_hits);
    detail
}

fn format_response_leak_guard_secret_value_count_detail(secret_value_count: usize) -> String {
    let mut detail = String::with_capacity(
        "response leak guard config has  secret values; maximum is ".len() + 2 * 20,
    );
    detail.push_str("response leak guard config has ");
    append_usize_decimal(&mut detail, secret_value_count);
    detail.push_str(" secret values; maximum is ");
    append_usize_decimal(&mut detail, MAX_RESPONSE_LEAK_GUARD_SECRET_VALUES);
    detail
}

fn format_response_leak_guard_total_value_bytes_detail(total_secret_value_bytes: usize) -> String {
    let mut detail = String::with_capacity(
        "response leak guard config has  total secret-value bytes; maximum is ".len() + 2 * 20,
    );
    detail.push_str("response leak guard config has ");
    append_usize_decimal(&mut detail, total_secret_value_bytes);
    detail.push_str(" total secret-value bytes; maximum is ");
    append_usize_decimal(&mut detail, MAX_RESPONSE_LEAK_GUARD_TOTAL_VALUE_BYTES);
    detail
}

#[cfg(feature = "host-tls")]
#[derive(Debug)]
struct MetadataEndpointDenyPlugin {
    manifest: StreamTransformManifest,
    pending_guest_to_upstream: Vec<u8>,
}

#[cfg(feature = "host-tls")]
impl MetadataEndpointDenyPlugin {
    fn new(id: PluginId) -> Self {
        Self {
            manifest: StreamTransformManifest::new(
                id,
                vec![
                    StreamTransformCapability::ObservePlaintext,
                    StreamTransformCapability::DenyFlow,
                ],
                DEFAULT_PLUGIN_TIMEOUT_BUDGET,
                METADATA_ENDPOINT_DENY_MAX_BUFFERED_BYTES,
            ),
            pending_guest_to_upstream: initial_plugin_buffer(
                METADATA_ENDPOINT_DENY_MAX_BUFFERED_BYTES,
            ),
        }
    }

    fn manifest(&self) -> &StreamTransformManifest {
        &self.manifest
    }

    fn process(
        &mut self,
        direction: StreamTransformDirection,
        bytes: &[u8],
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        match direction {
            StreamTransformDirection::UpstreamToGuest => {
                Ok(StreamTransformChunk::passthrough(bytes, None))
            }
            StreamTransformDirection::GuestToUpstream => {
                if self.pending_guest_to_upstream.is_empty() && !http_request_head_candidate(bytes)
                {
                    return Ok(StreamTransformChunk::passthrough(bytes, None));
                }
                self.pending_guest_to_upstream.extend_from_slice(bytes);
                self.flush_or_buffer_guest_request(false)
            }
        }
    }

    fn finish(&mut self) -> Result<Option<String>, StreamTransformError> {
        let chunk = self.flush_or_buffer_guest_request(true)?;
        if chunk.bytes().is_empty() {
            return Ok(None);
        }
        Ok(chunk.detail().map(ToOwned::to_owned))
    }

    fn flush_or_buffer_guest_request(
        &mut self,
        eof: bool,
    ) -> Result<StreamTransformChunk, StreamTransformError> {
        if !http_request_head_candidate(&self.pending_guest_to_upstream) {
            let bytes = self.take_pending_guest_to_upstream();
            return Ok(StreamTransformChunk::passthrough(&bytes, None));
        }

        if http2_prior_knowledge_preface_prefix(&self.pending_guest_to_upstream) {
            if self.pending_guest_to_upstream.len() >= HTTP2_PRIOR_KNOWLEDGE_PREFACE.len() || eof {
                return Err(StreamTransformError::PluginDenied {
                    plugin: self.manifest.id().clone(),
                    detail:
                        "guest plaintext HTTP/2 prior-knowledge preface is unsupported for metadata inspection"
                            .to_string(),
                });
            }
            return Ok(StreamTransformChunk::passthrough(&[], None));
        }

        if let Some(head_end) = find_http_request_head_end(&self.pending_guest_to_upstream) {
            if let Some(detail) =
                metadata_endpoint_request_denial(&self.pending_guest_to_upstream[..head_end])
            {
                return Err(StreamTransformError::PluginDenied {
                    plugin: self.manifest.id().clone(),
                    detail,
                });
            }
            let bytes = self.take_pending_guest_to_upstream();
            return Ok(StreamTransformChunk::passthrough(&bytes, None));
        }

        if self.pending_guest_to_upstream.len() >= self.manifest.max_buffered_bytes() {
            return Err(StreamTransformError::PluginDenied {
                plugin: self.manifest.id().clone(),
                detail:
                    "guest plaintext HTTP request head exceeded metadata inspection budget before terminator"
                        .to_string(),
            });
        }

        if eof {
            if let Some(detail) = metadata_endpoint_request_denial(&self.pending_guest_to_upstream)
            {
                return Err(StreamTransformError::PluginDenied {
                    plugin: self.manifest.id().clone(),
                    detail,
                });
            }
            let bytes = self.take_pending_guest_to_upstream();
            return Ok(StreamTransformChunk::passthrough(&bytes, None));
        }

        Ok(StreamTransformChunk::passthrough(&[], None))
    }

    fn take_pending_guest_to_upstream(&mut self) -> Vec<u8> {
        let capacity = self.pending_guest_to_upstream.capacity();
        std::mem::replace(
            &mut self.pending_guest_to_upstream,
            Vec::with_capacity(capacity),
        )
    }

    fn buffered_bytes(&self) -> usize {
        self.pending_guest_to_upstream.len()
    }
}

#[cfg(feature = "host-tls")]
fn full_replacement_match<'a>(
    buffer: &[u8],
    index: usize,
    replacements: &'a [(String, String)],
) -> Option<(usize, &'a str)> {
    replacements.iter().find_map(|(placeholder, value)| {
        let placeholder_bytes = placeholder.as_bytes();
        (index + placeholder_bytes.len() <= buffer.len()
            && &buffer[index..index + placeholder_bytes.len()] == placeholder_bytes)
            .then_some((placeholder_bytes.len(), value.as_str()))
    })
}

#[cfg(feature = "host-tls")]
fn replacement_prefix_match(remaining: &[u8], replacements: &[(String, String)]) -> bool {
    replacements.iter().any(|(placeholder, _)| {
        let placeholder_bytes = placeholder.as_bytes();
        remaining.len() < placeholder_bytes.len() && placeholder_bytes.starts_with(remaining)
    })
}

#[cfg(feature = "host-tls")]
fn full_secret_value_match(buffer: &[u8], index: usize, secret_values: &[String]) -> Option<usize> {
    secret_values.iter().find_map(|secret| {
        let secret_bytes = secret.as_bytes();
        (index + secret_bytes.len() <= buffer.len()
            && &buffer[index..index + secret_bytes.len()] == secret_bytes)
            .then_some(secret_bytes.len())
    })
}

#[cfg(feature = "host-tls")]
fn secret_value_prefix_match(remaining: &[u8], secret_values: &[String]) -> bool {
    secret_values.iter().any(|secret| {
        let secret_bytes = secret.as_bytes();
        remaining.len() < secret_bytes.len() && secret_bytes.starts_with(remaining)
    })
}

fn append_detail(slot: &mut Option<String>, next: Option<String>) {
    let Some(next) = next.filter(|detail| !detail.is_empty()) else {
        return;
    };
    append_detail_str(slot, Some(&next));
}

fn append_detail_str(slot: &mut Option<String>, next: Option<&str>) {
    let Some(next) = next.filter(|detail| !detail.is_empty()) else {
        return;
    };
    match slot {
        Some(existing) => {
            existing.push_str("; ");
            existing.push_str(next);
            clamp_detail_string(existing, MAX_STREAM_TRANSFORM_DETAIL_BYTES);
        }
        None => *slot = Some(clamped_detail_text(next, MAX_STREAM_TRANSFORM_DETAIL_BYTES)),
    }
}

fn clamped_detail_text(detail: &str, max_bytes: usize) -> String {
    if detail.len() <= max_bytes {
        return detail.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !detail.is_char_boundary(end) {
        end -= 1;
    }
    detail[..end].to_owned()
}

fn clamp_detail_string(detail: &mut String, max_bytes: usize) {
    if detail.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while end > 0 && !detail.is_char_boundary(end) {
        end -= 1;
    }
    detail.truncate(end);
}

#[cfg(feature = "host-tls")]
fn metadata_endpoint_request_denial(bytes: &[u8]) -> Option<String> {
    let inspected = &bytes[..bytes.len().min(HTTP_REQUEST_HEAD_INSPECTION_BYTES)];
    let text = match std::str::from_utf8(inspected) {
        Ok(text) => text,
        Err(_) => return Some("guest plaintext request head is not valid UTF-8".to_string()),
    };
    let mut lines = text.lines().map(|line| line.trim_end_matches('\r'));
    let request_line = lines.next()?;
    let (method, target, version) = match parse_http_request_line(request_line) {
        Some(parts) => parts,
        None => return Some("guest plaintext request line is malformed".to_string()),
    };
    if !is_valid_http_method_token(method) {
        return Some("guest plaintext request method is malformed".to_string());
    }
    if !is_supported_http1_version(version) {
        return Some("guest plaintext request version is malformed".to_string());
    }

    match request_target_host(method, target) {
        Ok(Some(host)) => {
            if let Some(reason) = classify_blocked_request_host(&host) {
                return Some(format_blocked_request_target_detail(&reason));
            }
        }
        Ok(None) => {}
        Err(detail) => {
            return Some(format_malformed_request_target_authority_detail(&detail));
        }
    }

    let mut current_header_name: Option<&str> = None;
    let mut current_header_value = String::new();
    let mut seen_host_header = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if matches!(line.as_bytes().first(), Some(b' ' | b'\t')) {
            if current_header_name.is_none() {
                return Some(
                    "guest plaintext request header continuation is malformed".to_string(),
                );
            }
            if !current_header_value.is_empty() {
                current_header_value.push(' ');
            }
            current_header_value.push_str(line.trim());
            continue;
        }
        let previous_header_name = current_header_name.take();
        if let Some(reason) =
            blocked_host_header_reason(previous_header_name, &current_header_value)
        {
            return Some(reason);
        }
        if previous_header_name.is_some_and(|name| name.eq_ignore_ascii_case("host")) {
            seen_host_header = true;
        }
        current_header_value.clear();
        let Some((name, value)) = line.split_once(':') else {
            return Some("guest plaintext request header line is malformed".to_string());
        };
        if name.is_empty() {
            return Some("guest plaintext request header name is malformed".to_string());
        }
        if name.chars().any(|ch| ch.is_ascii_whitespace()) {
            return Some("guest plaintext request header name contains whitespace".to_string());
        }
        if !is_valid_http_header_name(name) {
            return Some(
                "guest plaintext request header name contains invalid character".to_string(),
            );
        }
        if name.eq_ignore_ascii_case("host") && seen_host_header {
            return Some("guest plaintext request contains multiple Host headers".to_string());
        }
        current_header_name = Some(name);
        current_header_value.push_str(value.trim());
    }
    if let Some(reason) = blocked_host_header_reason(current_header_name, &current_header_value) {
        return Some(reason);
    }
    None
}

#[cfg(feature = "host-tls")]
fn find_http_request_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
        .or_else(|| {
            bytes
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|idx| idx + 2)
        })
}

#[cfg(feature = "host-tls")]
fn http_request_head_candidate(bytes: &[u8]) -> bool {
    let known_method = HTTP_METHODS
        .iter()
        .any(|method| http_method_candidate(bytes, method.as_bytes()));
    http1_leading_blank_line_candidate(bytes)
        || known_method
        || generic_http1_request_line_candidate(bytes)
        || http2_prior_knowledge_preface_prefix(bytes)
}

#[cfg(feature = "host-tls")]
fn http1_leading_blank_line_candidate(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(b'\n'))
        || matches!(bytes.first(), Some(b'\r'))
            && (bytes.len() == 1 || bytes.get(1) == Some(&b'\n'))
}

#[cfg(feature = "host-tls")]
fn http_method_candidate(bytes: &[u8], method: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.len() <= method.len() {
        return method
            .iter()
            .zip(bytes.iter())
            .all(|(expected, actual)| expected.eq_ignore_ascii_case(actual));
    }
    method
        .iter()
        .zip(bytes.iter().take(method.len()))
        .all(|(expected, actual)| expected.eq_ignore_ascii_case(actual))
        && bytes
            .get(method.len())
            .is_some_and(|byte| is_http_request_line_separator_byte(*byte))
}

#[cfg(feature = "host-tls")]
fn generic_http1_request_line_candidate(bytes: &[u8]) -> bool {
    let line_end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(bytes.len());
    let has_line_terminator = line_end < bytes.len();
    let line = bytes[..line_end]
        .strip_suffix(b"\r")
        .unwrap_or(&bytes[..line_end]);
    let Ok(line) = std::str::from_utf8(line) else {
        return generic_http1_request_line_candidate_bytes(line, has_line_terminator);
    };
    let Some((method, target, version)) = parse_http_request_line(line) else {
        if has_line_terminator {
            let mut parts = line.split_whitespace();
            let Some(method) = parts.next() else {
                return false;
            };
            let Some(target) = parts.next() else {
                return false;
            };
            let method_candidate = plausible_http_method_token(method);
            if !target_looks_http_request_target(target) || !method_candidate {
                return false;
            };
            let Some(version) = parts.next() else {
                return true;
            };
            return !version.is_empty();
        }
        let Some((method, remainder)) = split_http_request_line_method_and_remainder(line) else {
            let method = line.trim_end_matches(is_http_request_line_separator_char);
            return partial_http_method_candidate(method)
                || plausible_http_extension_method_prefix(method);
        };
        if remainder.is_empty() {
            return plausible_http_method_token(method);
        }
        let Some(target) = remainder.split_whitespace().next() else {
            return false;
        };
        return plausible_http_method_token(method) && target_looks_http_request_target(target);
    };
    if has_line_terminator {
        return plausible_http_method_token(method)
            && target_looks_http_request_target(target)
            && !version.is_empty();
    }
    plausible_http_method_token(method)
        && target_looks_http_request_target(target)
        && !version.is_empty()
}

#[cfg(feature = "host-tls")]
fn generic_http1_request_line_candidate_bytes(line: &[u8], has_line_terminator: bool) -> bool {
    if line.is_empty() {
        return false;
    }
    let mut fields = line
        .split(|byte| is_http_request_line_separator_byte(*byte))
        .filter(|field| !field.is_empty());
    let Some(method) = fields.next() else {
        return false;
    };
    let method_candidate = plausible_http_method_token_bytes(method);
    if !method_candidate {
        return false;
    }
    if has_line_terminator {
        let Some(target) = fields.next() else {
            return false;
        };
        if !target_looks_http_request_target_bytes(target) {
            return false;
        }
        let Some(version) = fields.next() else {
            return true;
        };
        return !version.is_empty();
    }
    match fields.next() {
        Some(target) => target_looks_http_request_target_bytes(target),
        None => {
            plausible_http_method_token_bytes(method)
                && plausible_http_extension_method_prefix_bytes(method)
        }
    }
}

#[cfg(feature = "host-tls")]
fn split_http_request_line_method_and_remainder(line: &str) -> Option<(&str, &str)> {
    let separator = line.find(is_http_request_line_separator_char)?;
    let method = &line[..separator];
    let remainder_start = line[separator..]
        .find(|ch| !is_http_request_line_separator_char(ch))
        .map(|offset| separator + offset)
        .unwrap_or(line.len());
    Some((method, &line[remainder_start..]))
}

#[cfg(feature = "host-tls")]
fn partial_http_method_candidate(method: &str) -> bool {
    partial_http_method_candidate_bytes(method.as_bytes())
}

#[cfg(feature = "host-tls")]
fn partial_http_method_candidate_bytes(method: &[u8]) -> bool {
    !method.is_empty()
        && HTTP_METHODS
            .iter()
            .any(|candidate| http_method_candidate(candidate.as_bytes(), method))
}

#[cfg(feature = "host-tls")]
fn plausible_http_method_token(method: &str) -> bool {
    plausible_http_method_token_bytes(method.as_bytes())
}

#[cfg(feature = "host-tls")]
fn plausible_http_method_token_bytes(method: &[u8]) -> bool {
    !method.is_empty()
        && method
            .iter()
            .copied()
            .all(|byte| !is_http_request_line_separator_byte(byte) && !byte.is_ascii_control())
}

#[cfg(feature = "host-tls")]
fn plausible_http_extension_method_prefix(method: &str) -> bool {
    plausible_http_extension_method_prefix_bytes(method.as_bytes())
}

#[cfg(feature = "host-tls")]
fn plausible_http_extension_method_prefix_bytes(method: &[u8]) -> bool {
    !method.is_empty()
        && plausible_http_method_token_bytes(method)
        && method.iter().any(u8::is_ascii_uppercase)
        && !method.iter().any(u8::is_ascii_lowercase)
}

#[cfg(feature = "host-tls")]
fn target_looks_http_request_target(target: &str) -> bool {
    target_looks_http_request_target_bytes(target.as_bytes())
}

#[cfg(feature = "host-tls")]
fn target_looks_http_request_target_bytes(target: &[u8]) -> bool {
    !target.is_empty()
        && (target.starts_with(b"/")
            || target == b"*"
            || target.windows(3).any(|window| window == b"://")
            || target.contains(&b':'))
}

#[cfg(feature = "host-tls")]
fn is_http_request_line_separator_char(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\u{000b}' | '\u{000c}')
}

#[cfg(feature = "host-tls")]
fn is_http_request_line_separator_byte(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\x0b' | b'\x0c')
}

#[cfg(feature = "host-tls")]
fn is_valid_http_method_token(method: &str) -> bool {
    is_valid_http_method_token_bytes(method.as_bytes())
}

#[cfg(feature = "host-tls")]
fn is_valid_http_method_token_bytes(method: &[u8]) -> bool {
    !method.is_empty() && method.iter().copied().all(is_http_header_name_byte)
}

#[cfg(feature = "host-tls")]
fn http2_prior_knowledge_preface_prefix(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && if bytes.len() <= HTTP2_PRIOR_KNOWLEDGE_PREFACE.len() {
            HTTP2_PRIOR_KNOWLEDGE_PREFACE.starts_with(bytes)
        } else {
            bytes.starts_with(HTTP2_PRIOR_KNOWLEDGE_PREFACE)
        }
}

#[cfg(feature = "host-tls")]
fn is_valid_http_header_name(name: &str) -> bool {
    name.bytes().all(is_http_header_name_byte)
}

#[cfg(feature = "host-tls")]
fn is_http_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(feature = "host-tls")]
fn is_supported_http1_version(version: &str) -> bool {
    matches!(version, "HTTP/1.0" | "HTTP/1.1")
}

#[cfg(feature = "host-tls")]
fn parse_http_request_line(line: &str) -> Option<(&str, &str, &str)> {
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if method.is_empty()
        || target.is_empty()
        || version.is_empty()
        || parts.next().is_some()
        || line.contains(['\t', '\x0b', '\x0c'])
    {
        return None;
    }
    Some((method, target, version))
}

#[cfg(feature = "host-tls")]
fn request_target_host(method: &str, target: &str) -> Result<Option<String>, String> {
    if method.eq_ignore_ascii_case("CONNECT") {
        return extract_authority_host(Some(target));
    }
    let Some(remainder) = split_absolute_form_target_remainder(target)? else {
        return Ok(None);
    };
    let remainder = percent_decode_target_remainder(remainder)
        .ok_or_else(|| "invalid percent-encoding in request target authority".to_string())?;
    let authority = remainder.split(['/', '\\', '?', '#']).next();
    extract_authority_host(authority)
}

#[cfg(feature = "host-tls")]
fn split_absolute_form_target_remainder(target: &str) -> Result<Option<&str>, String> {
    let Some((scheme, remainder)) = target.split_once("://") else {
        return Ok(None);
    };
    let mut chars = scheme.chars();
    let Some(first) = chars.next() else {
        return Err("invalid URI scheme in request target authority".to_string());
    };
    if !first.is_ascii_alphabetic() {
        return Err("invalid URI scheme in request target authority".to_string());
    }
    if !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.')) {
        return Err("invalid URI scheme in request target authority".to_string());
    }
    Ok(Some(remainder))
}

#[cfg(feature = "host-tls")]
fn extract_authority_host(authority: Option<&str>) -> Result<Option<String>, String> {
    let Some(authority) = authority else {
        return Ok(None);
    };
    let authority = authority.trim();
    if authority.is_empty() {
        return Err("missing host in authority".to_string());
    }
    if authority.contains('@') {
        return Err("raw userinfo delimiter in authority".to_string());
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .ok_or_else(|| "missing closing bracket in bracketed authority".to_string())?;
        let has_numeric_port_suffix = suffix.starts_with(':')
            && !suffix[1..].is_empty()
            && suffix[1..].chars().all(|ch| ch.is_ascii_digit());
        if !(suffix.is_empty() || has_numeric_port_suffix) {
            return Err("invalid suffix after bracketed authority".to_string());
        }
        let decoded = decode_authority_host(host.trim())?
            .ok_or_else(|| "missing host in authority".to_string())?;
        if !is_bracketed_ip_literal(&decoded) {
            return Err("bracketed authority must contain an IPv6-style IP literal".to_string());
        }
        return Ok(Some(decoded));
    }
    let host = if let Some((host, port)) = authority.rsplit_once(':') {
        let host_is_unbracketed_ip = is_unbracketed_ip_literal(host);
        if host.contains(':') && !host_is_unbracketed_ip {
            return Err("invalid colon-bearing authority".to_string());
        }
        if port.chars().all(|ch| ch.is_ascii_digit())
            && (!host.contains(':') || host_is_unbracketed_ip)
        {
            host
        } else if !port.chars().all(|ch| ch.is_ascii_digit()) && !host.contains(':') {
            return Err("invalid non-numeric port in authority".to_string());
        } else {
            authority
        }
    } else {
        authority
    };
    if host.trim().is_empty() {
        return Err("missing host in authority".to_string());
    }
    decode_authority_host(host.trim())
}

#[cfg(feature = "host-tls")]
fn is_unbracketed_ip_literal(host: &str) -> bool {
    let host = strip_ipv6_zone_id(host.trim());
    host.parse::<IpAddr>().is_ok()
}

#[cfg(feature = "host-tls")]
fn is_bracketed_ip_literal(host: &str) -> bool {
    let host = strip_ipv6_zone_id(host.trim());
    host.contains(':') && host.parse::<IpAddr>().is_ok()
}

#[cfg(feature = "host-tls")]
fn decode_authority_host(host: &str) -> Result<Option<String>, String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        return Err("missing host in authority".to_string());
    }
    let host = percent_decode_authority(host)
        .ok_or_else(|| "invalid percent-encoding in authority host".to_string())?;
    let host = host.trim().trim_end_matches('.');
    let host = strip_numeric_authority_port(host);
    let host = strip_ipv6_zone_id(host.trim()).trim_end_matches('.');
    if host.is_empty() {
        return Err("missing host in authority".to_string());
    }
    if host.contains(['/', '\\', '?', '#']) {
        return Err("path delimiter in authority host".to_string());
    }
    if host.chars().any(|ch| ch.is_ascii_whitespace()) {
        return Err("whitespace in authority host".to_string());
    }
    if host
        .chars()
        .any(|ch| ch.is_ascii_control() && !ch.is_ascii_whitespace())
    {
        return Err("control character in authority host".to_string());
    }
    if host.contains('@') {
        return Err("encoded userinfo delimiter in authority host".to_string());
    }
    if host.len() > MAX_HOST_NAME_BYTES {
        return Err("authority host exceeds maximum length".to_string());
    }
    let is_ip_literal = host.parse::<IpAddr>().is_ok();
    if !is_ip_literal {
        if host.contains('.') && host.split('.').any(str::is_empty) {
            return Err("empty label in authority host".to_string());
        }
        if host.split('.').any(|label| label.len() > 63) {
            return Err("overlong label in authority host".to_string());
        }
        if host
            .split('.')
            .any(|label| label.starts_with('-') || label.ends_with('-'))
        {
            return Err("edge hyphen in authority host label".to_string());
        }
        if host.split('.').any(|label| {
            !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }) {
            return Err("invalid character in authority host label".to_string());
        }
    }
    Ok(Some(host.to_ascii_lowercase()))
}

#[cfg(feature = "host-tls")]
fn percent_decode_authority(host: &str) -> Option<String> {
    percent_decode_with_preserved_bytes(host, &[])
}

#[cfg(feature = "host-tls")]
fn percent_decode_with_preserved_bytes(input: &str, preserved_bytes: &[u8]) -> Option<String> {
    if !input.as_bytes().contains(&b'%') {
        return Some(input.to_string());
    }
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] != b'%' {
            decoded.push(bytes[idx]);
            idx += 1;
            continue;
        }
        let hex = bytes.get(idx + 1..idx + 3)?;
        let value = hex_value(hex[0])?
            .checked_mul(16)?
            .checked_add(hex_value(hex[1])?)?;
        if preserved_bytes.contains(&value) {
            decoded.extend_from_slice(&bytes[idx..idx + 3]);
        } else {
            decoded.push(value);
        }
        idx += 3;
    }
    String::from_utf8(decoded).ok()
}

#[cfg(feature = "host-tls")]
fn percent_decode_target_remainder(remainder: &str) -> Option<String> {
    // Preserve `%40` so encoded `@` does not become a structural userinfo
    // delimiter before the authority parser has split on raw `@`. Preserve
    // `%25` too so bracketed RFC 6874 zone ids survive absolute-form target
    // decoding until the authority host parser can validate them explicitly.
    percent_decode_with_preserved_bytes(remainder, b"@%")
}

#[cfg(feature = "host-tls")]
fn strip_numeric_authority_port(host: &str) -> &str {
    if let Some((host_only, port)) = host.rsplit_once(':') {
        if port.chars().all(|ch| ch.is_ascii_digit())
            && (!host_only.contains(':') || is_unbracketed_ip_literal(host_only))
        {
            return host_only;
        }
    }
    host
}

#[cfg(feature = "host-tls")]
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(feature = "host-tls")]
fn classify_blocked_request_host(host: &str) -> Option<String> {
    if KNOWN_METADATA_HOSTS.contains(&host) {
        return Some(format_metadata_hostname_detail(host));
    }
    if host == "localhost" {
        return Some("localhost control-plane host".to_string());
    }
    let ip: IpAddr = host
        .parse()
        .ok()
        .or_else(|| parse_obfuscated_ipv4(host).map(IpAddr::V4))
        .map(normalize_blocked_request_ip)?;
    if is_mandatory_deny(ip) {
        return Some(format_mandatory_deny_ip_detail(ip));
    }
    None
}

#[cfg(feature = "host-tls")]
fn strip_ipv6_zone_id(host: &str) -> &str {
    if !host.contains(':') {
        return host;
    }
    host.split_once('%').map(|(addr, _)| addr).unwrap_or(host)
}

#[cfg(feature = "host-tls")]
fn blocked_host_header_reason(name: Option<&str>, value: &str) -> Option<String> {
    let name = name?;
    if !name.eq_ignore_ascii_case("host") {
        return None;
    }
    match extract_authority_host(Some(value.trim())) {
        Ok(Some(host)) => classify_blocked_request_host(&host)
            .map(|reason| format_blocked_host_header_detail(&reason)),
        Ok(None) => None,
        Err(detail) => Some(format_malformed_host_header_authority_detail(&detail)),
    }
}

#[cfg(feature = "host-tls")]
fn format_blocked_request_target_detail(reason: &str) -> String {
    let mut detail = String::with_capacity(
        "guest plaintext targets blocked endpoint via request target: ".len() + reason.len(),
    );
    detail.push_str("guest plaintext targets blocked endpoint via request target: ");
    detail.push_str(reason);
    detail
}

#[cfg(feature = "host-tls")]
fn format_malformed_request_target_authority_detail(detail_text: &str) -> String {
    let mut detail = String::with_capacity(
        "guest plaintext request target authority is malformed: ".len() + detail_text.len(),
    );
    detail.push_str("guest plaintext request target authority is malformed: ");
    detail.push_str(detail_text);
    detail
}

#[cfg(feature = "host-tls")]
fn format_metadata_hostname_detail(host: &str) -> String {
    let mut detail = String::with_capacity("metadata hostname ".len() + host.len());
    detail.push_str("metadata hostname ");
    detail.push_str(host);
    detail
}

#[cfg(feature = "host-tls")]
fn format_mandatory_deny_ip_detail(ip: IpAddr) -> String {
    let ip_text = ip.to_string();
    let mut detail = String::with_capacity("mandatory-deny IP ".len() + ip_text.len());
    detail.push_str("mandatory-deny IP ");
    detail.push_str(&ip_text);
    detail
}

#[cfg(feature = "host-tls")]
fn format_blocked_host_header_detail(reason: &str) -> String {
    let mut detail = String::with_capacity(
        "guest plaintext targets blocked endpoint via host header: ".len() + reason.len(),
    );
    detail.push_str("guest plaintext targets blocked endpoint via host header: ");
    detail.push_str(reason);
    detail
}

#[cfg(feature = "host-tls")]
fn format_malformed_host_header_authority_detail(detail_text: &str) -> String {
    let mut detail = String::with_capacity(
        "guest plaintext host header authority is malformed: ".len() + detail_text.len(),
    );
    detail.push_str("guest plaintext host header authority is malformed: ");
    detail.push_str(detail_text);
    detail
}

#[cfg(feature = "host-tls")]
fn normalize_blocked_request_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(ip),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
    }
}

#[cfg(feature = "host-tls")]
fn parse_obfuscated_ipv4(host: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let values = parts
        .iter()
        .map(|part| parse_ipv4_component(part))
        .collect::<Option<Vec<_>>>()?;
    let addr = match values.as_slice() {
        [a] => *a,
        [a, b] if *a <= 0xff && *b <= 0x00ff_ffff => (*a << 24) | *b,
        [a, b, c] if *a <= 0xff && *b <= 0xff && *c <= 0xffff => (*a << 24) | (*b << 16) | *c,
        [a, b, c, d] if *a <= 0xff && *b <= 0xff && *c <= 0xff && *d <= 0xff => {
            (*a << 24) | (*b << 16) | (*c << 8) | *d
        }
        _ => return None,
    };
    Some(Ipv4Addr::from(addr))
}

#[cfg(feature = "host-tls")]
fn parse_ipv4_component(part: &str) -> Option<u32> {
    if part.is_empty() {
        return None;
    }
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        return (!hex.is_empty())
            .then(|| u32::from_str_radix(hex, 16).ok())
            .flatten();
    }
    if part.len() > 1 && part.starts_with('0') {
        return u32::from_str_radix(part, 8).ok();
    }
    part.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_plugin_is_rejected_fail_closed() {
        let plugins = [PluginId::new("definitely-unknown").unwrap()];
        let err = StreamTransformChain::from_plugin_ids(&plugins).unwrap_err();
        assert_eq!(
            err.to_string(),
            "unknown TLS transform plugin definitely-unknown"
        );
    }

    #[test]
    fn overlong_plugin_chain_is_rejected_fail_closed() {
        let plugins: Vec<_> = (0..(MAX_STREAM_TRANSFORM_PLUGINS + 1))
            .map(|_| PluginId::new("audit").unwrap())
            .collect();
        let err = StreamTransformChain::from_plugin_ids(&plugins).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "TLS transform plugin chain has {} entries; maximum is {}",
                MAX_STREAM_TRANSFORM_PLUGINS + 1,
                MAX_STREAM_TRANSFORM_PLUGINS
            )
        );
    }

    #[test]
    fn duplicate_plugin_ids_are_rejected_fail_closed() {
        let plugins = [
            PluginId::new("audit").unwrap(),
            PluginId::new("audit").unwrap(),
        ];
        let err = StreamTransformChain::from_plugin_ids(&plugins).unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin audit denied the flow: duplicate plugin ids are not allowed in the transform chain"
        );
    }

    #[test]
    fn validate_plugin_ids_rejects_duplicate_plugin_ids() {
        let plugins = [
            PluginId::new("response-leak-guard").unwrap(),
            PluginId::new("response-leak-guard").unwrap(),
        ];
        let err = StreamTransformChain::validate_plugin_ids(&plugins).unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: duplicate plugin ids are not allowed in the transform chain"
        );
    }

    #[test]
    fn audit_plugin_chain_passthroughs_bytes_and_emits_safe_details() {
        let plugins = [PluginId::new("audit").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();

        let request = chain
            .process(StreamTransformDirection::GuestToUpstream, b"ping")
            .unwrap();
        assert_eq!(request.bytes(), b"ping");
        assert_eq!(
            request.detail(),
            Some("plugin=audit direction=guest_to_upstream chunk_bytes=4 totals=4/0")
        );

        let response = chain
            .process(StreamTransformDirection::UpstreamToGuest, b"pong")
            .unwrap();
        assert_eq!(response.bytes(), b"pong");
        assert_eq!(
            response.detail(),
            Some("plugin=audit direction=upstream_to_guest chunk_bytes=4 totals=4/4")
        );
        assert_eq!(
            chain.finish().unwrap().as_deref(),
            Some("plugin=audit totals guest_to_upstream=4 upstream_to_guest=4")
        );
    }

    #[test]
    fn empty_plugin_chain_passthroughs_non_empty_bytes() {
        let mut chain = StreamTransformChain::from_plugin_ids(&[]).expect("empty chain");

        let chunk = chain
            .process(StreamTransformDirection::GuestToUpstream, b"plain-text")
            .expect("empty chain should passthrough");

        assert_eq!(chunk.bytes(), b"plain-text");
        assert_eq!(chunk.detail(), None);
    }

    #[test]
    fn process_passes_original_input_slice_to_first_plugin() {
        let plugins = [PluginId::new(OBSERVE_INPUT_TEST_PLUGIN_ID).expect("plugin id")];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).expect("chain");
        let input = b"hello-over-vsock";

        let chunk = chain
            .process(StreamTransformDirection::GuestToUpstream, input)
            .expect("process should succeed");

        assert_eq!(chunk.bytes(), input);
        match &chain.plugins[0] {
            BuiltinStreamTransformPlugin::ObserveInput(plugin) => {
                assert_eq!(plugin.first_input_ptr, Some(input.as_ptr() as usize));
                assert_eq!(plugin.first_input_len, Some(input.len()));
            }
            other => panic!("unexpected plugin variant: {other:?}"),
        }
    }

    #[test]
    fn audit_plugin_manifest_exposes_caps_and_budgets() {
        let plugins = [PluginId::new("audit").unwrap()];
        let chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let manifests = chain.manifests();

        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].id().as_str(), "audit");
        assert_eq!(
            manifests[0].capabilities(),
            &[StreamTransformCapability::ObservePlaintext]
        );
        assert_eq!(manifests[0].timeout_budget(), DEFAULT_PLUGIN_TIMEOUT_BUDGET);
        assert_eq!(manifests[0].max_buffered_bytes(), 0);
    }

    #[cfg(feature = "host-netd")]
    #[test]
    fn built_in_plugin_identity_digests_are_sha256_hex_and_distinct() {
        let audit_chain =
            StreamTransformChain::from_plugin_ids(&[PluginId::new(AUDIT_PLUGIN_ID).unwrap()])
                .expect("audit chain");
        let response_chain = StreamTransformChain::from_plugin_ids_with_config(
            &[PluginId::new(RESPONSE_LEAK_GUARD_PLUGIN_ID).unwrap()],
            &StreamTransformConfig::default()
                .with_response_leak_guard_secret_values(["TOKEN"])
                .expect("response leak guard config"),
        )
        .expect("response leak guard chain");

        let audit_digest = audit_chain.manifests()[0].identity_digest_hex();
        let response_digest = response_chain.manifests()[0].identity_digest_hex();

        assert_eq!(audit_digest.len(), 64);
        assert_eq!(response_digest.len(), 64);
        assert!(audit_digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(response_digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(audit_digest, response_digest);
    }

    #[test]
    fn appended_stream_transform_detail_is_clamped_to_budget() {
        let mut detail = Some("x".repeat(MAX_STREAM_TRANSFORM_DETAIL_BYTES));

        append_detail(&mut detail, Some("y".to_string()));

        let detail = detail.expect("detail recorded");
        assert_eq!(detail.len(), MAX_STREAM_TRANSFORM_DETAIL_BYTES);
        assert!(detail.chars().all(|ch| ch == 'x'));
    }

    #[test]
    fn appended_stream_transform_detail_preserves_utf8_when_truncating() {
        let mut detail = Some("é".repeat((MAX_STREAM_TRANSFORM_DETAIL_BYTES / 2) + 1));

        append_detail(&mut detail, Some("é".to_string()));

        let detail = detail.expect("detail recorded");
        assert!(detail.len() <= MAX_STREAM_TRANSFORM_DETAIL_BYTES);
        assert!(detail.chars().all(|ch| ch == 'é'));
        assert!(detail.is_char_boundary(detail.len()));
    }

    #[test]
    fn appended_stream_transform_borrowed_detail_is_clamped_to_budget() {
        let mut detail = Some("x".repeat(MAX_STREAM_TRANSFORM_DETAIL_BYTES));

        append_detail_str(&mut detail, Some("y"));

        let detail = detail.expect("detail recorded");
        assert_eq!(detail.len(), MAX_STREAM_TRANSFORM_DETAIL_BYTES);
        assert!(detail.chars().all(|ch| ch == 'x'));
    }

    #[test]
    fn appended_stream_transform_borrowed_detail_preserves_utf8_when_truncating() {
        let mut detail = Some("é".repeat((MAX_STREAM_TRANSFORM_DETAIL_BYTES / 2) + 1));

        append_detail_str(&mut detail, Some("é"));

        let detail = detail.expect("detail recorded");
        assert!(detail.len() <= MAX_STREAM_TRANSFORM_DETAIL_BYTES);
        assert!(detail.chars().all(|ch| ch == 'é'));
        assert!(detail.is_char_boundary(detail.len()));
    }

    #[test]
    fn panic_in_plugin_process_is_caught_and_denied_fail_closed() {
        let plugins = [PluginId::new("panic-process-test").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();

        let err = chain
            .process(StreamTransformDirection::GuestToUpstream, b"boom")
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin panic-process-test denied the flow: plugin panicked during plaintext transform"
        );
    }

    #[test]
    fn panic_in_plugin_construction_is_caught_and_denied_fail_closed() {
        let plugins = [PluginId::new("panic-construct-test").unwrap()];
        let err = StreamTransformChain::from_plugin_ids(&plugins).unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin panic-construct-test denied the flow: plugin panicked during initialization"
        );
    }

    #[test]
    fn panic_in_plugin_finish_is_caught_and_denied_fail_closed() {
        let plugins = [PluginId::new("panic-finish-test").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let chunk = chain
            .process(StreamTransformDirection::GuestToUpstream, b"ok")
            .unwrap();
        assert_eq!(chunk.bytes(), b"ok");

        let err = chain.finish().unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin panic-finish-test denied the flow: plugin panicked during flow finalization"
        );
    }

    #[test]
    fn panic_in_plugin_finish_direction_is_caught_and_denied_fail_closed() {
        let plugins = [PluginId::new("panic-finish-direction-test").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let chunk = chain
            .process(StreamTransformDirection::UpstreamToGuest, b"ok")
            .unwrap();
        assert_eq!(chunk.bytes(), b"ok");

        let err = chain
            .finish_direction(StreamTransformDirection::UpstreamToGuest)
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin panic-finish-direction-test denied the flow: plugin panicked during directional finalization"
        );
    }

    #[test]
    fn timeout_in_plugin_process_is_caught_and_denied_fail_closed() {
        let plugins = [PluginId::new("slow-process-test").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();

        let err = chain
            .process(StreamTransformDirection::GuestToUpstream, b"slow")
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin slow-process-test denied the flow: plugin exceeded timeout budget during plaintext transform"
        );
    }

    #[test]
    fn timeout_in_plugin_construction_is_caught_and_denied_fail_closed() {
        let plugins = [PluginId::new("slow-construct-test").unwrap()];
        let err = StreamTransformChain::from_plugin_ids(&plugins).unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin slow-construct-test denied the flow: plugin exceeded timeout budget during initialization"
        );
    }

    #[test]
    fn timeout_in_plugin_finish_is_caught_and_denied_fail_closed() {
        let plugins = [PluginId::new("slow-finish-test").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let chunk = chain
            .process(StreamTransformDirection::GuestToUpstream, b"ok")
            .unwrap();
        assert_eq!(chunk.bytes(), b"ok");

        let err = chain.finish().unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin slow-finish-test denied the flow: plugin exceeded timeout budget during flow finalization"
        );
    }

    #[test]
    fn timeout_in_plugin_finish_direction_is_caught_and_denied_fail_closed() {
        let plugins = [PluginId::new("slow-finish-direction-test").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let chunk = chain
            .process(StreamTransformDirection::UpstreamToGuest, b"ok")
            .unwrap();
        assert_eq!(chunk.bytes(), b"ok");

        let err = chain
            .finish_direction(StreamTransformDirection::UpstreamToGuest)
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin slow-finish-direction-test denied the flow: plugin exceeded timeout budget during directional finalization"
        );
    }

    #[test]
    fn over_buffer_in_plugin_process_is_caught_and_denied_fail_closed() {
        let plugins = [PluginId::new("over-buffer-process-test").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();

        let err = chain
            .process(StreamTransformDirection::GuestToUpstream, b"hello")
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin over-buffer-process-test denied the flow: plugin buffered plaintext beyond configured budget during transform"
        );
    }

    #[test]
    fn over_buffer_in_plugin_finish_is_caught_and_denied_fail_closed() {
        let plugins = [PluginId::new("over-buffer-finish-test").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let chunk = chain
            .process(StreamTransformDirection::GuestToUpstream, b"ok")
            .unwrap();
        assert_eq!(chunk.bytes(), b"ok");

        let err = chain.finish().unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin over-buffer-finish-test denied the flow: plugin buffered plaintext beyond configured budget during finalization"
        );
    }

    #[test]
    fn over_buffer_in_plugin_finish_direction_is_caught_and_denied_fail_closed() {
        let plugins = [PluginId::new("over-buffer-finish-direction-test").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let chunk = chain
            .process(StreamTransformDirection::UpstreamToGuest, b"ok")
            .unwrap();
        assert_eq!(chunk.bytes(), b"ok");

        let err = chain
            .finish_direction(StreamTransformDirection::UpstreamToGuest)
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin over-buffer-finish-direction-test denied the flow: plugin buffered plaintext beyond configured budget during directional finalization"
        );
    }

    #[test]
    fn metadata_endpoint_deny_requires_host_tls_support() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        #[cfg(feature = "host-tls")]
        {
            let chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
            assert_eq!(chain.manifests().len(), 1);
        }
        #[cfg(not(feature = "host-tls"))]
        {
            let err = StreamTransformChain::from_plugin_ids(&plugins).unwrap_err();
            assert_eq!(
                err.to_string(),
                "TLS transform plugin metadata-endpoint-deny denied the flow: metadata endpoint denial requires host-tls support"
            );
        }
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_absolute_form_metadata_target() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 169.254.169.254"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_absolute_form_localhost_target() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://localhost/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: localhost control-plane host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_absolute_form_loopback_ipv4_target() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://127.0.0.1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 127.0.0.1"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_invalid_scheme_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET 1http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid URI scheme in request target authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_missing_host_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http:///latest/meta-data/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: missing host in authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_dot_only_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://./latest/meta-data/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: missing host in authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_decimal_dword_metadata_target() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://2852039166/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 169.254.169.254"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_percent_encoded_metadata_hostname_target() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://metadata%2egoogle%2einternal/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: metadata hostname metadata.google.internal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_empty_label_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://metadata..google.internal/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: empty label in authority host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_overlong_label_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let host = format!("{}.google.internal", "a".repeat(64));
        let request = format!(
            "GET http://{host}/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n"
        );
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                request.as_bytes(),
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: overlong label in authority host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_oversized_request_target_authority_host() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let host = format!(
            "{}.{}.{}.{}.{}.example.com",
            "a".repeat(50),
            "b".repeat(50),
            "c".repeat(50),
            "d".repeat(50),
            "e".repeat(50)
        );
        assert!(host.len() > MAX_HOST_NAME_BYTES);
        let request = format!(
            "GET http://{host}/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n"
        );
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                request.as_bytes(),
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: authority host exceeds maximum length"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_invalid_character_in_request_target_authority_host() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://metadata_google.internal/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid character in authority host label"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_edge_hyphen_in_request_target_authority_host() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://-metadata.google.internal/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: edge hyphen in authority host label"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_encoded_userinfo_delimiter_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://metadata.google.internal%40api.example.com/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: encoded userinfo delimiter in authority host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_raw_userinfo_delimiter_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://metadata.google.internal@api.example.com/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: raw userinfo delimiter in authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_missing_closing_bracket_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://[169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: missing closing bracket in bracketed authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_bracketed_hostname_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://[metadata.google.internal]/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: bracketed authority must contain an IPv6-style IP literal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_bracketed_ipv4_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://[169.254.169.254]/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: bracketed authority must contain an IPv6-style IP literal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_invalid_suffix_after_bracket_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://[169.254.169.254]metadata/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid suffix after bracketed authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_empty_port_after_bracket_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://[169.254.169.254]:/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid suffix after bracketed authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_non_numeric_port_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://169.254.169.254:abc/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid non-numeric port in authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_colon_bearing_hostname_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://metadata.google.internal:80:90/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid colon-bearing authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_invalid_percent_encoding_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://169.254.169.254%zz/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid percent-encoding in request target authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_whitespace_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://metadata.google.internal%20evil/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: whitespace in authority host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_control_character_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://metadata.google.internal%00evil/latest HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: control character in authority host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_unescaped_zone_id_in_request_target_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://[fe80::1%eth0]/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request target authority is malformed: invalid percent-encoding in request target authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_percent_encoded_metadata_hostname_with_port_target() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://metadata%2egoogle%2einternal%3a80/computeMetadata/v1/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: metadata hostname metadata.google.internal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_percent_encoded_path_delimiter_after_metadata_ip() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://169.254.169.254%2Flatest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 169.254.169.254"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_backslash_path_delimiter_after_metadata_ip() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://169.254.169.254\\latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 169.254.169.254"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_ipv4_mapped_metadata_target() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://[::ffff:169.254.169.254]/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 169.254.169.254"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_zone_scoped_link_local_metadata_target() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://[fe80::1%25eth0]/latest/meta-data/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP fe80::1"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_loopback_ipv6_absolute_form_target() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://[::1]/ HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP ::1"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_unbracketed_ipv6_with_port_metadata_target() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"CONNECT ::ffff:169.254.169.254:80 HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 169.254.169.254"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_host_header_metadata_hostname() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\nMetadata-Flavor: Google\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_duplicate_host_headers() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\nHost: api.example.com\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request contains multiple Host headers"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_malformed_request_line() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1 EXTRA\r\nHost: api.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request line is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_malformed_header_line() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\nHost metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request header line is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_orphaned_header_continuation_line() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\n metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request header continuation is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_empty_header_name() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\n: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request header name is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_whitespace_in_header_name() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\nHost : metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request header name contains whitespace"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_invalid_character_in_header_name() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\nHo(st: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request header name contains invalid character"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_malformed_http1_version() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1XYZ\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request version is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_non_utf8_request_head() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\nHost: metadata.\xffgoogle.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request head is not valid UTF-8"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_non_utf8_extension_method_request_line() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PROPFIND /\xffcomputeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request head is not valid UTF-8"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_split_non_utf8_invalid_method_with_target_only() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let first = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PROP\xffFIND /computeMetadata/v1/ ",
            )
            .unwrap();
        assert!(first.bytes().is_empty());
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request head is not valid UTF-8"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_non_utf8_extension_method_with_truncated_version() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PROP\xffFIND /computeMetadata/v1/ HTTP/\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request head is not valid UTF-8"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_extension_method_host_header_metadata_hostname() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PROPFIND /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_split_extension_method_host_header_metadata_hostname() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let first = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PROPFIND /computeMetadata/v1/ HT",
            )
            .unwrap();
        assert!(first.bytes().is_empty());
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"TP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_split_extension_method_prefix_host_header_metadata_hostname()
    {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let first = chain
            .process(StreamTransformDirection::GuestToUpstream, b"PROPFIND ")
            .unwrap();
        assert!(first.bytes().is_empty());
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"/computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_split_extension_method_without_space_host_header_metadata_hostname()
     {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let first = chain
            .process(StreamTransformDirection::GuestToUpstream, b"PROPFI")
            .unwrap();
        assert!(first.bytes().is_empty());
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"ND /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_long_split_extension_method_without_space_host_header_metadata_hostname()
     {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let first = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"EXTREMELYLONGCUSTOMMETHODPREFIXTOKEN",
            )
            .unwrap();
        assert!(first.bytes().is_empty());
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"CONTINUED /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_tab_separated_request_line() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET\t/computeMetadata/v1/\tHTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request line is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_request_head_with_leading_blank_line() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"\r\nGET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request line is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_split_tab_separated_request_line() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let first = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET\t/computeMetadata/v1/\tHT",
            )
            .unwrap();
        assert!(first.bytes().is_empty());
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"TP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request line is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_split_invalid_extension_method_token() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let first = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PROP(FIND /computeMetadata/v1/ HT",
            )
            .unwrap();
        assert!(first.bytes().is_empty());
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"TP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request method is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_split_invalid_extension_method_prefix() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let first = chain
            .process(StreamTransformDirection::GuestToUpstream, b"PROP(FIND ")
            .unwrap();
        assert!(first.bytes().is_empty());
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"/computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request method is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_split_invalid_extension_method_with_target_only() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let first = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PROP(FIND /computeMetadata/v1/ ",
            )
            .unwrap();
        assert!(first.bytes().is_empty());
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request method is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_split_invalid_extension_method_with_target_only_no_terminator()
     {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let first = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PROP(FIND /computeMetadata/v1/ ",
            )
            .unwrap();
        assert!(first.bytes().is_empty());
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request method is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_extension_method_request_line_missing_version() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PROPFIND /computeMetadata/v1/\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request line is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_extension_method_request_line_with_truncated_version() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PROPFIND /computeMetadata/v1/ HTTP/\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request version is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_extension_method_request_line_with_non_http_version_token() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PROPFIND /computeMetadata/v1/ XYZ\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request version is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_extension_method_request_line_with_non_http_version_token_no_terminator_first_chunk()
     {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let first = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PROPFIND /computeMetadata/v1/ XYZ",
            )
            .unwrap();
        assert!(first.bytes().is_empty());
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request version is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_non_utf8_extension_method_with_non_http_version_token() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PROP\xffFIND /computeMetadata/v1/ XYZ\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request head is not valid UTF-8"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_non_utf8_extension_method_request_line_missing_version() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PROP\xffFIND /computeMetadata/v1/\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request head is not valid UTF-8"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_non_utf8_extension_method_with_non_http_version_token_no_terminator_first_chunk()
     {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let first = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PROP\xffFIND /computeMetadata/v1/ XYZ",
            )
            .unwrap();
        assert!(first.bytes().is_empty());
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request head is not valid UTF-8"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_http2_prior_knowledge_preface() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext HTTP/2 prior-knowledge preface is unsupported for metadata inspection"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_http2_prior_knowledge_preface_with_following_bytes() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nextra",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext HTTP/2 prior-knowledge preface is unsupported for metadata inspection"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_invalid_method_token() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GE(T /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext request method is malformed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_percent_encoded_host_header_metadata_hostname() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata%2egoogle%2einternal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_empty_label_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata..google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: empty label in authority host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_overlong_label_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let host = format!("{}.google.internal", "a".repeat(64));
        let request = format!("GET /computeMetadata/v1/ HTTP/1.1\r\nHost: {host}\r\n\r\n");
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                request.as_bytes(),
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: overlong label in authority host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_oversized_host_header_authority_host() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let host = format!(
            "{}.{}.{}.{}.{}.example.com",
            "a".repeat(50),
            "b".repeat(50),
            "c".repeat(50),
            "d".repeat(50),
            "e".repeat(50)
        );
        assert!(host.len() > MAX_HOST_NAME_BYTES);
        let request = format!("GET /computeMetadata/v1/ HTTP/1.1\r\nHost: {host}\r\n\r\n");
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                request.as_bytes(),
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: authority host exceeds maximum length"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_invalid_character_in_host_header_authority_host() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata_google.internal\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: invalid character in authority host label"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_edge_hyphen_in_host_header_authority_host() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal-\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: edge hyphen in authority host label"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_encoded_userinfo_delimiter_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal%40api.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: encoded userinfo delimiter in authority host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_raw_userinfo_delimiter_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal@api.example.com\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: raw userinfo delimiter in authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_missing_closing_bracket_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /latest/meta-data/ HTTP/1.1\r\nHost: [169.254.169.254\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: missing closing bracket in bracketed authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_bracketed_hostname_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: [metadata.google.internal]\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: bracketed authority must contain an IPv6-style IP literal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_bracketed_ipv4_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /latest/meta-data/ HTTP/1.1\r\nHost: [169.254.169.254]\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: bracketed authority must contain an IPv6-style IP literal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_invalid_suffix_after_bracket_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /latest/meta-data/ HTTP/1.1\r\nHost: [169.254.169.254]metadata\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: invalid suffix after bracketed authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_empty_port_after_bracket_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /latest/meta-data/ HTTP/1.1\r\nHost: [169.254.169.254]:\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: invalid suffix after bracketed authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_non_numeric_port_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254:abc\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: invalid non-numeric port in authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_colon_bearing_hostname_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal:80:90\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: invalid colon-bearing authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_invalid_percent_encoding_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: 169.254.169.254%zz\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: invalid percent-encoding in authority host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_whitespace_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata.google.internal evil\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: whitespace in authority host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_control_character_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\nHost: metadata.google.internal%00evil\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: control character in authority host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_missing_host_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\nHost: :443\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: missing host in authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_dot_only_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\nHost: .\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: missing host in authority"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_unescaped_zone_id_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /latest/meta-data/ HTTP/1.1\r\nHost: [fe80::1%eth0]\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: invalid percent-encoding in authority host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_path_delimiter_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\nHost: metadata.google.internal/latest\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: path delimiter in authority host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_encoded_path_delimiter_in_host_header_authority() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\nHost: metadata.google.internal%2flatest\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext host header authority is malformed: path delimiter in authority host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_percent_encoded_host_header_metadata_hostname_with_port() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metadata%2egoogle%2einternal%3a80\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_localhost_host_header() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\nHost: localhost:8080\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: localhost control-plane host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_loopback_ipv4_host_header() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: mandatory-deny IP 127.0.0.1"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_loopback_ipv6_host_header() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: mandatory-deny IP ::1"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_ipv4_mapped_host_header_metadata_ip() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /latest/meta-data/ HTTP/1.1\r\nHost: [::ffff:169.254.169.254]\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: mandatory-deny IP 169.254.169.254"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_zone_scoped_link_local_host_header_metadata_ip() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /latest/meta-data/ HTTP/1.1\r\nHost: [fe80::1%25eth0]\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: mandatory-deny IP fe80::1"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_unbracketed_ipv6_with_port_host_header_metadata_ip() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /latest/meta-data/ HTTP/1.1\r\nHost: ::ffff:169.254.169.254:80\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: mandatory-deny IP 169.254.169.254"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_hex_host_header_metadata_ip() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /latest/meta-data/ HTTP/1.1\r\nHost: 0xA9FEA9FE\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: mandatory-deny IP 169.254.169.254"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_lf_only_host_header_metadata_hostname() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /computeMetadata/v1/ HTTP/1.1\nHost: metadata.google.internal\nMetadata-Flavor: Google\n\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_folded_host_header_metadata_hostname() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost:\r\n metadata.google.internal\r\nMetadata-Flavor: Google\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_connect_to_localhost() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"CONNECT localhost:8080 HTTP/1.1\r\nHost: localhost:8080\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: localhost control-plane host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_connect_to_loopback_ipv6() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"CONNECT [::1]:8080 HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP ::1"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_connect_to_loopback_ipv4() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"CONNECT 127.0.0.1:8080 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: mandatory-deny IP 127.0.0.1"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_split_host_header_metadata_hostname() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();

        let first = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET /computeMetadata/v1/ HTTP/1.1\r\nHost: metada",
            )
            .unwrap();
        assert!(first.bytes().is_empty());
        assert_eq!(first.detail(), None);

        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"ta.google.internal\r\nMetadata-Flavor: Google\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_rejects_split_connect_target() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();

        let first = chain
            .process(StreamTransformDirection::GuestToUpstream, b"CONNE")
            .unwrap();
        assert!(first.bytes().is_empty());
        assert_eq!(first.detail(), None);

        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"CT localhost:8080 HTTP/1.1\r\nHost: localhost:8080\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via request target: localhost control-plane host"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_passthroughs_non_http_binary_plaintext() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let request = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"\x16\x03\x01binary",
            )
            .unwrap();
        assert_eq!(request.bytes(), b"\x16\x03\x01binary");
        assert_eq!(request.detail(), None);
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_passthroughs_short_non_http_ascii_plaintext() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let mut chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let request = chain
            .process(StreamTransformDirection::GuestToUpstream, b"ping")
            .unwrap();
        assert_eq!(request.bytes(), b"ping");
        assert_eq!(request.detail(), None);
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_take_pending_guest_request_preserves_buffer_capacity() {
        let mut plugin = MetadataEndpointDenyPlugin::new(
            PluginId::new(METADATA_ENDPOINT_DENY_PLUGIN_ID).unwrap(),
        );
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        plugin.pending_guest_to_upstream = Vec::with_capacity(64);
        plugin.pending_guest_to_upstream.extend_from_slice(request);
        let initial_capacity = plugin.pending_guest_to_upstream.capacity();
        let initial_ptr = plugin.pending_guest_to_upstream.as_ptr();

        let bytes = plugin.take_pending_guest_to_upstream();

        assert_eq!(bytes, request);
        assert_eq!(bytes.as_ptr(), initial_ptr);
        assert!(plugin.pending_guest_to_upstream.is_empty());
        assert_eq!(
            plugin.pending_guest_to_upstream.capacity(),
            initial_capacity
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_manifest_exposes_deny_budget() {
        let plugins = [PluginId::new("metadata-endpoint-deny").unwrap()];
        let chain = StreamTransformChain::from_plugin_ids(&plugins).unwrap();
        let manifests = chain.manifests();

        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].id().as_str(), "metadata-endpoint-deny");
        assert_eq!(
            manifests[0].capabilities(),
            &[
                StreamTransformCapability::ObservePlaintext,
                StreamTransformCapability::DenyFlow,
            ]
        );
        assert_eq!(manifests[0].timeout_budget(), DEFAULT_PLUGIN_TIMEOUT_BUDGET);
        assert_eq!(
            manifests[0].max_buffered_bytes(),
            METADATA_ENDPOINT_DENY_MAX_BUFFERED_BYTES
        );
    }

    #[test]
    fn secret_replacement_requires_bindings() {
        let plugins = [PluginId::new("secret-replacement").unwrap()];
        let err = StreamTransformChain::from_plugin_ids_with_config_for_target(
            &plugins,
            &StreamTransformConfig::default(),
            Some("api.example.com"),
        )
        .unwrap_err();
        #[cfg(feature = "host-tls")]
        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: no secret replacement bindings are configured for target host api.example.com"
        );
        #[cfg(not(feature = "host-tls"))]
        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: secret replacement requires host-tls support"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_rewrites_guest_plaintext_for_bound_host_only() {
        let plugins = [PluginId::new("secret-replacement").unwrap()];
        let config = StreamTransformConfig::default()
            .with_secret_replacement_bindings([
                SecretBinding::new("OPENAI_API_KEY", "api.example.com").with_value("sk-live-12345"),
                SecretBinding::new("IGNORED", "other.example.com").with_value("unused"),
            ])
            .expect("secret replacement config is valid");
        let mut chain = StreamTransformChain::from_plugin_ids_with_config_for_target(
            &plugins,
            &config,
            Some("api.example.com"),
        )
        .unwrap();

        let request = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"authorization=mvm-managed:OPENAI_API_KEY",
            )
            .unwrap();
        assert_eq!(request.bytes(), b"authorization=sk-live-12345");
        assert_eq!(
            request.detail(),
            Some("plugin=secret-replacement substituted_hits=1 chunk_bytes=40")
        );

        let response = chain
            .process(
                StreamTransformDirection::UpstreamToGuest,
                b"echo sk-live-12345",
            )
            .unwrap();
        assert_eq!(response.bytes(), b"echo sk-live-12345");
        assert_eq!(response.detail(), None);
        assert_eq!(
            chain.finish().unwrap().as_deref(),
            Some("plugin=secret-replacement total_substituted_hits=1")
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_rejects_duplicate_placeholders_for_same_target_host() {
        let plugins = [PluginId::new("secret-replacement").unwrap()];
        let config = StreamTransformConfig::default()
            .with_secret_replacement_bindings([
                SecretBinding::new("OPENAI_API_KEY", "api.example.com").with_value("sk-live-1"),
                SecretBinding::new("OPENAI_API_KEY", "*.example.com").with_value("sk-live-2"),
            ])
            .expect("secret replacement config is structurally valid");

        let err = StreamTransformChain::from_plugin_ids_with_config_for_target(
            &plugins,
            &config,
            Some("api.example.com"),
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: multiple secret replacement bindings resolve to placeholder mvm-managed:OPENAI_API_KEY for target host api.example.com"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_allows_duplicate_binding_names_for_disjoint_target_hosts() {
        let plugins = [PluginId::new("secret-replacement").unwrap()];
        let config = StreamTransformConfig::default()
            .with_secret_replacement_bindings([
                SecretBinding::new("OPENAI_API_KEY", "api.example.com").with_value("sk-api"),
                SecretBinding::new("OPENAI_API_KEY", "vault.example.com").with_value("sk-vault"),
            ])
            .expect("secret replacement config is structurally valid");
        let mut chain = StreamTransformChain::from_plugin_ids_with_config_for_target(
            &plugins,
            &config,
            Some("api.example.com"),
        )
        .expect("only one binding applies to api.example.com");

        let request = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"authorization=mvm-managed:OPENAI_API_KEY",
            )
            .unwrap();
        assert_eq!(request.bytes(), b"authorization=sk-api");
        assert_eq!(
            chain.finish().unwrap().as_deref(),
            Some("plugin=secret-replacement total_substituted_hits=1")
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn effective_plugin_chain_orders_secret_replacement_before_metadata_endpoint_deny() {
        let config = StreamTransformConfig::default()
            .with_secret_replacement_bindings([SecretBinding::new(
                "OPENAI_API_KEY",
                "api.example.com",
            )
            .with_value("metadata.google.internal")])
            .expect("secret replacement config is valid");
        let chain = config.effective_plugin_chain(&[
            PluginId::new("audit").unwrap(),
            PluginId::new("metadata-endpoint-deny").unwrap(),
        ]);

        let plugin_ids = chain
            .iter()
            .map(|plugin_id| plugin_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            plugin_ids,
            vec!["audit", "secret-replacement", "metadata-endpoint-deny"]
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn effective_plugin_chain_seeds_capacity_for_auto_appended_builtins() {
        let config = StreamTransformConfig::default()
            .with_secret_replacement_bindings([SecretBinding::new(
                "OPENAI_API_KEY",
                "api.example.com",
            )
            .with_value("sk-api")])
            .expect("secret replacement config is valid")
            .with_response_leak_guard_secret_values(["sk-api"])
            .expect("response leak guard config is valid");
        let chain =
            config.effective_plugin_chain(&[PluginId::new("metadata-endpoint-deny").unwrap()]);

        assert_eq!(chain.capacity(), 3);
        let plugin_ids = chain
            .iter()
            .map(|plugin_id| plugin_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            plugin_ids,
            vec![
                "secret-replacement",
                "metadata-endpoint-deny",
                "response-leak-guard",
            ]
        );
    }

    #[test]
    fn effective_plugin_chain_orders_audit_before_other_plugins() {
        let config = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values(["secret-token"])
            .expect("response leak guard config is valid");
        let chain = config.effective_plugin_chain(&[
            PluginId::new("response-leak-guard").unwrap(),
            PluginId::new("audit").unwrap(),
        ]);

        let plugin_ids = chain
            .iter()
            .map(|plugin_id| plugin_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(plugin_ids, vec!["audit", "response-leak-guard"]);
    }

    #[cfg(feature = "host-netd")]
    #[test]
    fn chain_identity_digests_follow_effective_plugin_order() {
        let config = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values(["TOKEN"])
            .expect("response leak guard config is valid");
        let chain = StreamTransformChain::from_plugin_ids_with_config(
            &[
                PluginId::new(METADATA_ENDPOINT_DENY_PLUGIN_ID).unwrap(),
                PluginId::new(AUDIT_PLUGIN_ID).unwrap(),
            ],
            &config,
        )
        .expect("chain should build");

        let digests = chain.identity_digests();
        let manifests = chain.manifests();

        assert_eq!(digests.len(), manifests.len());
        assert_eq!(digests[0].0.as_str(), AUDIT_PLUGIN_ID);
        assert_eq!(digests[1].0.as_str(), METADATA_ENDPOINT_DENY_PLUGIN_ID);
        assert_eq!(digests[2].0.as_str(), RESPONSE_LEAK_GUARD_PLUGIN_ID);
        for ((plugin_id, digest), manifest) in digests.iter().zip(manifests.iter()) {
            assert_eq!(plugin_id, manifest.id());
            assert_eq!(digest, &manifest.identity_digest_hex());
        }
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_runs_before_metadata_endpoint_deny_for_placeholder_host_header() {
        let config = StreamTransformConfig::default()
            .with_secret_replacement_bindings([SecretBinding::new(
                "OPENAI_API_KEY",
                "api.example.com",
            )
            .with_value("metadata.google.internal")])
            .expect("secret replacement config is valid");
        let mut chain = StreamTransformChain::from_plugin_ids_with_config_for_target(
            &[PluginId::new("metadata-endpoint-deny").unwrap()],
            &config,
            Some("api.example.com"),
        )
        .expect("metadata guard plus secret replacement chain should build");

        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"GET / HTTP/1.1\r\nHost: mvm-managed:OPENAI_API_KEY\r\n\r\n",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin metadata-endpoint-deny denied the flow: guest plaintext targets blocked endpoint via host header: metadata hostname metadata.google.internal"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn audit_runs_before_response_leak_guard_even_when_requested_after_it() {
        let config = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values(["secret-token"])
            .expect("response leak guard config is valid");
        let mut chain = StreamTransformChain::from_plugin_ids_with_config_for_target(
            &[
                PluginId::new("response-leak-guard").unwrap(),
                PluginId::new("audit").unwrap(),
            ],
            &config,
            Some("api.example.com"),
        )
        .expect("audit plus leak guard chain should build");

        let redacted = chain
            .process(StreamTransformDirection::UpstreamToGuest, b"secret-token")
            .unwrap();
        assert_eq!(redacted.bytes(), REDACTION_MASK);
        assert_eq!(
            redacted.detail(),
            Some(
                "plugin=audit direction=upstream_to_guest chunk_bytes=12 totals=0/12; plugin=response-leak-guard redacted_hits=1 chunk_bytes=12"
            )
        );
        assert_eq!(
            chain.finish().unwrap().as_deref(),
            Some(
                "plugin=audit totals guest_to_upstream=0 upstream_to_guest=12; plugin=response-leak-guard total_redacted_hits=1"
            )
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_rewrites_file_mount_placeholder_for_bound_host() {
        let plugins = [PluginId::new("secret-replacement").unwrap()];
        let config = StreamTransformConfig::default()
            .with_secret_replacement_bindings([SecretBinding::new(
                "/run/mvm-secrets/openai",
                "api.example.com",
            )
            .with_value("sk-live-12345")])
            .expect("secret replacement config is valid");
        let mut chain = StreamTransformChain::from_plugin_ids_with_config_for_target(
            &plugins,
            &config,
            Some("api.example.com"),
        )
        .unwrap();

        let request = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"authorization=mvm-managed:/run/mvm-secrets/openai",
            )
            .unwrap();
        assert_eq!(request.bytes(), b"authorization=sk-live-12345");
        assert_eq!(
            request.detail(),
            Some("plugin=secret-replacement substituted_hits=1 chunk_bytes=49")
        );
        assert_eq!(
            chain.finish().unwrap().as_deref(),
            Some("plugin=secret-replacement total_substituted_hits=1")
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_rewrites_placeholder_split_across_chunks() {
        let plugins = [PluginId::new("secret-replacement").unwrap()];
        let config = StreamTransformConfig::default()
            .with_secret_replacement_bindings([SecretBinding::new(
                "OPENAI_API_KEY",
                "api.example.com",
            )
            .with_value("sk-live-12345")])
            .expect("secret replacement config is valid");
        let mut chain = StreamTransformChain::from_plugin_ids_with_config_for_target(
            &plugins,
            &config,
            Some("api.example.com"),
        )
        .unwrap();

        let first = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"authorization=mvm-managed:OPENAI_",
            )
            .unwrap();
        assert_eq!(first.bytes(), b"authorization=");
        assert_eq!(first.detail(), None);

        let second = chain
            .process(StreamTransformDirection::GuestToUpstream, b"API_KEY")
            .unwrap();
        assert_eq!(second.bytes(), b"sk-live-12345");
        assert_eq!(
            second.detail(),
            Some("plugin=secret-replacement substituted_hits=1 chunk_bytes=7")
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_finish_denies_split_unresolved_placeholder() {
        let plugins = [PluginId::new("secret-replacement").unwrap()];
        let config = StreamTransformConfig::default()
            .with_secret_replacement_bindings([SecretBinding::new(
                "OPENAI_API_KEY",
                "api.example.com",
            )
            .with_value("sk-live-12345")])
            .expect("secret replacement config is valid");
        let mut chain = StreamTransformChain::from_plugin_ids_with_config_for_target(
            &plugins,
            &config,
            Some("api.example.com"),
        )
        .unwrap();

        let first = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"authorization=mvm-managed:OPENAI_",
            )
            .unwrap();
        assert_eq!(first.bytes(), b"authorization=");
        assert_eq!(first.detail(), None);

        let err = chain.finish().unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: guest plaintext ended with an incomplete managed secret placeholder"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_denies_unresolved_managed_placeholder() {
        let plugins = [PluginId::new("secret-replacement").unwrap()];
        let config = StreamTransformConfig::default()
            .with_secret_replacement_bindings([SecretBinding::new(
                "OPENAI_API_KEY",
                "api.example.com",
            )
            .with_value("sk-live-12345")])
            .expect("secret replacement config is valid");
        let mut chain = StreamTransformChain::from_plugin_ids_with_config_for_target(
            &plugins,
            &config,
            Some("api.example.com"),
        )
        .unwrap();

        let err = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"authorization=mvm-managed:OTHER_SECRET",
            )
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: guest plaintext still carries an unresolved managed secret placeholder"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_manifest_exposes_mutation_budget() {
        let plugins = [PluginId::new("secret-replacement").unwrap()];
        let config = StreamTransformConfig::default()
            .with_secret_replacement_bindings([SecretBinding::new(
                "OPENAI_API_KEY",
                "api.example.com",
            )
            .with_value("sk-live-12345")])
            .expect("secret replacement config is valid");
        let chain = StreamTransformChain::from_plugin_ids_with_config_for_target(
            &plugins,
            &config,
            Some("api.example.com"),
        )
        .unwrap();
        let manifests = chain.manifests();

        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].id().as_str(), "secret-replacement");
        assert_eq!(
            manifests[0].capabilities(),
            &[
                StreamTransformCapability::MutatePlaintext,
                StreamTransformCapability::ObservePlaintext,
                StreamTransformCapability::DenyFlow,
            ]
        );
        assert_eq!(manifests[0].timeout_budget(), DEFAULT_PLUGIN_TIMEOUT_BUDGET);
        assert_eq!(
            manifests[0].max_buffered_bytes(),
            "mvm-managed:OPENAI_API_KEY".len() - 1
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_seeds_pending_buffer_capacity_from_manifest_budget() {
        let plugin = SecretReplacementPlugin::new(
            PluginId::new(SECRET_REPLACEMENT_PLUGIN_ID).expect("plugin id"),
            Some("api.example.com"),
            vec![
                SecretBinding::new("OPENAI_API_KEY", "api.example.com").with_value("sk-live-12345"),
            ],
        )
        .expect("secret replacement plugin should construct");

        assert_eq!(
            plugin.pending_guest_to_upstream.capacity(),
            plugin.manifest.max_buffered_bytes()
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_noop_rewrite_seeds_output_capacity_from_buffer_len() {
        let mut plugin = SecretReplacementPlugin::new(
            PluginId::new(SECRET_REPLACEMENT_PLUGIN_ID).expect("plugin id"),
            Some("api.example.com"),
            vec![
                SecretBinding::new("OPENAI_API_KEY", "api.example.com").with_value("sk-live-12345"),
            ],
        )
        .expect("secret replacement plugin should construct");
        plugin
            .pending_guest_to_upstream
            .extend_from_slice(b"plain-text");

        let (rewritten, consumed, hits) = plugin
            .rewrite_guest_plaintext(false)
            .expect("no-op rewrite should succeed");

        assert_eq!(rewritten, b"plain-text");
        assert_eq!(consumed, b"plain-text".len());
        assert_eq!(hits, 0);
        assert_eq!(rewritten.capacity(), b"plain-text".len());
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_process_preserves_pending_buffer_capacity_when_suffix_is_retained() {
        let mut plugin = SecretReplacementPlugin::new(
            PluginId::new(SECRET_REPLACEMENT_PLUGIN_ID).expect("plugin id"),
            Some("api.example.com"),
            vec![
                SecretBinding::new("OPENAI_API_KEY", "api.example.com").with_value("sk-live-12345"),
            ],
        )
        .expect("secret replacement plugin should construct");
        plugin.pending_guest_to_upstream = Vec::with_capacity(64);
        plugin
            .pending_guest_to_upstream
            .extend_from_slice(b"prefix-mvm-man");
        let initial_capacity = plugin.pending_guest_to_upstream.capacity();

        let chunk = plugin
            .process(StreamTransformDirection::GuestToUpstream, b"")
            .expect("partial placeholder should buffer");

        assert_eq!(chunk.bytes(), b"prefix-");
        assert_eq!(plugin.pending_guest_to_upstream, b"mvm-man");
        assert_eq!(
            plugin.pending_guest_to_upstream.capacity(),
            initial_capacity
        );
    }

    #[test]
    fn response_leak_guard_requires_secret_values() {
        let plugins = [PluginId::new("response-leak-guard").unwrap()];
        let err = StreamTransformChain::from_plugin_ids(&plugins).unwrap_err();
        #[cfg(feature = "host-tls")]
        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: no known secret values are configured for response leak guard"
        );
        #[cfg(not(feature = "host-tls"))]
        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: response leak guard requires host-tls support"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn response_leak_guard_redacts_upstream_plaintext_only() {
        let plugins = [PluginId::new("response-leak-guard").unwrap()];
        let config = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values(["sk-live-12345"])
            .expect("response leak guard config is valid");
        let mut chain =
            StreamTransformChain::from_plugin_ids_with_config(&plugins, &config).unwrap();

        let request = chain
            .process(
                StreamTransformDirection::GuestToUpstream,
                b"authorization=sk-live-12345",
            )
            .unwrap();
        assert_eq!(request.bytes(), b"authorization=sk-live-12345");
        assert_eq!(request.detail(), None);

        let response = chain
            .process(
                StreamTransformDirection::UpstreamToGuest,
                b"echo sk-live-12345 from upstream",
            )
            .unwrap();
        assert_ne!(response.bytes(), b"echo sk-live-12345 from upstream");
        assert!(
            !response
                .bytes()
                .windows("sk-live-12345".len())
                .any(|w| w == b"sk-live-12345")
        );
        assert_eq!(
            response.detail(),
            Some("plugin=response-leak-guard redacted_hits=1 chunk_bytes=32")
        );
        assert_eq!(
            chain.finish().unwrap().as_deref(),
            Some("plugin=response-leak-guard total_redacted_hits=1")
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn response_leak_guard_preserves_secret_value_whitespace_exactly() {
        let plugins = [PluginId::new("response-leak-guard").unwrap()];
        let config = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values(["  sk-live-12345  "])
            .expect("response leak guard config is valid");
        let mut chain =
            StreamTransformChain::from_plugin_ids_with_config(&plugins, &config).unwrap();

        let passthrough = chain
            .process(StreamTransformDirection::UpstreamToGuest, b"sk-live-12345")
            .unwrap();
        assert_eq!(passthrough.bytes(), b"sk-live-12345");
        assert_eq!(passthrough.detail(), None);

        let redacted = chain
            .process(
                StreamTransformDirection::UpstreamToGuest,
                b"  sk-live-12345  ",
            )
            .unwrap();
        assert_eq!(redacted.bytes(), REDACTION_MASK);
        assert_eq!(
            redacted.detail(),
            Some("plugin=response-leak-guard redacted_hits=1 chunk_bytes=17")
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn empty_response_leak_guard_secret_value_is_rejected_fail_closed() {
        let err = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values([""])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: response leak guard secret values must not be empty"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn duplicate_response_leak_guard_secret_value_is_rejected_fail_closed() {
        let err = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values(["sk-live-12345", "sk-live-12345"])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: duplicate response leak guard secret values are not allowed"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn response_leak_guard_redacts_secret_split_across_chunks() {
        let plugins = [PluginId::new("response-leak-guard").unwrap()];
        let config = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values(["sk-live-12345"])
            .expect("response leak guard config is valid");
        let mut chain =
            StreamTransformChain::from_plugin_ids_with_config(&plugins, &config).unwrap();

        let first = chain
            .process(StreamTransformDirection::UpstreamToGuest, b"echo sk-l")
            .unwrap();
        assert_eq!(first.bytes(), b"echo ");
        assert_eq!(first.detail(), None);

        let second = chain
            .process(
                StreamTransformDirection::UpstreamToGuest,
                b"ive-12345 from upstream",
            )
            .unwrap();
        let expected = format!("{} from upstream", String::from_utf8_lossy(REDACTION_MASK));
        assert_eq!(String::from_utf8(second.into_bytes()).unwrap(), expected);
        assert_eq!(
            chain.finish().unwrap().as_deref(),
            Some("plugin=response-leak-guard total_redacted_hits=1")
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn response_leak_guard_finish_direction_flushes_split_nonsecret_tail() {
        let plugins = [PluginId::new("response-leak-guard").unwrap()];
        let config = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values(["TOKEN"])
            .expect("response leak guard config is valid");
        let mut chain =
            StreamTransformChain::from_plugin_ids_with_config(&plugins, &config).unwrap();

        let first = chain
            .process(StreamTransformDirection::UpstreamToGuest, b"echo TO")
            .unwrap();
        assert_eq!(first.bytes(), b"echo ");

        let tail = chain
            .finish_direction(StreamTransformDirection::UpstreamToGuest)
            .unwrap();
        assert_eq!(tail.bytes(), b"TO");
        assert_eq!(tail.detail(), None);
        assert_eq!(
            chain.finish().unwrap().as_deref(),
            Some("plugin=response-leak-guard total_redacted_hits=0")
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn response_leak_guard_finish_denies_when_directional_finalization_was_skipped() {
        let plugins = [PluginId::new("response-leak-guard").unwrap()];
        let config = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values(["TOKEN"])
            .expect("response leak guard config is valid");
        let mut chain =
            StreamTransformChain::from_plugin_ids_with_config(&plugins, &config).unwrap();

        let chunk = chain
            .process(StreamTransformDirection::UpstreamToGuest, b"prefix-TO")
            .expect("partial secret should buffer");
        assert_eq!(chunk.bytes(), b"prefix-");

        let err = chain.finish().unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: response leak guard still has retained upstream plaintext; directional finalization is required before flow finalization"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn response_leak_guard_rejects_overlong_secret_value() {
        let too_long_secret = "x".repeat(RESPONSE_LEAK_GUARD_MAX_BUFFERED_BYTES + 1);
        let err = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values([too_long_secret])
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: known secret value exceeds response leak guard buffering budget"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn response_leak_guard_validation_rejects_overlong_secret_value() {
        let plugins = [PluginId::new("response-leak-guard").unwrap()];
        let too_long_secret = "x".repeat(RESPONSE_LEAK_GUARD_MAX_BUFFERED_BYTES + 1);
        let err = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values([too_long_secret])
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: known secret value exceeds response leak guard buffering budget"
        );
        let empty_config = StreamTransformConfig::default();
        let err = StreamTransformChain::validate_plugin_ids_with_config(&plugins, &empty_config)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: no known secret values are configured for response leak guard"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn overlong_secret_replacement_binding_count_is_rejected_fail_closed() {
        let err = StreamTransformConfig::default()
            .with_secret_replacement_bindings((0..(MAX_SECRET_REPLACEMENT_BINDINGS + 1)).map(
                |index| {
                    SecretBinding::new(format!("KEY_{index}"), "api.example.com")
                        .with_value("secret")
                },
            ))
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: secret replacement config has 257 bindings; maximum is 256"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn overlong_secret_replacement_total_value_bytes_are_rejected_fail_closed() {
        let oversized = "x".repeat((MAX_SECRET_REPLACEMENT_TOTAL_VALUE_BYTES / 3) + 1);
        let err = StreamTransformConfig::default()
            .with_secret_replacement_bindings([
                SecretBinding::new("KEY_A", "api.example.com").with_value(oversized.clone()),
                SecretBinding::new("KEY_B", "api.example.com").with_value(oversized.clone()),
                SecretBinding::new("KEY_C", "api.example.com").with_value(oversized),
            ])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: secret replacement config has 262146 configured secret-value bytes; maximum is 262144"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn empty_secret_replacement_binding_name_is_rejected_fail_closed() {
        let err = StreamTransformConfig::default()
            .with_secret_replacement_bindings([
                SecretBinding::new("", "api.example.com").with_value("secret")
            ])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: secret replacement binding name must not be empty"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_binding_name_with_surrounding_whitespace_is_rejected_fail_closed() {
        let err = StreamTransformConfig::default()
            .with_secret_replacement_bindings([SecretBinding::new(
                " OPENAI_API_KEY ",
                "api.example.com",
            )
            .with_value("secret")])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: secret replacement binding name must not contain surrounding whitespace"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn empty_secret_replacement_target_host_is_rejected_fail_closed() {
        let err = StreamTransformConfig::default()
            .with_secret_replacement_bindings([
                SecretBinding::new("OPENAI_API_KEY", "").with_value("secret")
            ])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: secret replacement target host must not be empty"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn empty_secret_replacement_explicit_value_is_rejected_fail_closed() {
        let err = StreamTransformConfig::default()
            .with_secret_replacement_bindings([SecretBinding::new(
                "OPENAI_API_KEY",
                "api.example.com",
            )
            .with_value("")])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: secret replacement binding OPENAI_API_KEY must not resolve to an empty value"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_target_host_with_surrounding_whitespace_is_rejected_fail_closed() {
        let err = StreamTransformConfig::default()
            .with_secret_replacement_bindings([SecretBinding::new(
                "OPENAI_API_KEY",
                " api.example.com ",
            )
            .with_value("secret")])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: secret replacement target host must not contain surrounding whitespace"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn malformed_secret_replacement_target_host_wildcard_is_rejected_fail_closed() {
        let err = StreamTransformConfig::default()
            .with_secret_replacement_bindings([SecretBinding::new(
                "OPENAI_API_KEY",
                "api.*.example.com",
            )
            .with_value("secret")])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: secret replacement target host wildcard must appear only as a leading *."
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_target_host_with_invalid_label_characters_is_rejected_fail_closed() {
        let err = StreamTransformConfig::default()
            .with_secret_replacement_bindings([SecretBinding::new(
                "OPENAI_API_KEY",
                "api_exam!ple.com",
            )
            .with_value("secret")])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: secret replacement target host labels must contain only ASCII letters, digits, or -"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn secret_replacement_target_host_with_edge_hyphen_label_is_rejected_fail_closed() {
        let err = StreamTransformConfig::default()
            .with_secret_replacement_bindings([SecretBinding::new(
                "OPENAI_API_KEY",
                "-api.example.com",
            )
            .with_value("secret")])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin secret-replacement denied the flow: secret replacement target host labels must not start or end with -"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn overlong_secret_replacement_target_host_is_rejected_fail_closed() {
        let host = format!("{}.example.com", "x".repeat(MAX_TARGET_HOST_BYTES));
        let err = StreamTransformConfig::default()
            .with_secret_replacement_bindings([
                SecretBinding::new("OPENAI_API_KEY", host.clone()).with_value("secret")
            ])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "TLS transform plugin secret-replacement denied the flow: secret replacement target host is {} bytes; maximum is {}",
                host.len(),
                MAX_TARGET_HOST_BYTES,
            )
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn overlong_secret_replacement_placeholder_is_rejected_fail_closed() {
        let binding_name =
            "x".repeat(MAX_SECRET_REPLACEMENT_PLACEHOLDER_BYTES - PLACEHOLDER_PREFIX.len() + 1);
        let err = StreamTransformConfig::default()
            .with_secret_replacement_bindings([
                SecretBinding::new(binding_name, "api.example.com").with_value("secret")
            ])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            format!(
                "TLS transform plugin secret-replacement denied the flow: secret replacement placeholder for {} is {} bytes; maximum is {}",
                "x".repeat(MAX_SECRET_REPLACEMENT_PLACEHOLDER_BYTES - PLACEHOLDER_PREFIX.len() + 1),
                MAX_SECRET_REPLACEMENT_PLACEHOLDER_BYTES + 1,
                MAX_SECRET_REPLACEMENT_PLACEHOLDER_BYTES,
            )
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn overlong_response_leak_guard_secret_value_count_is_rejected_fail_closed() {
        let err = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values(
                (0..(MAX_RESPONSE_LEAK_GUARD_SECRET_VALUES + 1))
                    .map(|index| format!("secret-{index}")),
            )
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: response leak guard config has 129 secret values; maximum is 128"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn overlong_response_leak_guard_total_secret_value_bytes_are_rejected_fail_closed() {
        let oversized_a = "a".repeat((MAX_RESPONSE_LEAK_GUARD_TOTAL_VALUE_BYTES / 3) + 1);
        let oversized_b = "b".repeat((MAX_RESPONSE_LEAK_GUARD_TOTAL_VALUE_BYTES / 3) + 1);
        let oversized_c = "c".repeat((MAX_RESPONSE_LEAK_GUARD_TOTAL_VALUE_BYTES / 3) + 1);
        let err = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values([oversized_a, oversized_b, oversized_c])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: response leak guard config has 262146 total secret-value bytes; maximum is 262144"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn overlong_response_leak_guard_secret_value_is_rejected_fail_closed() {
        let too_long_secret = "x".repeat(RESPONSE_LEAK_GUARD_MAX_BUFFERED_BYTES + 1);
        let err = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values([too_long_secret])
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "TLS transform plugin response-leak-guard denied the flow: known secret value exceeds response leak guard buffering budget"
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn response_leak_guard_manifest_exposes_mutation_budget() {
        let plugins = [PluginId::new("response-leak-guard").unwrap()];
        let config = StreamTransformConfig::default()
            .with_response_leak_guard_secret_values(["TOKEN"])
            .expect("response leak guard config is valid");
        let chain = StreamTransformChain::from_plugin_ids_with_config(&plugins, &config).unwrap();
        let manifests = chain.manifests();

        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].id().as_str(), "response-leak-guard");
        assert_eq!(
            manifests[0].capabilities(),
            &[
                StreamTransformCapability::MutatePlaintext,
                StreamTransformCapability::ObservePlaintext,
            ]
        );
        assert_eq!(manifests[0].timeout_budget(), DEFAULT_PLUGIN_TIMEOUT_BUDGET);
        assert_eq!(manifests[0].max_buffered_bytes(), "TOKEN".len() - 1);
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn response_leak_guard_seeds_pending_buffer_capacity_from_manifest_budget() {
        let plugin = ResponseLeakGuardPlugin::new(
            PluginId::new(RESPONSE_LEAK_GUARD_PLUGIN_ID).expect("plugin id"),
            vec!["TOKEN".to_string()],
        )
        .expect("response leak guard plugin should construct");

        assert_eq!(
            plugin.pending_upstream_to_guest.capacity(),
            plugin.manifest.max_buffered_bytes()
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn response_leak_guard_noop_redaction_seeds_output_capacity_from_buffer_len() {
        let mut plugin = ResponseLeakGuardPlugin::new(
            PluginId::new(RESPONSE_LEAK_GUARD_PLUGIN_ID).expect("plugin id"),
            vec!["TOKEN".to_string()],
        )
        .expect("response leak guard plugin should construct");
        plugin
            .pending_upstream_to_guest
            .extend_from_slice(b"plain-text");

        let (redacted, consumed, hits) = plugin
            .redact_upstream_plaintext(false)
            .expect("no-op redaction should succeed");

        assert_eq!(redacted, b"plain-text");
        assert_eq!(consumed, b"plain-text".len());
        assert_eq!(hits, 0);
        assert_eq!(redacted.capacity(), b"plain-text".len());
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn response_leak_guard_process_preserves_pending_buffer_capacity_when_suffix_is_retained() {
        let mut plugin = ResponseLeakGuardPlugin::new(
            PluginId::new(RESPONSE_LEAK_GUARD_PLUGIN_ID).expect("plugin id"),
            vec!["TOKEN".to_string()],
        )
        .expect("response leak guard plugin should construct");
        plugin.pending_upstream_to_guest = Vec::with_capacity(64);
        plugin
            .pending_upstream_to_guest
            .extend_from_slice(b"prefix-TO");
        let initial_capacity = plugin.pending_upstream_to_guest.capacity();

        let chunk = plugin
            .process(StreamTransformDirection::UpstreamToGuest, b"")
            .expect("partial secret should buffer");

        assert_eq!(chunk.bytes(), b"prefix-");
        assert_eq!(plugin.pending_upstream_to_guest, b"TO");
        assert_eq!(
            plugin.pending_upstream_to_guest.capacity(),
            initial_capacity
        );
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn builtin_response_leak_guard_reports_retained_buffered_bytes() {
        let mut plugin = BuiltinStreamTransformPlugin::ResponseLeakGuard(
            ResponseLeakGuardPlugin::new(
                PluginId::new(RESPONSE_LEAK_GUARD_PLUGIN_ID).expect("plugin id"),
                vec!["TOKEN".to_string()],
            )
            .expect("response leak guard plugin should construct"),
        );

        plugin
            .process(StreamTransformDirection::UpstreamToGuest, b"prefix-TO")
            .expect("partial secret should buffer");

        assert_eq!(plugin.buffered_bytes(), 2);
    }

    #[cfg(feature = "host-tls")]
    #[test]
    fn metadata_endpoint_deny_seeds_pending_buffer_capacity_from_manifest_budget() {
        let plugin = MetadataEndpointDenyPlugin::new(
            PluginId::new(METADATA_ENDPOINT_DENY_PLUGIN_ID).expect("plugin id"),
        );

        assert_eq!(
            plugin.pending_guest_to_upstream.capacity(),
            plugin.manifest.max_buffered_bytes()
        );
    }
}
