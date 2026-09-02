//! `host.kv.v1` — a per-workload key-value store served over the broker.
//!
//! # Why this is a service and not a network dependency
//!
//! A workload microVM has no NIC, so the usual way to reach a data store is
//! closed to it. Serving the store here rather than opening a network path
//! keeps two properties that would otherwise have to be re-argued: the
//! registry refuses a service the admitted plan did not bind, and the bytes
//! never leave the host, so no credential has to be handed to the guest for it
//! to have durable storage.
//!
//! # Namespacing
//!
//! The namespace comes from `ServiceCallCtx::workload_id`, which the supervisor
//! sets. It is never a payload field, so a workload cannot address another
//! one's namespace by asking. The directory name is a digest of that id rather
//! than the id itself: the id reaches this code from the call context, and a
//! caller-influenced string does not belong in a filesystem path even when the
//! caller is trusted to set it.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use mvm_core::plan::bundle::sha256_hex;
use mvm_core::policy::security::AgentProfile;
use mvm_core::protocol::broker::{AuditDurability, Idempotency, ServiceErrorCode, ServiceId};
use mvm_core::protocol::handler::{
    ServiceCallCtx, ServiceDispatchResult, ServiceError, ServiceHandler,
};
use mvm_core::protocol::host_kv::{
    KvDeleteRequest, KvDeleteResponse, KvGetRequest, KvGetResponse, KvListRequest, KvListResponse,
    KvPutRequest, KvPutResponse, MAX_VALUE_LEN, validate_key,
};

/// The service this handler answers for.
pub const HOST_KV_SERVICE: &str = "host.kv.v1";

/// Number of digest hex characters used for a namespace directory name.
/// Half a SHA-256 is far past the point where a collision is a practical
/// concern, and keeps the path short enough to read in a log line.
const NAMESPACE_PREFIX_LEN: usize = 32;

/// One entry on disk: a 4-byte big-endian key length, the key bytes, then the
/// value bytes.
///
/// The key is stored alongside its value because `list` has to return the keys
/// a workload wrote, and the filename is a digest it cannot be recovered from.
/// A length-prefixed binary frame rather than JSON: a JSON encoding would turn
/// every value into a number array, which costs several times the bytes it
/// represents for data that is never read by a human.
const KEY_LEN_BYTES: usize = 4;

/// Filesystem-backed store rooted at one directory.
pub struct KvStore {
    root: PathBuf,
}

impl KvStore {
    /// A store rooted at `root`. The directory is created lazily on first
    /// write, so constructing a handler never touches the filesystem.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory holding one workload's entries.
    fn namespace(&self, workload_id: &str) -> PathBuf {
        let digest = sha256_hex(workload_id.as_bytes());
        self.root.join(&digest[..NAMESPACE_PREFIX_LEN])
    }

    /// The file holding one entry. The key is validated before this is called,
    /// and the name is a digest regardless, so the result is always a direct
    /// child of the namespace.
    fn entry_path(&self, workload_id: &str, key: &str) -> PathBuf {
        self.namespace(workload_id).join(sha256_hex(key.as_bytes()))
    }

    fn encode(key: &str, value: &[u8]) -> Vec<u8> {
        let key_len = u32::try_from(key.len()).expect("key length is bounded by MAX_KEY_LEN");
        let mut out = Vec::with_capacity(KEY_LEN_BYTES + key.len() + value.len());
        out.extend_from_slice(&key_len.to_be_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(value);
        out
    }

    fn decode(raw: &[u8]) -> Option<(String, Vec<u8>)> {
        let len_bytes: [u8; KEY_LEN_BYTES] = raw.get(..KEY_LEN_BYTES)?.try_into().ok()?;
        let key_len = u32::from_be_bytes(len_bytes) as usize;
        let key_end = KEY_LEN_BYTES.checked_add(key_len)?;
        let key = core::str::from_utf8(raw.get(KEY_LEN_BYTES..key_end)?).ok()?;
        Some((key.to_string(), raw.get(key_end..)?.to_vec()))
    }

    fn get(&self, workload_id: &str, key: &str) -> std::io::Result<Option<Vec<u8>>> {
        let path = self.entry_path(workload_id, key);
        match std::fs::read(&path) {
            Ok(raw) => Ok(Self::decode(&raw).map(|(_, value)| value)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn put(&self, workload_id: &str, key: &str, value: &[u8]) -> std::io::Result<bool> {
        let dir = self.namespace(workload_id);
        std::fs::create_dir_all(&dir)?;
        restrict_to_owner(&dir)?;
        let path = dir.join(sha256_hex(key.as_bytes()));
        let replaced = path.exists();
        // Write-then-rename so a reader never observes a half-written entry and
        // an interrupted write leaves the previous value intact.
        let staging = path.with_extension("staging");
        std::fs::write(&staging, Self::encode(key, value))?;
        restrict_to_owner(&staging)?;
        std::fs::rename(&staging, &path)?;
        Ok(replaced)
    }

    fn delete(&self, workload_id: &str, key: &str) -> std::io::Result<bool> {
        match std::fs::remove_file(self.entry_path(workload_id, key)) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn list(&self, workload_id: &str, prefix: &str) -> std::io::Result<Vec<String>> {
        let dir = self.namespace(workload_id);
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut keys = Vec::new();
        for entry in entries.flatten() {
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let Ok(raw) = std::fs::read(entry.path()) else {
                continue;
            };
            if let Some((key, _)) = Self::decode(&raw)
                && key.starts_with(prefix)
            {
                keys.push(key);
            }
        }
        // Sorted so a caller comparing two listings sees a stable sequence
        // rather than whatever order the directory happened to yield.
        keys.sort();
        Ok(keys)
    }
}

/// Narrow a freshly created path to the owner. `~/.mvm` and every child is
/// owner-only; an entry written here inherits that posture explicitly rather
/// than depending on the process umask.
#[cfg(unix)]
fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if path.is_dir() { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Handler for the `host.kv.v1` service.
pub struct HostKvV1Handler {
    store: KvStore,
}

impl HostKvV1Handler {
    /// A handler over the default store root (`<mvm_home>/kv`).
    pub fn new() -> Self {
        Self::with_root(mvm_core::config::mvm_kv_dir())
    }

    /// A handler over an explicit root. Tests use this; the binary does not.
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self {
            store: KvStore::new(root),
        }
    }

    fn parse<T: serde::de::DeserializeOwned>(
        verb: &str,
        payload: serde_json::Value,
    ) -> Result<T, ServiceError> {
        serde_json::from_value(payload).map_err(|error| {
            ServiceError::new(
                ServiceErrorCode::BadRequest,
                format!("{HOST_KV_SERVICE} {verb} payload rejected: {error}"),
            )
        })
    }

    fn checked_key(key: &str) -> Result<(), ServiceError> {
        validate_key(key).map_err(|reason| {
            ServiceError::new(
                ServiceErrorCode::BadRequest,
                format!("{HOST_KV_SERVICE}: {reason}"),
            )
        })
    }

    fn encode_response<T: serde::Serialize>(value: T) -> ServiceDispatchResult {
        serde_json::to_value(value).map_err(|error| {
            ServiceError::new(
                ServiceErrorCode::InternalError,
                format!("{HOST_KV_SERVICE} response encode failed: {error}"),
            )
        })
    }

    fn unavailable(error: std::io::Error) -> ServiceError {
        // The io error is not returned to the guest: it names host paths. The
        // caller learns the class, the host log keeps the detail.
        tracing::warn!(target: "mvm::broker::host_kv", %error, "host.kv.v1 store operation failed");
        ServiceError::new(
            ServiceErrorCode::Unavailable,
            format!("{HOST_KV_SERVICE}: store unavailable"),
        )
    }

    fn get(&self, ctx: &ServiceCallCtx, payload: serde_json::Value) -> ServiceDispatchResult {
        let request: KvGetRequest = Self::parse("get", payload)?;
        Self::checked_key(&request.key)?;
        let value = self
            .store
            .get(&ctx.workload_id, &request.key)
            .map_err(Self::unavailable)?;
        Self::encode_response(KvGetResponse { value })
    }

    fn put(&self, ctx: &ServiceCallCtx, payload: serde_json::Value) -> ServiceDispatchResult {
        let request: KvPutRequest = Self::parse("put", payload)?;
        Self::checked_key(&request.key)?;
        if request.value.len() > MAX_VALUE_LEN {
            return Err(ServiceError::new(
                ServiceErrorCode::BadRequest,
                format!(
                    "{HOST_KV_SERVICE}: value is {} bytes, over the {MAX_VALUE_LEN}-byte limit",
                    request.value.len()
                ),
            ));
        }
        let replaced = self
            .store
            .put(&ctx.workload_id, &request.key, &request.value)
            .map_err(Self::unavailable)?;
        Self::encode_response(KvPutResponse { replaced })
    }

    fn delete(&self, ctx: &ServiceCallCtx, payload: serde_json::Value) -> ServiceDispatchResult {
        let request: KvDeleteRequest = Self::parse("delete", payload)?;
        Self::checked_key(&request.key)?;
        let removed = self
            .store
            .delete(&ctx.workload_id, &request.key)
            .map_err(Self::unavailable)?;
        Self::encode_response(KvDeleteResponse { removed })
    }

    fn list(&self, ctx: &ServiceCallCtx, payload: serde_json::Value) -> ServiceDispatchResult {
        let request: KvListRequest = Self::parse("list", payload)?;
        let keys = self
            .store
            .list(&ctx.workload_id, &request.prefix)
            .map_err(Self::unavailable)?;
        Self::encode_response(KvListResponse { keys })
    }
}

impl Default for HostKvV1Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceHandler for HostKvV1Handler {
    fn id(&self) -> ServiceId {
        ServiceId::parse(HOST_KV_SERVICE).expect("host.kv.v1 is a valid ServiceId")
    }

    fn profiles(&self) -> &[AgentProfile] {
        &[
            AgentProfile::SealedProd,
            AgentProfile::Dev,
            AgentProfile::Builder,
        ]
    }

    fn audit_durability(&self) -> AuditDurability {
        AuditDurability::default_batched()
    }

    fn idempotency(&self) -> Idempotency {
        Idempotency::MintFresh
    }

    fn call_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn dispatch<'a>(
        &'a self,
        ctx: &'a ServiceCallCtx,
        verb: &'a str,
        payload: serde_json::Value,
    ) -> Pin<Box<dyn std::future::Future<Output = ServiceDispatchResult> + Send + 'a>> {
        Box::pin(async move {
            match verb {
                "get" => self.get(ctx, payload),
                "put" => self.put(ctx, payload),
                "delete" => self.delete(ctx, payload),
                "list" => self.list(ctx, payload),
                other => Err(ServiceError::new(
                    ServiceErrorCode::NotImplemented,
                    format!("{HOST_KV_SERVICE}: unknown verb `{other}`"),
                )),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(workload_id: &str) -> ServiceCallCtx {
        ServiceCallCtx {
            workload_id: workload_id.into(),
            tenant_id: "tenant".into(),
            correlation_id: mvm_core::protocol::broker::CorrelationId::new("correlation"),
            session_id: "session".into(),
            profile: AgentProfile::Dev,
            composition_depth: 0,
            composition_width: 0,
        }
    }

    fn handler() -> (HostKvV1Handler, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        (HostKvV1Handler::with_root(dir.path()), dir)
    }

    #[tokio::test]
    async fn put_then_get_round_trips() {
        let (handler, _dir) = handler();
        let ctx = context("w1");

        let put: KvPutResponse = serde_json::from_value(
            handler
                .dispatch(
                    &ctx,
                    "put",
                    serde_json::json!({"key": "k", "value": [1, 2, 3]}),
                )
                .await
                .expect("put"),
        )
        .expect("decode put");
        assert!(!put.replaced);

        let got: KvGetResponse = serde_json::from_value(
            handler
                .dispatch(&ctx, "get", serde_json::json!({"key": "k"}))
                .await
                .expect("get"),
        )
        .expect("decode get");
        assert_eq!(got.value, Some(vec![1, 2, 3]));
    }

    #[tokio::test]
    async fn a_missing_key_reads_as_absent_rather_than_erroring() {
        let (handler, _dir) = handler();
        let got: KvGetResponse = serde_json::from_value(
            handler
                .dispatch(&context("w1"), "get", serde_json::json!({"key": "absent"}))
                .await
                .expect("get"),
        )
        .expect("decode");
        assert_eq!(got.value, None);
    }

    #[tokio::test]
    async fn a_second_put_reports_that_it_replaced() {
        let (handler, _dir) = handler();
        let ctx = context("w1");
        for _ in 0..1 {
            handler
                .dispatch(&ctx, "put", serde_json::json!({"key": "k", "value": [1]}))
                .await
                .expect("first put");
        }
        let put: KvPutResponse = serde_json::from_value(
            handler
                .dispatch(&ctx, "put", serde_json::json!({"key": "k", "value": [2]}))
                .await
                .expect("second put"),
        )
        .expect("decode");
        assert!(put.replaced);
    }

    #[tokio::test]
    async fn delete_reports_whether_anything_was_removed() {
        let (handler, _dir) = handler();
        let ctx = context("w1");
        handler
            .dispatch(&ctx, "put", serde_json::json!({"key": "k", "value": [1]}))
            .await
            .expect("put");

        let first: KvDeleteResponse = serde_json::from_value(
            handler
                .dispatch(&ctx, "delete", serde_json::json!({"key": "k"}))
                .await
                .expect("delete"),
        )
        .expect("decode");
        assert!(first.removed);

        let second: KvDeleteResponse = serde_json::from_value(
            handler
                .dispatch(&ctx, "delete", serde_json::json!({"key": "k"}))
                .await
                .expect("delete"),
        )
        .expect("decode");
        assert!(!second.removed);
    }

    #[tokio::test]
    async fn list_filters_by_prefix_and_sorts() {
        let (handler, _dir) = handler();
        let ctx = context("w1");
        for key in ["b-two", "a-one", "b-one"] {
            handler
                .dispatch(&ctx, "put", serde_json::json!({"key": key, "value": [0]}))
                .await
                .expect("put");
        }

        let all: KvListResponse = serde_json::from_value(
            handler
                .dispatch(&ctx, "list", serde_json::json!({}))
                .await
                .expect("list"),
        )
        .expect("decode");
        assert_eq!(all.keys, vec!["a-one", "b-one", "b-two"]);

        let filtered: KvListResponse = serde_json::from_value(
            handler
                .dispatch(&ctx, "list", serde_json::json!({"prefix": "b-"}))
                .await
                .expect("list"),
        )
        .expect("decode");
        assert_eq!(filtered.keys, vec!["b-one", "b-two"]);
    }

    /// The namespace comes from the call context, so two workloads sharing one
    /// store root cannot observe each other. This is the property that makes a
    /// single host-side store safe to serve to every workload at once.
    #[tokio::test]
    async fn one_workload_cannot_read_or_list_another_namespace() {
        let (handler, _dir) = handler();
        handler
            .dispatch(
                &context("w1"),
                "put",
                serde_json::json!({"key": "secret", "value": [9]}),
            )
            .await
            .expect("put");

        let got: KvGetResponse = serde_json::from_value(
            handler
                .dispatch(&context("w2"), "get", serde_json::json!({"key": "secret"}))
                .await
                .expect("get"),
        )
        .expect("decode");
        assert_eq!(got.value, None, "w2 must not read w1's key");

        let listed: KvListResponse = serde_json::from_value(
            handler
                .dispatch(&context("w2"), "list", serde_json::json!({}))
                .await
                .expect("list"),
        )
        .expect("decode");
        assert!(listed.keys.is_empty(), "w2 must not see w1's keys");
    }

    #[tokio::test]
    async fn a_traversal_key_is_refused_before_it_reaches_the_filesystem() {
        let (handler, _dir) = handler();
        let error = handler
            .dispatch(
                &context("w1"),
                "get",
                serde_json::json!({"key": "../../etc/passwd"}),
            )
            .await
            .expect_err("traversal must be refused");
        assert_eq!(error.code, ServiceErrorCode::BadRequest);
    }

    #[tokio::test]
    async fn an_oversized_value_is_refused() {
        let (handler, _dir) = handler();
        let error = handler
            .dispatch(
                &context("w1"),
                "put",
                serde_json::json!({"key": "k", "value": vec![0u8; MAX_VALUE_LEN + 1]}),
            )
            .await
            .expect_err("oversized value must be refused");
        assert_eq!(error.code, ServiceErrorCode::BadRequest);
    }

    #[tokio::test]
    async fn an_unknown_envelope_field_is_refused() {
        let (handler, _dir) = handler();
        let error = handler
            .dispatch(
                &context("w1"),
                "get",
                serde_json::json!({"key": "k", "workload_id": "w2"}),
            )
            .await
            .expect_err("unknown field must be refused");
        assert_eq!(error.code, ServiceErrorCode::BadRequest);
    }

    #[tokio::test]
    async fn unknown_verb_is_not_implemented() {
        let (handler, _dir) = handler();
        let error = handler
            .dispatch(&context("w1"), "increment", serde_json::json!({}))
            .await
            .expect_err("unknown verb");
        assert_eq!(error.code, ServiceErrorCode::NotImplemented);
    }

    #[test]
    fn a_value_with_an_embedded_frame_header_still_decodes() {
        // The value is opaque bytes: it may legitimately begin with something
        // that looks like a length prefix. Decoding keys off the stored key
        // length rather than scanning keeps that from mattering.
        let encoded = KvStore::encode("k", &[0, 0, 0, 9, 1, 2]);
        let (key, value) = KvStore::decode(&encoded).expect("decode");
        assert_eq!(key, "k");
        assert_eq!(value, vec![0, 0, 0, 9, 1, 2]);
    }

    #[test]
    fn a_truncated_entry_decodes_to_nothing_rather_than_panicking() {
        assert!(KvStore::decode(&[0, 0]).is_none());
        assert!(KvStore::decode(&[0, 0, 0, 200, b'k']).is_none());
    }
}
