#[cfg(feature = "template-registry-s3")]
use anyhow::Context;
use anyhow::{Result, anyhow, bail};

#[cfg(feature = "template-registry-s3")]
use object_store::ObjectStore;
#[cfg(feature = "template-registry-s3")]
use object_store::aws::{AmazonS3, AmazonS3Builder};
#[cfg(feature = "template-registry-s3")]
use object_store::path::Path as ObjPath;

#[cfg(feature = "template-registry-s3")]
pub struct TemplateRegistry {
    store: AmazonS3,
    // object_store is async; this registry's API is sync, so it owns a
    // current-thread runtime to drive the get/put calls (mirrors
    // `mvm_storage::s3::S3MountProvider`).
    rt: tokio::runtime::Runtime,
    prefix: String,
}

#[cfg(not(feature = "template-registry-s3"))]
pub struct TemplateRegistry;

#[cfg(feature = "template-registry-s3")]
impl TemplateRegistry {
    pub fn from_env() -> Result<Option<Self>> {
        let endpoint = match std::env::var("MVM_TEMPLATE_REGISTRY_ENDPOINT") {
            Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
            _ => return Ok(None),
        };
        let insecure = std::env::var("MVM_TEMPLATE_REGISTRY_INSECURE")
            .ok()
            .map(|v| v.to_ascii_lowercase())
            .map(|v| v == "1" || v == "true" || v == "yes")
            .unwrap_or(false);
        if endpoint.starts_with("http://") && !insecure {
            bail!(
                "Template registry endpoint is http:// but MVM_TEMPLATE_REGISTRY_INSECURE is not true"
            );
        }
        let bucket = std::env::var("MVM_TEMPLATE_REGISTRY_BUCKET")
            .map_err(anyhow::Error::new)
            .context("MVM_TEMPLATE_REGISTRY_BUCKET must be set when registry endpoint is set")?;

        let access_key = std::env::var("MVM_TEMPLATE_REGISTRY_ACCESS_KEY_ID")
            .map_err(anyhow::Error::new)
            .context("MVM_TEMPLATE_REGISTRY_ACCESS_KEY_ID must be set")?;
        let secret_key = std::env::var("MVM_TEMPLATE_REGISTRY_SECRET_ACCESS_KEY")
            .map_err(anyhow::Error::new)
            .context("MVM_TEMPLATE_REGISTRY_SECRET_ACCESS_KEY must be set")?;

        let prefix = std::env::var("MVM_TEMPLATE_REGISTRY_PREFIX")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "mvm".to_string());
        let prefix = prefix.trim_matches('/').to_string();

        let region = std::env::var("MVM_TEMPLATE_REGISTRY_REGION")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "us-east-1".to_string());

        // The endpoint is always a custom S3-compatible gateway (MinIO/etc., it's
        // required above), so use path-style requests. `with_allow_http` permits
        // http:// only when the operator opted in via MVM_TEMPLATE_REGISTRY_INSECURE
        // (already validated above).
        let store = AmazonS3Builder::new()
            .with_endpoint(&endpoint)
            .with_bucket_name(bucket.trim())
            .with_region(region.trim())
            .with_access_key_id(access_key.trim())
            .with_secret_access_key(secret_key.trim())
            .with_virtual_hosted_style_request(false)
            .with_allow_http(insecure)
            .build()
            .context("building the S3 client for the template registry")?;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building the runtime for the template registry")?;

        Ok(Some(Self { store, rt, prefix }))
    }

    pub fn key_current(&self, template_id: &str) -> String {
        format!(
            "{}/templates/{}/current",
            self.prefix,
            template_id.trim_matches('/')
        )
    }

    pub fn key_revision_base(&self, template_id: &str, revision: &str) -> String {
        format!(
            "{}/templates/{}/revisions/{}",
            self.prefix,
            template_id.trim_matches('/'),
            revision
        )
    }

    pub fn key_revision_file(&self, template_id: &str, revision: &str, file: &str) -> String {
        format!("{}/{}", self.key_revision_base(template_id, revision), file)
    }

    pub fn put_bytes(&self, key: &str, data: Vec<u8>) -> Result<()> {
        self.rt
            .block_on(self.store.put(&ObjPath::from(key), data.into()))
            .map_err(anyhow::Error::new)
            .with_context(|| format!("Failed to write object {}", key))?;
        Ok(())
    }

    pub fn get_bytes(&self, key: &str) -> Result<Vec<u8>> {
        let bytes = self
            .rt
            .block_on(async {
                let resp = self.store.get(&ObjPath::from(key)).await?;
                resp.bytes().await
            })
            .map_err(anyhow::Error::new)
            .with_context(|| format!("Failed to read object {}", key))?;
        Ok(bytes.to_vec())
    }

    pub fn put_text(&self, key: &str, text: &str) -> Result<()> {
        self.put_bytes(key, text.as_bytes().to_vec())
    }

    pub fn get_text(&self, key: &str) -> Result<String> {
        let bytes = self.get_bytes(key)?;
        String::from_utf8(bytes).map_err(|e| anyhow!("invalid utf-8 in object {}: {}", key, e))
    }

    pub fn require_configured(&self) -> Result<()> {
        if self.prefix.is_empty() {
            bail!("Template registry prefix is empty");
        }
        Ok(())
    }
}

#[cfg(not(feature = "template-registry-s3"))]
impl TemplateRegistry {
    pub fn from_env() -> Result<Option<Self>> {
        match std::env::var("MVM_TEMPLATE_REGISTRY_ENDPOINT") {
            Ok(v) if !v.trim().is_empty() => bail!(
                "S3 template registry support is disabled in this build; rebuild with \
                 --features template-registry-s3"
            ),
            _ => Ok(None),
        }
    }

    pub fn key_current(&self, template_id: &str) -> String {
        format!("templates/{}/current", template_id.trim_matches('/'))
    }

    pub fn key_revision_base(&self, template_id: &str, revision: &str) -> String {
        format!(
            "templates/{}/revisions/{}",
            template_id.trim_matches('/'),
            revision
        )
    }

    pub fn key_revision_file(&self, template_id: &str, revision: &str, file: &str) -> String {
        format!("{}/{}", self.key_revision_base(template_id, revision), file)
    }

    pub fn put_bytes(&self, _key: &str, _data: Vec<u8>) -> Result<()> {
        bail!("S3 template registry support is disabled in this build")
    }

    pub fn get_bytes(&self, _key: &str) -> Result<Vec<u8>> {
        bail!("S3 template registry support is disabled in this build")
    }

    pub fn put_text(&self, key: &str, text: &str) -> Result<()> {
        self.put_bytes(key, text.as_bytes().to_vec())
    }

    pub fn get_text(&self, key: &str) -> Result<String> {
        let bytes = self.get_bytes(key)?;
        String::from_utf8(bytes).map_err(|e| anyhow!("invalid utf-8 in object {}: {}", key, e))
    }

    pub fn require_configured(&self) -> Result<()> {
        bail!("S3 template registry support is disabled in this build")
    }
}
