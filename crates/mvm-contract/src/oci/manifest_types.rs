use alloc::string::String;
use alloc::vec::Vec;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OciManifest {
    Image(ImageManifest),
    ImageIndex(ImageIndexManifest),
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImageManifest {
    pub config: ContentDescriptor,
    pub layers: Vec<ContentDescriptor>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImageIndexManifest {
    pub manifests: Vec<ManifestDescriptor>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContentDescriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub size: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManifestDescriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: String,
    pub platform: Option<PlatformDescriptor>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PlatformDescriptor {
    pub os: String,
    pub architecture: String,
    pub variant: Option<String>,
}
