//! OCI config decoding shared by image acquisition and CLI materialization.

use serde::Deserialize;

use super::{LinuxPlatform, OciError};

/// Runtime metadata from an image config. Parsing alone is not verification:
/// acquisition must verify the blob digest and validate its platform.
#[derive(Debug, PartialEq, Eq)]
pub struct OciImageConfig {
    architecture: Option<String>,
    os: Option<String>,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub working_dir: Option<String>,
}

#[derive(Default, Deserialize)]
struct RuntimeConfig {
    #[serde(default, rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[serde(default, rename = "Cmd")]
    cmd: Option<Vec<String>>,
    #[serde(default, rename = "Env")]
    env: Vec<String>,
    #[serde(default, rename = "WorkingDir")]
    working_dir: Option<String>,
}

#[derive(Deserialize)]
struct Config {
    architecture: Option<String>,
    os: Option<String>,
    #[serde(default)]
    config: RuntimeConfig,
}

impl OciImageConfig {
    /// Flatten Entrypoint followed by Cmd, preserving environment-only images.
    pub fn parse(bytes: &[u8]) -> Result<Self, OciError> {
        let config: Config = serde_json::from_slice(bytes)
            .map_err(|error| OciError::Registry(format!("parse OCI image config: {error}")))?;
        let mut argv = config.config.entrypoint.unwrap_or_default();
        argv.extend(config.config.cmd.unwrap_or_default());
        Ok(Self {
            architecture: config.architecture,
            os: config.os,
            argv,
            env: config.config.env,
            working_dir: config.config.working_dir,
        })
    }

    /// Require the config blob itself, not only an index descriptor, to declare
    /// the selected Linux architecture. OCI uses `amd64` and `arm64` spelling.
    pub fn validate_platform(&self, platform: &LinuxPlatform) -> Result<(), OciError> {
        if self.os.as_deref() != Some("linux")
            || self.architecture.as_deref() != Some(platform.architecture.as_str())
        {
            return Err(OciError::Registry(format!(
                "OCI config platform must be linux/{}",
                platform.architecture
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform() -> LinuxPlatform {
        LinuxPlatform {
            architecture: "amd64".into(),
            variant: None,
        }
    }

    #[test]
    fn config_preserves_runtime_contract() {
        let config = OciImageConfig::parse(br#"{"os":"linux","architecture":"amd64","config":{"Entrypoint":["/bin/app"],"Cmd":["--serve"],"Env":["A=B"],"WorkingDir":"/app"}}"#).unwrap();
        config.validate_platform(&platform()).unwrap();
        assert_eq!(config.argv, ["/bin/app", "--serve"]);
        assert_eq!(config.env, ["A=B"]);
        assert_eq!(config.working_dir.as_deref(), Some("/app"));
    }

    #[test]
    fn config_rejects_wrong_or_missing_platform() {
        for bytes in [
            br#"{"os":"windows","architecture":"amd64"}"#.as_slice(),
            br#"{"os":"linux","architecture":"arm64"}"#,
            br#"{"os":"linux"}"#,
            br#"{}"#,
        ] {
            assert!(
                OciImageConfig::parse(bytes)
                    .unwrap()
                    .validate_platform(&platform())
                    .is_err()
            );
        }
    }

    #[test]
    fn environment_without_command_is_preserved() {
        let config = OciImageConfig::parse(br#"{"config":{"Env":["PATH=/tools"]}}"#).unwrap();
        assert!(config.argv.is_empty());
        assert_eq!(config.env, ["PATH=/tools"]);
        assert!(OciImageConfig::parse(br#"{"config":{"Cmd":"not-an-array"}}"#).is_err());
        assert!(OciImageConfig::parse(b"not json").is_err());
    }
}
