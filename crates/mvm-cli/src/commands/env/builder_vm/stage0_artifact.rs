#[cfg(feature = "builder-vm")]
use super::*;

#[cfg(feature = "builder-vm")]
#[derive(Debug)]
pub(super) struct Stage0ArtifactBuild<'a> {
    workspace_root: &'a std::path::Path,
    staging_dir: &'a std::path::Path,
    build_attr: &'a str,
    output_mode: &'a str,
    config_attr: Option<&'a str>,
    verbose: bool,
}

#[cfg(feature = "builder-vm")]
#[derive(Debug)]
pub(super) struct Stage0ArtifactBuildBuilder<'a> {
    workspace_root: &'a std::path::Path,
    staging_dir: &'a std::path::Path,
    build_attr: Option<&'a str>,
    output_mode: Option<&'a str>,
    config_attr: Option<&'a str>,
    verbose: bool,
}

#[cfg(feature = "builder-vm")]
impl<'a> Stage0ArtifactBuild<'a> {
    pub(super) fn builder(
        workspace_root: &'a std::path::Path,
        staging_dir: &'a std::path::Path,
    ) -> Stage0ArtifactBuildBuilder<'a> {
        Stage0ArtifactBuildBuilder {
            workspace_root,
            staging_dir,
            build_attr: None,
            output_mode: None,
            config_attr: None,
            verbose: false,
        }
    }

    pub(super) fn run(&self) -> Result<()> {
        let stage0_assets = mvm_build::stage0::assets_for_host_arch();
        let vendor_reports = mvm_build::stage0::prepare_assets(stage0_assets)
            .context("preparing Stage 0 bootstrap assets (nix-tarball seed)")?;
        for report in &vendor_reports {
            mvm_core::policy::audit::emit(
                mvm_core::policy::audit::LocalAuditKind::VendorBlobFetched,
                None,
                Some(&report.audit_detail()),
            );
        }

        let root_dir = mvm_build::stage0::stage0_cache_dir().join("root");
        let host_bins_cache = format!("{}/host-bins", mvm_core::config::mvm_cache_dir());
        let boot_binaries = crate::host_binaries::extract::ensure_boot_host_binaries(
            std::path::Path::new(&host_bins_cache),
        )?;
        mvm_build::stage0::materialize_root_dir(&root_dir, &boot_binaries.stage0_init)
            .with_context(|| format!("materializing Stage 0 root at {}", root_dir.display()))?;

        std::fs::write(
            self.staging_dir.join("stage0-build.conf"),
            self.render_conf(),
        )
        .with_context(|| {
            format!(
                "writing stage0-build.conf in {}",
                self.staging_dir.display()
            )
        })?;

        use mvm_build::builder_backend_select as bbs;
        let selected = bbs::resolve_choice();
        let explicit = bbs::resolve_env_override().is_some();
        bbs::run_with_builder_fallback(selected, explicit, |choice| {
            bbs::resolve_stage0_backend_for_choice(choice, self.verbose).run_stage0(
                &root_dir,
                "/init",
                self.workspace_root,
                self.staging_dir,
                &boot_binaries.dir,
            )
        })
        .map_err(|error| anyhow::anyhow!("Stage 0 artifact build: {error}"))
    }

    fn render_conf(&self) -> String {
        let mut conf = format!(
            "MVM_STAGE0_BUILD_ATTR={}\nMVM_STAGE0_OUTPUT_MODE={}\n",
            self.build_attr, self.output_mode
        );
        if let Some(config_attr) = self.config_attr {
            conf.push_str(&format!("MVM_STAGE0_CONFIG_ATTR={config_attr}\n"));
        }
        conf
    }
}

#[cfg(feature = "builder-vm")]
impl<'a> Stage0ArtifactBuildBuilder<'a> {
    pub(super) fn build_attr(mut self, build_attr: &'a str) -> Self {
        self.build_attr = Some(build_attr);
        self
    }

    pub(super) fn output_mode(mut self, output_mode: &'a str) -> Self {
        self.output_mode = Some(output_mode);
        self
    }

    pub(super) fn config_attr(mut self, config_attr: &'a str) -> Self {
        self.config_attr = Some(config_attr);
        self
    }

    pub(super) fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    pub(super) fn build(self) -> Result<Stage0ArtifactBuild<'a>> {
        let build_attr = self
            .build_attr
            .ok_or_else(|| anyhow::anyhow!("Stage 0 build attribute is required"))?;
        let output_mode = self
            .output_mode
            .ok_or_else(|| anyhow::anyhow!("Stage 0 output mode is required"))?;
        for (label, value) in [
            ("build attribute", build_attr),
            ("output mode", output_mode),
        ] {
            if !valid_conf_token(value) {
                anyhow::bail!("Stage 0 {label} contains invalid characters: {value:?}");
            }
        }
        if let Some(config_attr) = self.config_attr
            && !valid_conf_token(config_attr)
        {
            anyhow::bail!("Stage 0 config attribute contains invalid characters: {config_attr:?}");
        }
        Ok(Stage0ArtifactBuild {
            workspace_root: self.workspace_root,
            staging_dir: self.staging_dir,
            build_attr,
            output_mode,
            config_attr: self.config_attr,
            verbose: self.verbose,
        })
    }
}

#[cfg(feature = "builder-vm")]
fn valid_conf_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(all(test, feature = "builder-vm"))]
mod tests {
    use super::*;

    #[test]
    fn builder_rejects_config_injection() {
        let root = std::path::Path::new("/work");
        let out = std::path::Path::new("/out");
        let error = Stage0ArtifactBuild::builder(root, out)
            .build_attr("sdk-sidecar-image\nMVM_STAGE0_OUTPUT_MODE=image")
            .output_mode("sdk-sidecar")
            .build()
            .expect_err("a newline must not enter stage0-build.conf");
        assert!(error.to_string().contains("invalid characters"), "{error}");
    }

    #[test]
    fn builder_renders_the_requested_artifact_contract() {
        let build = Stage0ArtifactBuild::builder(
            std::path::Path::new("/work"),
            std::path::Path::new("/out"),
        )
        .build_attr("sdk-sidecar-image")
        .output_mode("sdk-sidecar")
        .verbose(true)
        .build()
        .expect("valid request");
        assert_eq!(
            build.render_conf(),
            "MVM_STAGE0_BUILD_ATTR=sdk-sidecar-image\nMVM_STAGE0_OUTPUT_MODE=sdk-sidecar\n"
        );
    }
}
