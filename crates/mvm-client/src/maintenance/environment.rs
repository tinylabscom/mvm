//! Host provisioning workflows. Frontends render events; this module decides
//! which operations are necessary and owns their ordering and failures.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SetupScope {
    #[default]
    Full,
    SecurityBaseline,
}

/// Preview is the default, even for a forced refresh.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct SetupRequest {
    #[serde(default)]
    pub apply: bool,
    #[serde(default)]
    pub force: bool,
    #[serde(default)]
    pub scope: SetupScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SetupAction {
    InstallFirecracker,
    DownloadAssets,
    RepairRootfsDownload,
    PrepareRootfs,
    WriteState,
    DeployStrictSeccomp,
    CreateAuditDirectory,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct SetupReport {
    pub supported: bool,
    pub planned: Vec<SetupAction>,
    pub completed: Vec<SetupAction>,
    pub jailer_available: Option<bool>,
}

/// Pure progress notifications; consumers cannot replace provisioning steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupEvent {
    Unsupported,
    FirecrackerPresent,
    AssetsPresent,
    Starting(SetupAction),
    Completed(SetupAction),
    JailerAvailable(bool),
}

#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    // Deliberately omit subprocess output: it can contain caller environment.
    #[error("host provisioning check failed: {check}; inspect the host environment and retry")]
    Check { check: &'static str },
    #[error("host provisioning failed at {action:?}; inspect the host environment and retry")]
    Operation { action: SetupAction },
}

trait Provisioner {
    fn supported(&self) -> bool;
    fn installed(&self) -> Result<bool, SetupError>;
    fn assets_present(&self) -> Result<bool, SetupError>;
    fn rootfs_corrupt(&self) -> Result<bool, SetupError>;
    fn execute(&self, action: SetupAction) -> Result<(), SetupError>;
    fn jailer_available(&self) -> bool;
}

struct HostProvisioner;

impl Provisioner for HostProvisioner {
    fn supported(&self) -> bool {
        cfg!(target_os = "linux")
    }

    fn installed(&self) -> Result<bool, SetupError> {
        mvm_runtime::firecracker::is_installed().map_err(|_| SetupError::Check {
            check: "Firecracker installation",
        })
    }

    fn assets_present(&self) -> Result<bool, SetupError> {
        mvm_runtime::firecracker::has_base_assets().map_err(|_| SetupError::Check {
            check: "kernel and rootfs assets",
        })
    }

    fn rootfs_corrupt(&self) -> Result<bool, SetupError> {
        let check = || -> anyhow::Result<bool> {
            Ok(mvm_runtime::firecracker::has_squashfs()?
                && !mvm_runtime::firecracker::validate_rootfs_squashfs()?)
        };
        check().map_err(|_| SetupError::Check {
            check: "rootfs integrity",
        })
    }

    fn execute(&self, action: SetupAction) -> Result<(), SetupError> {
        use mvm_runtime::{firecracker, shell};
        let result = match action {
            SetupAction::InstallFirecracker => firecracker::install(),
            SetupAction::DownloadAssets => firecracker::download_assets(),
            SetupAction::RepairRootfsDownload => shell::run_in_vm(&format!(
                "rm -f {dir}/ubuntu-*.squashfs.upstream",
                dir = mvm_runtime::config::MICROVM_DIR,
            ))
            .and_then(|_| firecracker::download_assets()),
            SetupAction::PrepareRootfs => firecracker::prepare_rootfs(),
            SetupAction::WriteState => firecracker::write_state(),
            SetupAction::DeployStrictSeccomp => {
                mvm_runtime::security::seccomp::ensure_strict_profile()
            }
            SetupAction::CreateAuditDirectory => {
                shell::run_in_vm("sudo mkdir -p /var/lib/mvm/tenants").map(|_| ())
            }
        };
        result.map_err(|_| SetupError::Operation { action })
    }

    fn jailer_available(&self) -> bool {
        mvm_runtime::security::jailer::jailer_available().unwrap_or(false)
    }
}

/// Rechecks the host on every invocation. A serialized preview is informational,
/// never an executable plan. No downloads, writes or signing occur in preview.
pub fn setup(
    request: &SetupRequest,
    progress: &mut dyn FnMut(SetupEvent),
) -> Result<SetupReport, SetupError> {
    setup_with(request, &HostProvisioner, progress)
}

fn setup_with(
    request: &SetupRequest,
    host: &impl Provisioner,
    progress: &mut dyn FnMut(SetupEvent),
) -> Result<SetupReport, SetupError> {
    if !host.supported() {
        progress(SetupEvent::Unsupported);
        return Ok(SetupReport::default());
    }
    let mut report = SetupReport {
        supported: true,
        ..SetupReport::default()
    };
    if request.scope == SetupScope::Full {
        if request.force || !host.installed()? {
            perform(
                SetupAction::InstallFirecracker,
                request,
                host,
                &mut report,
                progress,
            )?;
        } else {
            progress(SetupEvent::FirecrackerPresent);
        }
        if request.force || !host.assets_present()? {
            perform(
                SetupAction::DownloadAssets,
                request,
                host,
                &mut report,
                progress,
            )?;
        } else {
            progress(SetupEvent::AssetsPresent);
        }
        // This check is intentionally after any download, not based on a stale
        // preview. A corrupt freshly downloaded squashfs must be repaired too.
        if host.rootfs_corrupt()? {
            perform(
                SetupAction::RepairRootfsDownload,
                request,
                host,
                &mut report,
                progress,
            )?;
        }
        perform(
            SetupAction::PrepareRootfs,
            request,
            host,
            &mut report,
            progress,
        )?;
        perform(
            SetupAction::WriteState,
            request,
            host,
            &mut report,
            progress,
        )?;
    }
    perform(
        SetupAction::DeployStrictSeccomp,
        request,
        host,
        &mut report,
        progress,
    )?;
    perform(
        SetupAction::CreateAuditDirectory,
        request,
        host,
        &mut report,
        progress,
    )?;
    let available = host.jailer_available();
    report.jailer_available = Some(available);
    progress(SetupEvent::JailerAvailable(available));
    Ok(report)
}

fn perform(
    action: SetupAction,
    request: &SetupRequest,
    host: &impl Provisioner,
    report: &mut SetupReport,
    progress: &mut dyn FnMut(SetupEvent),
) -> Result<(), SetupError> {
    report.planned.push(action);
    if request.apply {
        progress(SetupEvent::Starting(action));
        host.execute(action)?;
        report.completed.push(action);
        progress(SetupEvent::Completed(action));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Fake {
        supported: bool,
        present: bool,
        corrupt: bool,
        fail: Option<SetupAction>,
        calls: RefCell<Vec<SetupAction>>,
    }

    impl Default for Fake {
        fn default() -> Self {
            Self {
                supported: true,
                present: false,
                corrupt: false,
                fail: None,
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl Provisioner for Fake {
        fn supported(&self) -> bool {
            self.supported
        }
        fn installed(&self) -> Result<bool, SetupError> {
            Ok(self.present)
        }
        fn assets_present(&self) -> Result<bool, SetupError> {
            Ok(self.present)
        }
        fn rootfs_corrupt(&self) -> Result<bool, SetupError> {
            Ok(self.corrupt)
        }
        fn jailer_available(&self) -> bool {
            true
        }
        fn execute(&self, action: SetupAction) -> Result<(), SetupError> {
            self.calls.borrow_mut().push(action);
            if self.fail == Some(action) {
                Err(SetupError::Operation { action })
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn preview_is_nonmutating_and_wire_defaults_are_safe() {
        let host = Fake::default();
        let request: SetupRequest = serde_json::from_str("{}").unwrap();
        assert!(!request.apply);
        let report = setup_with(&request, &host, &mut |_| {}).unwrap();
        assert!(!report.planned.is_empty());
        assert!(report.completed.is_empty());
        assert!(host.calls.borrow().is_empty());
        let decoded: SetupReport =
            serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
        assert_eq!(report, decoded);
        assert!(serde_json::from_str::<SetupRequest>(r#"{"yes":true}"#).is_err());
    }

    #[test]
    fn applies_in_order_and_rechecks_instead_of_accepting_preview() {
        let mut host = Fake::default();
        setup_with(&SetupRequest::default(), &host, &mut |_| {}).unwrap();
        host.present = true;
        host.corrupt = true;
        let report = setup_with(
            &SetupRequest {
                apply: true,
                ..SetupRequest::default()
            },
            &host,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(
            report.completed,
            vec![
                SetupAction::RepairRootfsDownload,
                SetupAction::PrepareRootfs,
                SetupAction::WriteState,
                SetupAction::DeployStrictSeccomp,
                SetupAction::CreateAuditDirectory,
            ]
        );
        assert_eq!(report.completed, *host.calls.borrow());
    }

    #[test]
    fn failed_security_step_stops_the_workflow() {
        let host = Fake {
            fail: Some(SetupAction::DeployStrictSeccomp),
            ..Fake::default()
        };
        let error = setup_with(
            &SetupRequest {
                apply: true,
                scope: SetupScope::SecurityBaseline,
                force: false,
            },
            &host,
            &mut |_| {},
        )
        .unwrap_err();
        assert!(matches!(
            error,
            SetupError::Operation {
                action: SetupAction::DeployStrictSeccomp
            }
        ));
        assert_eq!(*host.calls.borrow(), vec![SetupAction::DeployStrictSeccomp]);
    }

    #[test]
    fn unsupported_platform_performs_no_operations() {
        let host = Fake {
            supported: false,
            ..Fake::default()
        };
        let report = setup_with(
            &SetupRequest {
                apply: true,
                force: true,
                ..SetupRequest::default()
            },
            &host,
            &mut |_| {},
        )
        .unwrap();
        assert!(!report.supported);
        assert!(host.calls.borrow().is_empty());
    }

    #[test]
    fn progress_events_describe_the_workflow_without_delegating_steps() {
        let host = Fake::default();
        let mut events = Vec::new();
        let request = SetupRequest {
            apply: true,
            scope: SetupScope::SecurityBaseline,
            force: false,
        };
        setup_with(&request, &host, &mut |event| events.push(event)).unwrap();
        assert_eq!(
            events,
            vec![
                SetupEvent::Starting(SetupAction::DeployStrictSeccomp),
                SetupEvent::Completed(SetupAction::DeployStrictSeccomp),
                SetupEvent::Starting(SetupAction::CreateAuditDirectory),
                SetupEvent::Completed(SetupAction::CreateAuditDirectory),
                SetupEvent::JailerAvailable(true),
            ]
        );
        assert_eq!(host.calls.borrow().len(), 2);
    }
}
