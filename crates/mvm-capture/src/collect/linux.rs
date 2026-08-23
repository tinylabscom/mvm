//! Linux-specific collectors: PATH executables, package ownership, and tracing.

use crate::CaptureError;
use crate::collect::package::all_providers;
use crate::collect::{TraverseLimits, inspect_executable, obs_id};
use crate::report::{CaptureReportV1, Confidence, Evidence, Observation, ObservationKind};

/// Resolve PATH executables and their native package ownership.
pub fn collect_path_executables(
    report: &mut CaptureReportV1,
    limits: &TraverseLimits,
) -> Result<(), CaptureError> {
    let providers = all_providers();
    for tool in ["cargo", "rustc", "cc", "ld", "python3", "node"] {
        if let Ok(path) = which::which(tool) {
            inspect_executable(
                report,
                &path,
                &path,
                crate::collect::InspectMeta {
                    source: "linux-path-resolution",
                    confidence: Confidence::Observed,
                    name: Some(tool),
                    warnings: vec![],
                    provenance: vec!["resolved via PATH".to_owned()],
                },
                limits,
            )?;

            for provider in &providers {
                if let Some(pkg) = provider.owner_of(&path) {
                    report.observations.push(Observation {
                        id: obs_id("pkg", &path),
                        kind: ObservationKind::NativePackage,
                        path: Some(path.display().to_string()),
                        source: format!("linux-{}", provider.name()),
                        evidence: Evidence {
                            observed_path: Some(path.display().to_string()),
                            package_name: Some(pkg.name),
                            package_version: pkg.version,
                            package_manager: Some(provider.name().to_owned()),
                            installed: true,
                            ..Default::default()
                        },
                        confidence: Confidence::Observed,
                        warnings: vec![
                            "package database output treated as untrusted input".to_owned(),
                        ],
                        provenance: vec![format!("{} -S", provider.name())],
                    });
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Resolve package versions for observations that already name a package.
pub fn collect_packages(report: &mut CaptureReportV1) -> Result<(), CaptureError> {
    let providers = all_providers();
    for obs in &mut report.observations {
        if obs.evidence.package_version.is_some() {
            continue;
        }
        let manager = match obs.evidence.package_manager.as_deref() {
            Some(m) => m,
            None => continue,
        };
        let name = match obs.evidence.package_name.as_deref() {
            Some(n) => n,
            None => continue,
        };
        for provider in &providers {
            if provider.name() == manager {
                if let Some(version) = provider.version_of(name) {
                    obs.evidence.package_version = Some(version);
                }
                break;
            }
        }
    }
    Ok(())
}

/// Trace explicitly supplied commands and record observed artifacts.
pub fn trace_explicit_commands(
    report: &mut CaptureReportV1,
    commands: &[String],
) -> Result<(), CaptureError> {
    let tracer =
        crate::collect::trace::StraceTracer::new(crate::collect::trace::StraceLimits::default());
    for cmd in commands {
        let argv: Vec<String> = cmd.split_whitespace().map(str::to_owned).collect();
        match tracer.trace_command(&argv) {
            Ok(events) => {
                record_trace_events(report, &argv, events);
            }
            Err(e) => {
                report.observations.push(Observation {
                    id: obs_id("trace", cmd),
                    kind: ObservationKind::Executable,
                    path: Some(cmd.clone()),
                    source: "linux-trace-request".to_owned(),
                    evidence: Evidence {
                        observed_path: Some(cmd.clone()),
                        executed: true,
                        ..Default::default()
                    },
                    confidence: Confidence::Observed,
                    warnings: vec![format!("dynamic tracing failed: {}", e)],
                    provenance: vec!["user-supplied --run".to_owned()],
                });
            }
        }
    }
    Ok(())
}

fn record_trace_events(
    report: &mut CaptureReportV1,
    argv: &[String],
    events: Vec<crate::collect::trace::TraceEvent>,
) {
    let command_line = argv.join(" ");
    report.observations.push(Observation {
        id: obs_id("trace", &command_line),
        kind: ObservationKind::Executable,
        path: Some(command_line.clone()),
        source: "linux-trace-request".to_owned(),
        evidence: Evidence {
            observed_path: Some(command_line),
            executed: true,
            ..Default::default()
        },
        confidence: Confidence::Observed,
        warnings: vec![],
        provenance: vec!["user-supplied --run".to_owned()],
    });

    for event in events {
        match event {
            crate::collect::trace::TraceEvent::Execve { argv: exec_argv } => {
                let path = exec_argv.first().cloned().unwrap_or_default();
                report.observations.push(Observation {
                    id: obs_id("exec", &path),
                    kind: ObservationKind::Executable,
                    path: Some(path.clone()),
                    source: "strace-execve".to_owned(),
                    evidence: Evidence {
                        observed_path: Some(path),
                        executable_name: exec_argv.get(1).cloned(),
                        executed: true,
                        ..Default::default()
                    },
                    confidence: Confidence::Observed,
                    warnings: vec!["observed via strace; file was not run by capture".to_owned()],
                    provenance: vec!["strace -e execve".to_owned()],
                });
            }
            crate::collect::trace::TraceEvent::Open { path } => {
                report.observations.push(Observation {
                    id: obs_id("file", &path),
                    kind: ObservationKind::FilesystemRequirement,
                    path: Some(path.clone()),
                    source: "strace-open".to_owned(),
                    evidence: Evidence {
                        observed_path: Some(path),
                        opened: true,
                        ..Default::default()
                    },
                    confidence: Confidence::Observed,
                    warnings: vec!["observed via strace".to_owned()],
                    provenance: vec!["strace -e openat,open".to_owned()],
                });
            }
            crate::collect::trace::TraceEvent::Connect { endpoint } => {
                report.observations.push(Observation {
                    id: obs_id("net", &endpoint),
                    kind: ObservationKind::NetworkEndpoint,
                    path: Some(endpoint.clone()),
                    source: "strace-connect".to_owned(),
                    evidence: Evidence {
                        observed_path: Some(endpoint),
                        connected: true,
                        ..Default::default()
                    },
                    confidence: Confidence::Observed,
                    warnings: vec!["observed via strace".to_owned()],
                    provenance: vec!["strace -e connect".to_owned()],
                });
            }
        }
    }
}
