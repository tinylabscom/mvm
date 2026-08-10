//! Baseline regression gate (pure).

use super::report::{BenchReport, DensityReport, LaunchDistributionReport};

/// Outcome of comparing a current run to a baseline.
#[derive(Debug, Clone, PartialEq)]
pub enum RegressionVerdict {
    /// Within tolerance (negative `delta_pct` = improvement).
    Ok { delta_pct: f64 },
    /// Regressed beyond `limit_pct`.
    Regressed { delta_pct: f64, limit_pct: f64 },
    /// The two reports describe different hosts/configs/schema and
    /// must not be compared (avoids false greens after a kernel or
    /// backend change).
    Incomparable { reason: String },
}

/// Compare median `total_ready_ms`. Refuses to compare across a
/// differing host descriptor or schema version — silently comparing
/// a faster kernel's numbers against an older baseline would mask a
/// real regression (or invent a fake one).
pub fn compare_to_baseline(
    baseline: &BenchReport,
    current: &BenchReport,
    max_regression_pct: f64,
) -> RegressionVerdict {
    if baseline.schema_version != current.schema_version {
        return RegressionVerdict::Incomparable {
            reason: format!(
                "schema version differs (baseline {}, current {})",
                baseline.schema_version, current.schema_version
            ),
        };
    }
    if baseline.host != current.host {
        return RegressionVerdict::Incomparable {
            reason: "host descriptor differs (os/arch/hypervisor/kernel/cmdline) — \
                     a baseline from a different host or kernel is not comparable"
                .to_string(),
        };
    }
    let base = baseline.total_ready_ms.p50;
    let cur = current.total_ready_ms.p50;
    if !(base.is_finite() && cur.is_finite()) || base <= 0.0 {
        return RegressionVerdict::Incomparable {
            reason: "non-finite or zero baseline median total_ready_ms".to_string(),
        };
    }
    let delta_pct = (cur - base) / base * 100.0;
    if delta_pct > max_regression_pct {
        RegressionVerdict::Regressed {
            delta_pct,
            limit_pct: max_regression_pct,
        }
    } else {
        RegressionVerdict::Ok { delta_pct }
    }
}

pub fn compare_launch_distribution_to_baseline(
    baseline: &LaunchDistributionReport,
    current: &LaunchDistributionReport,
    max_regression_pct: f64,
) -> RegressionVerdict {
    if baseline.schema_version != current.schema_version {
        return RegressionVerdict::Incomparable {
            reason: format!(
                "schema version differs (baseline {}, current {})",
                baseline.schema_version, current.schema_version
            ),
        };
    }
    if baseline.host != current.host {
        return RegressionVerdict::Incomparable {
            reason: "host descriptor differs (os/arch/hypervisor/kernel/cmdline) — \
                     a baseline from a different host or kernel is not comparable"
                .to_string(),
        };
    }
    if baseline.concurrency != current.concurrency {
        return RegressionVerdict::Incomparable {
            reason: format!(
                "concurrency differs (baseline {}, current {})",
                baseline.concurrency, current.concurrency
            ),
        };
    }
    compare_metric(
        baseline.total_ready_tail_ms.p95,
        current.total_ready_tail_ms.p95,
        max_regression_pct,
        "non-finite or zero baseline p95 total_ready_ms",
    )
}

pub fn compare_density_to_baseline(
    baseline: &DensityReport,
    current: &DensityReport,
    max_regression_pct: f64,
) -> RegressionVerdict {
    if baseline.schema_version != current.schema_version {
        return RegressionVerdict::Incomparable {
            reason: format!(
                "schema version differs (baseline {}, current {})",
                baseline.schema_version, current.schema_version
            ),
        };
    }
    if baseline.host != current.host {
        return RegressionVerdict::Incomparable {
            reason: "host descriptor differs (os/arch/hypervisor/kernel/cmdline) — \
                     a baseline from a different host or kernel is not comparable"
                .to_string(),
        };
    }
    if baseline.count != current.count {
        return RegressionVerdict::Incomparable {
            reason: format!(
                "density count differs (baseline {}, current {})",
                baseline.count, current.count
            ),
        };
    }
    compare_metric(
        baseline.stats.per_instance_bytes as f64,
        current.stats.per_instance_bytes as f64,
        max_regression_pct,
        "zero baseline per_instance_bytes",
    )
}

fn compare_metric(
    baseline: f64,
    current: f64,
    max_regression_pct: f64,
    invalid_reason: &str,
) -> RegressionVerdict {
    if !(baseline.is_finite() && current.is_finite()) || baseline <= 0.0 {
        return RegressionVerdict::Incomparable {
            reason: invalid_reason.to_string(),
        };
    }
    let delta_pct = (current - baseline) / baseline * 100.0;
    if delta_pct > max_regression_pct {
        RegressionVerdict::Regressed {
            delta_pct,
            limit_pct: max_regression_pct,
        }
    } else {
        RegressionVerdict::Ok { delta_pct }
    }
}

#[cfg(test)]
mod tests {
    use super::super::report::{
        HostDescriptor, InstanceFootprint, build_density_report, build_launch_distribution_report,
        build_report,
    };
    use super::super::stats::IterationTiming;
    use super::*;

    fn host(arch: &str) -> HostDescriptor {
        HostDescriptor {
            os: "macos".to_string(),
            arch: arch.to_string(),
            hypervisor: "libkrun".to_string(),
            libkrun_version: Some("1.0".to_string()),
            kernel_sha256: Some("deadbeef".to_string()),
            cmdline: Some("root=/dev/vda rw init=/init".to_string()),
            readiness_boundary: Some("guest-agent-ping".to_string()),
        }
    }

    fn report_with_median(arch: &str, median: f64) -> BenchReport {
        let raw = vec![IterationTiming {
            start_to_pid_ms: 1.0,
            pid_to_connect_ms: 1.0,
            handshake_ms: 1.0,
            total_ready_ms: median,
        }];
        build_report(host(arch), 1, 0, raw)
    }

    #[test]
    fn baseline_flags_regression_and_passes_improvement() {
        let base = report_with_median("aarch64", 100.0);
        let worse = report_with_median("aarch64", 120.0);
        let better = report_with_median("aarch64", 80.0);

        assert!(matches!(
            compare_to_baseline(&base, &worse, 10.0),
            RegressionVerdict::Regressed { .. }
        ));
        assert!(matches!(
            compare_to_baseline(&base, &better, 10.0),
            RegressionVerdict::Ok { .. }
        ));
        // Exactly at the limit is not a regression.
        let at_limit = report_with_median("aarch64", 110.0);
        assert!(matches!(
            compare_to_baseline(&base, &at_limit, 10.0),
            RegressionVerdict::Ok { .. }
        ));
    }

    #[test]
    fn baseline_refuses_cross_host_comparison() {
        let base = report_with_median("aarch64", 100.0);
        let other = report_with_median("x86_64", 100.0);
        assert!(matches!(
            compare_to_baseline(&base, &other, 10.0),
            RegressionVerdict::Incomparable { .. }
        ));
    }

    #[test]
    fn launch_distribution_baseline_compares_concurrency_p95() {
        let base = build_launch_distribution_report(
            host("aarch64"),
            2,
            vec![
                IterationTiming {
                    start_to_pid_ms: 1.0,
                    pid_to_connect_ms: 0.0,
                    handshake_ms: 0.0,
                    total_ready_ms: 100.0,
                },
                IterationTiming {
                    start_to_pid_ms: 1.0,
                    pid_to_connect_ms: 0.0,
                    handshake_ms: 0.0,
                    total_ready_ms: 100.0,
                },
            ],
        );
        let worse = build_launch_distribution_report(
            host("aarch64"),
            2,
            vec![
                IterationTiming {
                    start_to_pid_ms: 1.0,
                    pid_to_connect_ms: 0.0,
                    handshake_ms: 0.0,
                    total_ready_ms: 130.0,
                },
                IterationTiming {
                    start_to_pid_ms: 1.0,
                    pid_to_connect_ms: 0.0,
                    handshake_ms: 0.0,
                    total_ready_ms: 130.0,
                },
            ],
        );
        assert!(matches!(
            compare_launch_distribution_to_baseline(&base, &worse, 10.0),
            RegressionVerdict::Regressed { .. }
        ));
    }

    #[test]
    fn density_baseline_compares_per_instance_bytes() {
        let baseline = build_density_report(
            host("aarch64"),
            2,
            2,
            vec![
                InstanceFootprint {
                    vm_name: "a".to_string(),
                    pid: 1,
                    bytes: 100,
                    guest_agent_rss_bytes: None,
                },
                InstanceFootprint {
                    vm_name: "b".to_string(),
                    pid: 2,
                    bytes: 100,
                    guest_agent_rss_bytes: None,
                },
            ],
        );
        let current = build_density_report(
            host("aarch64"),
            2,
            2,
            vec![
                InstanceFootprint {
                    vm_name: "a".to_string(),
                    pid: 1,
                    bytes: 130,
                    guest_agent_rss_bytes: None,
                },
                InstanceFootprint {
                    vm_name: "b".to_string(),
                    pid: 2,
                    bytes: 130,
                    guest_agent_rss_bytes: None,
                },
            ],
        );

        assert!(matches!(
            compare_density_to_baseline(&baseline, &current, 10.0),
            RegressionVerdict::Regressed { .. }
        ));
    }
}
