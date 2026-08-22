//! Non-Linux stub collector.

use crate::report::CaptureReportV1;

pub fn record_unsupported(report: &mut CaptureReportV1) {
    report.warnings.push(
        "native package and executable collection require Linux; only project manifests were scanned"
            .to_owned(),
    );
}
