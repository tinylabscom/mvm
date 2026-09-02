//! Renders the published launch-budget contract as markdown.
//!
//! The budget table on the public performance page is generated from
//! [`LaunchLane::budgets`] — the same accessor
//! [`validate_matrix_report`](super::cold_launch::validate_matrix_report)
//! gates against — so a published number cannot drift from the number CI
//! enforces. A doc-sync test re-renders this and compares it to the committed
//! page; changing a budget constant without regenerating the page fails.
//!
//! This module renders the *contract*, not measurements. Measured percentiles
//! come from a seeded matrix report and are published separately, because a
//! budget is a promise and a percentile is an observation, and printing them
//! in one column without saying which is which is how a ceiling gets read as
//! a result.

use super::cold_launch::{
    COLD_LAUNCH_SCHEMA_VERSION, LaunchLane, MATRIX_WARMUP_SAMPLES, MIN_MATRIX_SAMPLES,
    PREPARED_COLD_HARD_MAX_MS,
};

/// Delimiters bounding the generated region of the performance page. The text
/// outside them is hand-written prose the generator neither reads nor rewrites.
pub const BEGIN_MARKER: &str = "<!-- generated:launch-budgets:begin -->";
pub const END_MARKER: &str = "<!-- generated:launch-budgets:end -->";

/// Format one budget cell. An unbudgeted percentile prints as an em dash with
/// no number, so a reader cannot mistake "not gated" for "gated at zero".
fn cell(budget_ms: Option<f64>) -> String {
    match budget_ms {
        Some(ms) => format!("{ms:.0} ms"),
        None => "—".to_string(),
    }
}

fn hard_max_cell(budget_ms: Option<f64>) -> String {
    match budget_ms {
        Some(ms) => format!("< {ms:.0} ms"),
        None => "—".to_string(),
    }
}

/// The sample-count contract a lane report must satisfy to be published,
/// stated from the constants the report-level gate enforces.
#[must_use]
pub fn sample_contract_sentence() -> String {
    format!(
        "A lane result is publishable only when it carries at least \
         {MIN_MATRIX_SAMPLES} measured samples taken after exactly \
         {MATRIX_WARMUP_SAMPLES} discarded warm-ups, under report schema \
         version {COLD_LAUNCH_SCHEMA_VERSION}. A report that misses any of \
         those is refused rather than published with a caveat. Prepared-cold \
         lanes additionally require every measured dispatch to be strictly \
         under {PREPARED_COLD_HARD_MAX_MS:.0} ms, even below the publication \
         sample floor."
    )
}

/// Render the generated region: the sample contract, then one row per lane.
///
/// The output is bounded by [`BEGIN_MARKER`] / [`END_MARKER`] and ends with a
/// trailing newline so it can be spliced into the page verbatim.
#[must_use]
pub fn render_budget_section() -> String {
    let mut out = String::new();
    out.push_str(BEGIN_MARKER);
    out.push_str("\n\n");
    out.push_str(&sample_contract_sentence());
    out.push_str("\n\n");
    out.push_str("| Lane | What it measures | p50 | p95 | p99 | Every boot |\n");
    out.push_str("| --- | --- | --- | --- | --- | --- |\n");
    for lane in LaunchLane::ALL {
        let budgets = lane.budgets();
        out.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} |\n",
            lane.as_str(),
            lane.description(),
            cell(budgets.p50_ms),
            cell(budgets.p95_ms),
            cell(budgets.p99_ms),
            hard_max_cell(budgets.hard_max_ms),
        ));
    }
    out.push('\n');
    out.push_str(END_MARKER);
    out.push('\n');
    out
}

/// Extract the generated region from `page`, inclusive of both markers.
///
/// Returns `None` when either marker is absent or they appear out of order —
/// a page the generator cannot locate its own region in is a drift failure,
/// not something to silently append to.
#[must_use]
pub fn extract_budget_section(page: &str) -> Option<&str> {
    let begin = page.find(BEGIN_MARKER)?;
    let end = page.find(END_MARKER)?;
    if end < begin {
        return None;
    }
    Some(&page[begin..end + END_MARKER.len()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_lane_gets_a_row_naming_itself() {
        let rendered = render_budget_section();
        for lane in LaunchLane::ALL {
            assert!(
                rendered.contains(&format!("| `{}` |", lane.as_str())),
                "lane {} is missing from the rendered table",
                lane.as_str()
            );
            assert!(
                rendered.contains(lane.description()),
                "lane {} rendered without its description",
                lane.as_str()
            );
        }
    }

    #[test]
    fn budgeted_lanes_print_their_gated_numbers() {
        let rendered = render_budget_section();
        // The prepared-cold contract: 200/250/300 ms at p50/p95/p99.
        assert!(rendered.contains("| 200 ms | 250 ms | 300 ms | < 200 ms |"));
        // The warm-claim contract publishes no p95, and says so with a dash
        // rather than a zero.
        assert!(rendered.contains("| 30 ms | — | 50 ms | — |"));
    }

    #[test]
    fn unbudgeted_lanes_render_a_dash_and_never_a_zero() {
        for lane in [LaunchLane::MountMiss, LaunchLane::ArtifactMiss] {
            let budgets = lane.budgets();
            assert_eq!(budgets.p50_ms, None);
            assert_eq!(budgets.p95_ms, None);
            assert_eq!(budgets.p99_ms, None);
            assert_eq!(budgets.hard_max_ms, None);
        }
        let rendered = render_budget_section();
        assert!(rendered.contains("| — | — | — | — |"));
        assert!(
            !rendered.contains("| 0 ms"),
            "an unbudgeted percentile must never render as a zero budget"
        );
        assert_eq!(cell(None), "—");
    }

    #[test]
    fn rendered_section_is_delimited_and_round_trips_through_extraction() {
        let rendered = render_budget_section();
        assert!(rendered.starts_with(BEGIN_MARKER));
        assert!(rendered.trim_end().ends_with(END_MARKER));

        let page = format!("# Title\n\nprose before\n\n{rendered}\nprose after\n");
        assert_eq!(
            extract_budget_section(&page),
            Some(rendered.trim_end_matches('\n'))
        );
    }

    #[test]
    fn extraction_refuses_a_page_with_missing_or_inverted_markers() {
        assert_eq!(extract_budget_section("no markers at all"), None);
        assert_eq!(extract_budget_section(BEGIN_MARKER), None);
        assert_eq!(extract_budget_section(END_MARKER), None);
        let inverted = format!("{END_MARKER}\nrows\n{BEGIN_MARKER}");
        assert_eq!(extract_budget_section(&inverted), None);
    }

    /// Substring assertions on a bare "5" would pass against "250 ms"; each
    /// number is anchored to the words around it so the test fails when a
    /// constant changes rather than matching some other cell.
    #[test]
    fn sample_contract_numbers_come_from_the_gate_constants() {
        let sentence = sample_contract_sentence();
        assert!(sentence.contains(&format!("at least {MIN_MATRIX_SAMPLES} measured samples")));
        assert!(sentence.contains(&format!(
            "exactly {MATRIX_WARMUP_SAMPLES} discarded warm-ups"
        )));
        assert!(sentence.contains(&format!("schema version {COLD_LAUNCH_SCHEMA_VERSION}")));
        assert!(sentence.contains(&format!("strictly under {PREPARED_COLD_HARD_MAX_MS:.0} ms")));
        assert!(render_budget_section().contains(&sentence));
    }
}
