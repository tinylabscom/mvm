//! Reading and writing the committed mutation-witness baseline.

use super::*;
use anyhow::{Context, Result};
use std::path::Path;

pub(crate) fn read_baseline(path: &Path) -> Result<Baseline> {
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!(
            "reading {} — seed it with `cargo run -p xtask -- check-mutation-witnesses \
             --write-baseline`",
            path.display()
        )
    })?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

pub(crate) fn write_baseline(path: &Path, baseline: &Baseline) -> Result<()> {
    let mut json = serde_json::to_string_pretty(baseline)
        .context("serializing the mutation-witness baseline")?;
    json.push('\n');
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(file: &str, mutant: &str) -> AcceptedMiss {
        AcceptedMiss {
            file: file.into(),
            mutant: mutant.into(),
            reason: "known".into(),
        }
    }

    fn surface(path: &str, claims: Vec<u32>) -> SurfaceFile {
        SurfaceFile {
            path: path.into(),
            package: package_for(path).unwrap_or_else(|| "unknown".into()),
            claims,
            scope: None,
            features: Vec::new(),
        }
    }

    fn uncovered(number: u32) -> UncoveredClaim {
        UncoveredClaim {
            number,
            why: WHY_NO_FN_WITNESS.to_string(),
        }
    }

    #[test]
    fn baseline_round_trips_through_json() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("baseline.json");
        let baseline = Baseline {
            surface: vec![surface("crates/a/src/l.rs", vec![1, 2])],
            uncovered_claims: vec![uncovered(7)],
            accepted_misses: vec![accepted("crates/a/src/l.rs", "replace x")],
        };
        write_baseline(&path, &baseline).unwrap();
        let back = read_baseline(&path).unwrap();
        assert_eq!(back.surface, baseline.surface);
        assert_eq!(back.uncovered_claims, baseline.uncovered_claims);
        assert_eq!(back.accepted_misses, baseline.accepted_misses);
    }

    #[test]
    fn missing_baseline_names_the_command_that_seeds_it() {
        let err = read_baseline(Path::new("/nonexistent/baseline.json")).unwrap_err();
        assert!(format!("{err}").contains("--write-baseline"));
    }
}
