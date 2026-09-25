//! Per-package shard selection and the CI shard-matrix cross-check.

use super::*;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

impl std::fmt::Display for ShardSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.shard {
            None => write!(f, "{}", self.package),
            Some((i, n)) => write!(f, "{}/{i}of{n}", self.package),
        }
    }
}

/// The lane's shard matrix must name exactly the packages on the surface.
///
/// The shards exist because the whole surface cannot finish inside a
/// GitHub job's six-hour cap. That makes the matrix a second place the
/// surface is written down, and a package that joins the ledger but not
/// the matrix is simply never mutated — while every shard stays green.
/// That is the same silent-loss failure the committed surface pin exists
/// to prevent, one level out, so it is checked the same way.
pub fn check_shard_matrix(workspace: &Path, surface: &[SurfaceFile]) -> Vec<String> {
    let path = workspace.join(SECURITY_WORKFLOW_REL);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return vec![format!(
            "cannot read {SECURITY_WORKFLOW_REL} to verify the mutation shard matrix"
        )];
    };
    let entries = shard_entries(&text);
    if entries.is_empty() {
        return vec![format!(
            "{SECURITY_WORKFLOW_REL} declares no mutation shard matrix; the nightly lane would \
             measure nothing"
        )];
    }
    let mut errors = Vec::new();
    let mut declared: BTreeMap<String, Vec<(usize, usize)>> = BTreeMap::new();
    for raw in &entries {
        match parse_shard_spec(raw) {
            Ok(spec) => {
                let slot = declared.entry(spec.package).or_default();
                if let Some(pair) = spec.shard {
                    slot.push(pair);
                }
            }
            Err(err) => errors.push(format!(
                "{SECURITY_WORKFLOW_REL} declares an unparseable mutation shard {raw:?}: {err}"
            )),
        }
    }

    let wanted: BTreeSet<&str> = surface.iter().map(|s| s.package.as_str()).collect();
    for pkg in &wanted {
        if !declared.contains_key(*pkg) {
            errors.push(format!(
                "package {pkg} is on the mutation surface but has no shard in \
                 {SECURITY_WORKFLOW_REL}, so nothing ever mutates it"
            ));
        }
    }
    for pkg in declared.keys() {
        if !wanted.contains(pkg.as_str()) {
            errors.push(format!(
                "{SECURITY_WORKFLOW_REL} declares a mutation shard for {pkg}, which owns no \
                 surface file; the shard would fail on an empty surface"
            ));
        }
    }

    // A package cut into shards must be cut completely. A missing or repeated
    // index is the same silent loss the package check above exists to catch —
    // the files that shard owned are simply never mutated, and every remaining
    // shard still goes green.
    for (pkg, shards) in &declared {
        if shards.is_empty() {
            continue;
        }
        let count = entries
            .iter()
            .filter(|raw| parse_shard_spec(raw).is_ok_and(|s| &s.package == pkg))
            .count();
        if count != shards.len() {
            errors.push(format!(
                "{SECURITY_WORKFLOW_REL} mixes sharded and unsharded entries for {pkg}; the \
                 unsharded one re-runs work a shard already owns"
            ));
            continue;
        }
        let total = shards[0].1;
        if shards.iter().any(|(_, t)| *t != total) {
            errors.push(format!(
                "{SECURITY_WORKFLOW_REL} declares shards of {pkg} with disagreeing totals; the \
                 surface would be split more than one way at once"
            ));
            continue;
        }
        let seen: BTreeSet<usize> = shards.iter().map(|(i, _)| *i).collect();
        let expected: BTreeSet<usize> = (1..=total).collect();
        if seen != expected {
            errors.push(format!(
                "{SECURITY_WORKFLOW_REL} declares shards {seen:?} of {total} for {pkg}; the \
                 missing ones own surface files nothing would mutate"
            ));
        }
    }
    errors
}

/// The raw `package:` entries under the mutation job's matrix.
///
/// Text-scanned rather than YAML-parsed, matching the sibling gates and
/// the workspace's deliberate dependency floor.
pub fn shard_entries(workflow: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_job = false;
    let mut in_list = false;
    for line in workflow.lines() {
        if line.starts_with("  mutation-witnesses:") {
            in_job = true;
            continue;
        }
        if in_job && line.starts_with("  ") && !line.starts_with("   ") && line.ends_with(':') {
            break; // next job at the same indent
        }
        if !in_job {
            continue;
        }
        let t = line.trim();
        if t == "package:" {
            in_list = true;
            continue;
        }
        if in_list {
            if let Some(name) = t.strip_prefix("- ") {
                out.push(name.trim().to_string());
            } else if !t.is_empty() && !t.starts_with('#') {
                // A comment between entries is not the end of the list.
                // Treating it as one truncates the matrix silently, and
                // every package below the comment reads as unsharded.
                in_list = false;
            }
        }
    }
    out
}

/// Parse `mvm-hostd` or `mvm-hostd/1of2`.
///
/// Rejects rather than rounds: a typo that silently selected the whole
/// package would double the work and hide the shard that vanished, and a
/// zero or out-of-range index would quietly measure nothing.
pub fn parse_shard_spec(raw: &str) -> Result<ShardSpec> {
    let raw = raw.trim();
    let Some((package, shard)) = raw.split_once('/') else {
        return Ok(ShardSpec {
            package: raw.to_string(),
            shard: None,
        });
    };
    let Some((index, total)) = shard.split_once("of") else {
        bail!("malformed shard {raw:?}: expected <package>/<index>of<total>, e.g. mvm-hostd/1of2");
    };
    let index: usize = index
        .parse()
        .with_context(|| format!("malformed shard index in {raw:?}"))?;
    let total: usize = total
        .parse()
        .with_context(|| format!("malformed shard total in {raw:?}"))?;
    if total == 0 || index == 0 || index > total {
        bail!("malformed shard {raw:?}: index must be within 1..={total}");
    }
    Ok(ShardSpec {
        package: package.to_string(),
        shard: Some((index, total)),
    })
}

/// The surface files this shard owns, or all of them when unfiltered.
///
/// Files are ordered by path before packing, so which shard owns a file
/// is a property of the committed surface rather than of resolution
/// order — otherwise a file could migrate between shards without the
/// baseline changing, and a survivor would appear and vanish by shard.
///
/// Shards are packed longest-first by source size rather than sliced by
/// stride. Mutation cost spans more than an order of magnitude across one
/// package's surface, and a cost-blind split parks the expensive files
/// together: `mvm-hostd` shards 2 and 4 were killed at the lane's timeout
/// nightly, each holding two ~150-minute files, while shard 3 finished its
/// three cheapest in 24 minutes. Size is a coarse stand-in for cost, but
/// any cost-aware packing beats a blind one, and it needs nothing recorded
/// or maintained alongside the surface.
pub fn for_shard(
    workspace: &Path,
    surface: &[SurfaceFile],
    spec: Option<&ShardSpec>,
) -> Vec<SurfaceFile> {
    for_shard_by_weight(surface, spec, &|f| source_weight(workspace, f))
}

/// A surface file's stand-in for mutation cost.
///
/// Never zero: a file the workspace cannot stat still has to land
/// somewhere, and equal weights make the packing fall back to plain
/// round-robin rather than piling every file onto the first shard.
fn source_weight(workspace: &Path, file: &SurfaceFile) -> u64 {
    std::fs::metadata(workspace.join(&file.path))
        .map(|m| m.len())
        .unwrap_or(0)
        .max(1)
}

/// [`for_shard`] against a caller-supplied cost, so the packing can be
/// tested without a workspace on disk.
fn for_shard_by_weight(
    surface: &[SurfaceFile],
    spec: Option<&ShardSpec>,
    weight: &dyn Fn(&SurfaceFile) -> u64,
) -> Vec<SurfaceFile> {
    let Some(spec) = spec else {
        return surface.to_vec();
    };
    let mut owned: Vec<SurfaceFile> = surface
        .iter()
        .filter(|s| s.package == spec.package)
        .cloned()
        .collect();
    owned.sort_by(|a, b| a.path.cmp(&b.path));
    let Some((index, total)) = spec.shard else {
        return owned;
    };

    // Heaviest file onto the lightest shard, ties by path then by shard
    // index, so the assignment is a pure function of the surface.
    let mut ordered: Vec<(u64, SurfaceFile)> = owned.into_iter().map(|f| (weight(&f), f)).collect();
    ordered.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.path.cmp(&b.1.path)));

    let mut loads = vec![0u64; total];
    let mut mine = Vec::new();
    for (w, file) in ordered {
        let target = loads
            .iter()
            .enumerate()
            .min_by_key(|(i, load)| (**load, *i))
            .map(|(i, _)| i)
            .expect("a shard total of zero is rejected when the spec is parsed");
        loads[target] += w;
        if target == index - 1 {
            mine.push(file);
        }
    }
    mine.sort_by(|a, b| a.path.cmp(&b.path));
    mine
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surface(path: &str, claims: Vec<u32>) -> SurfaceFile {
        SurfaceFile {
            path: path.into(),
            package: package_for(path).unwrap_or_else(|| "unknown".into()),
            claims,
            scope: None,
            features: Vec::new(),
        }
    }

    /// Shard a surface at uniform cost. The packing degenerates to
    /// round-robin when every file weighs the same, which is what these
    /// tests pin: membership, disjointness, coverage, order-independence.
    fn even(surface: &[SurfaceFile], spec: Option<&ShardSpec>) -> Vec<SurfaceFile> {
        for_shard_by_weight(surface, spec, &|_| 1)
    }

    const SHARD_WORKFLOW: &str = "\
jobs:
  other-job:
    name: not this one
    strategy:
      matrix:
        package:
          - not-a-real-package
  mutation-witnesses:
    name: Claim witnesses
    strategy:
      fail-fast: false
      matrix:
        package:
          - mvm-cli
          - mvm-hostd
    steps:
      - run: true
  later-job:
    name: after
";

    #[test]
    fn a_comment_between_entries_does_not_truncate_the_matrix() {
        let workflow = "\
jobs:
  mutation-witnesses:
    strategy:
      matrix:
        package:
          - mvm-cli
          # why this one is split
          - mvm-hostd/1of2
          - mvm-hostd/2of2
  later-job:
    name: after
";
        assert_eq!(
            shard_entries(workflow),
            vec![
                "mvm-cli".to_string(),
                "mvm-hostd/1of2".to_string(),
                "mvm-hostd/2of2".to_string(),
            ],
            "a comment must not end the list and silently unshard everything below it"
        );
    }

    #[test]
    fn shard_entries_read_only_the_mutation_jobs_matrix() {
        let got = shard_entries(SHARD_WORKFLOW);
        assert_eq!(
            got,
            vec!["mvm-cli".to_string(), "mvm-hostd".to_string()],
            "a sibling job's matrix must not leak into the mutation shard list"
        );
    }

    #[test]
    fn a_surface_package_with_no_shard_is_reported() {
        let declared: BTreeSet<String> = shard_entries(SHARD_WORKFLOW).into_iter().collect();
        // mvm-core is on the surface but absent from the matrix above.
        let surface = [
            surface("crates/mvm-cli/src/a.rs", vec![1]),
            surface("crates/mvm-core/src/b.rs", vec![2]),
        ];
        let missing: Vec<&str> = surface
            .iter()
            .map(|s| s.package.as_str())
            .filter(|p| !declared.contains(*p))
            .collect();
        assert_eq!(
            missing,
            vec!["mvm-core"],
            "a package on the surface with no shard must be visible"
        );
    }

    #[test]
    fn a_shard_for_a_package_with_no_surface_file_is_reported() {
        let declared: BTreeSet<String> = shard_entries(SHARD_WORKFLOW).into_iter().collect();
        let surface = [surface("crates/mvm-cli/src/a.rs", vec![1])];
        let wanted: BTreeSet<&str> = surface.iter().map(|s| s.package.as_str()).collect();
        let extra: Vec<&String> = declared
            .iter()
            .filter(|p| !wanted.contains(p.as_str()))
            .collect();
        assert_eq!(
            extra.len(),
            1,
            "a shard whose package owns no surface file must be visible"
        );
    }

    #[test]
    fn a_package_shard_selects_only_that_packages_files() {
        let surface = [
            surface("crates/mvm-cli/src/a.rs", vec![1]),
            surface("crates/mvm-cli/src/b.rs", vec![2]),
            surface("crates/mvm-hostd/src/c.rs", vec![3]),
        ];
        let cli = even(
            &surface,
            Some(&ShardSpec {
                package: "mvm-cli".to_string(),
                shard: None,
            }),
        );
        assert_eq!(cli.len(), 2);
        assert!(cli.iter().all(|s| s.package == "mvm-cli"));

        assert_eq!(
            even(
                &surface,
                Some(&ShardSpec {
                    package: "mvm-hostd".to_string(),
                    shard: None,
                })
            )
            .len(),
            1
        );
        // Unfiltered is the whole surface, so a non-sharded run is
        // unchanged.
        assert_eq!(even(&surface, None).len(), 3);
        // A package with no surface files yields nothing, which the caller
        // turns into a failure rather than a silent pass.
        assert!(
            even(
                &surface,
                Some(&ShardSpec {
                    package: "mvm-sdk".to_string(),
                    shard: None,
                })
            )
            .is_empty()
        );
    }

    /// Every shard together must cover the surface exactly once. A package
    /// dropped from the matrix would otherwise go unmeasured while every
    /// job stayed green.
    #[test]
    fn the_shards_partition_the_surface() {
        let surface = [
            surface("crates/mvm-cli/src/a.rs", vec![1]),
            surface("crates/mvm-hostd/src/c.rs", vec![3]),
            surface("crates/mvm-core/src/d.rs", vec![4]),
        ];
        let packages: BTreeSet<&str> = surface.iter().map(|s| s.package.as_str()).collect();
        let mut seen: Vec<String> = Vec::new();
        for p in &packages {
            let spec = ShardSpec {
                package: (*p).to_string(),
                shard: None,
            };
            for f in even(&surface, Some(&spec)) {
                seen.push(f.path);
            }
        }
        seen.sort();
        let mut all: Vec<String> = surface.iter().map(|s| s.path.clone()).collect();
        all.sort();
        assert_eq!(seen, all, "the shards must cover every file exactly once");
    }

    #[test]
    fn a_shard_spec_round_trips_and_rejects_nonsense() {
        assert_eq!(
            parse_shard_spec("mvm-hostd").unwrap(),
            ShardSpec {
                package: "mvm-hostd".to_string(),
                shard: None
            }
        );
        let sharded = parse_shard_spec("mvm-hostd/2of3").unwrap();
        assert_eq!(sharded.package, "mvm-hostd");
        assert_eq!(sharded.shard, Some((2, 3)));
        // Display is what the matrix and the log line both print, so it has
        // to be the form the parser accepts back.
        assert_eq!(sharded.to_string(), "mvm-hostd/2of3");
        assert_eq!(parse_shard_spec(&sharded.to_string()).unwrap(), sharded);

        // A shard that names no valid slice must fail rather than quietly
        // widening to the whole package and doubling the run.
        for bad in [
            "mvm-hostd/",
            "mvm-hostd/0of2",
            "mvm-hostd/3of2",
            "mvm-hostd/xofy",
        ] {
            assert!(
                parse_shard_spec(bad).is_err(),
                "{bad} must not parse as a shard"
            );
        }
    }

    /// The whole point of splitting a package: every file it owns is still
    /// mutated exactly once, across the shards rather than within one job.
    #[test]
    fn the_shards_of_one_package_partition_its_files() {
        let surface: Vec<SurfaceFile> = ["e", "a", "d", "b", "c"]
            .iter()
            .map(|n| surface(&format!("crates/mvm-hostd/src/{n}.rs"), vec![8]))
            .collect();

        let one = even(&surface, Some(&parse_shard_spec("mvm-hostd/1of2").unwrap()));
        let two = even(&surface, Some(&parse_shard_spec("mvm-hostd/2of2").unwrap()));

        // Disjoint.
        let a: BTreeSet<&str> = one.iter().map(|f| f.path.as_str()).collect();
        let b: BTreeSet<&str> = two.iter().map(|f| f.path.as_str()).collect();
        assert!(
            a.is_disjoint(&b),
            "no file may be mutated twice: {a:?} overlaps {b:?}"
        );

        // Complete.
        let mut seen: Vec<&str> = a.union(&b).copied().collect();
        seen.sort_unstable();
        let mut all: Vec<&str> = surface.iter().map(|f| f.path.as_str()).collect();
        all.sort_unstable();
        assert_eq!(seen, all, "every file must land in exactly one shard");

        // Balanced to within one file, or the split has not bought anything.
        assert!(one.len().abs_diff(two.len()) <= 1);
    }

    /// The regression this packing exists for.
    ///
    /// These are the measured per-file costs of `mvm-hostd`'s surface from
    /// the nightly of 2026-08-21 (Security run 32448509693), in minutes.
    /// Round-robin over the path-sorted surface put `network/stages.rs` with
    /// `plan_admission.rs` on one shard and `audit_file.rs` with
    /// `network_endpoint_proxy.rs` on another; both ran past the lane's
    /// 330-minute timeout and were killed, nightly, while a third shard
    /// finished its three cheapest files in 24 minutes.
    ///
    /// The assertion is on balance, not on wall-clock minutes. Two of the
    /// costs above are lower bounds — those shards were killed part-way
    /// through a file, so the real number is higher — which makes any
    /// absolute budget compared against them meaningless: round-robin's
    /// worst shard measures 324, and would slip under a literal 330. Against
    /// the ideal even split it is 1.70x, and that ratio is what separates a
    /// cost-blind split from a cost-aware one.
    #[test]
    fn cost_packing_balances_a_surface_that_round_robin_left_lopsided() {
        // (path, measured minutes)
        let measured: [(&str, u64); 11] = [
            ("crates/mvm-hostd/src/supervisor/network/stages.rs", 163),
            ("crates/mvm-hostd/src/plan_admission.rs", 161),
            ("crates/mvm-hostd/src/supervisor/audit_file.rs", 141),
            (
                "crates/mvm-hostd/src/supervisor/network_endpoint_proxy.rs",
                132,
            ),
            ("crates/mvm-hostd/src/stream/input_gate.rs", 61),
            ("crates/mvm-hostd/src/broker/registry.rs", 50),
            ("crates/mvm-hostd/src/supervisor/network_endpoint.rs", 22),
            ("crates/mvm-hostd/src/supervisor/wall_clock.rs", 9),
            ("crates/mvm-hostd/src/keyholder/substitution.rs", 9),
            ("crates/mvm-hostd/src/admission_budget.rs", 7),
            ("crates/mvm-hostd/src/supervisor/dns_audit.rs", 6),
        ];
        let cost: BTreeMap<&str, u64> = measured.iter().copied().collect();
        let surface: Vec<SurfaceFile> = measured
            .iter()
            .map(|(path, _)| surface(path, vec![8]))
            .collect();

        let total = 4;
        let sum: u64 = measured.iter().map(|(_, c)| c).sum();
        // Half again the ideal even split. Round-robin lands at 1.70x of it,
        // longest-first at 1.01x, so the bound discriminates while leaving
        // room for the surface to drift.
        let ceiling = sum * 3 / (total as u64 * 2);

        let mut covered: Vec<String> = Vec::new();
        for index in 1..=total {
            let spec = ShardSpec {
                package: "mvm-hostd".to_string(),
                shard: Some((index, total)),
            };
            let files = for_shard_by_weight(&surface, Some(&spec), &|f| cost[f.path.as_str()]);
            let load: u64 = files.iter().map(|f| cost[f.path.as_str()]).sum();
            assert!(
                load <= ceiling,
                "shard {index}of{total} carries {load} minutes against a {ceiling} \
                 ceiling — the split is not cost-aware: {:?}",
                files.iter().map(|f| &f.path).collect::<Vec<_>>()
            );
            covered.extend(files.into_iter().map(|f| f.path));
        }

        // Still a partition: a cheap shard must not come from dropped work.
        covered.sort();
        let mut all: Vec<String> = surface.iter().map(|f| f.path.clone()).collect();
        all.sort();
        assert_eq!(covered, all, "every file must land in exactly one shard");
    }

    /// Which shard owns a file must not depend on the order resolution
    /// happened to emit, or a survivor would move between shards without
    /// the baseline changing.
    #[test]
    fn shard_membership_follows_the_path_not_the_input_order() {
        let names = ["c", "a", "b", "d"];
        let forward: Vec<SurfaceFile> = names
            .iter()
            .map(|n| surface(&format!("crates/mvm-hostd/src/{n}.rs"), vec![8]))
            .collect();
        let mut backward = forward.clone();
        backward.reverse();

        let spec = parse_shard_spec("mvm-hostd/1of2").unwrap();
        let a: Vec<String> = even(&forward, Some(&spec))
            .into_iter()
            .map(|f| f.path)
            .collect();
        let b: Vec<String> = even(&backward, Some(&spec))
            .into_iter()
            .map(|f| f.path)
            .collect();
        assert_eq!(a, b, "shard membership must be a property of the surface");
    }

    /// A package cut into shards must be cut completely. Dropping `2of2`
    /// leaves its files unmutated while `1of2` still reports success — the
    /// silent loss this gate exists to prevent, one level in.
    #[test]
    fn an_incomplete_shard_set_is_reported() {
        let entries = ["mvm-hostd/1of2".to_string()];
        let mut shards: Vec<(usize, usize)> = Vec::new();
        for raw in &entries {
            if let Some(pair) = parse_shard_spec(raw).unwrap().shard {
                shards.push(pair);
            }
        }
        let total = shards[0].1;
        let seen: BTreeSet<usize> = shards.iter().map(|(i, _)| *i).collect();
        let expected: BTreeSet<usize> = (1..=total).collect();
        assert_ne!(
            seen, expected,
            "a half-declared split must not look complete"
        );
    }
}
