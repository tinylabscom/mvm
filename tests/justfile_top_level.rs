//! The root justfile is a deliberately small, CI-mirroring surface; the
//! modules under `just/` carry everything else. These guards pin that
//! shape so the surface cannot quietly grow back.

const JUSTFILE: &str = include_str!("../Justfile");

/// Recipe and module names share one namespace, so the top level is exactly
/// this set — no more, no fewer.
#[test]
fn root_recipes_are_exactly_the_ci_mirror_set() {
    let mut names: Vec<&str> = Vec::new();
    for line in JUSTFILE.lines() {
        // Recipe headers sit at column 0; indented body lines may contain
        // ':' (module calls, case arms) and are not headers.
        if line.starts_with(|c: char| c.is_whitespace())
            || line.starts_with('#')
            || line.starts_with("set ")
            || line.starts_with("mod ")
        {
            continue;
        }
        let Some(colon) = line.find(':') else {
            continue;
        };
        let head = &line[..colon];
        let name = head.split_whitespace().next().unwrap_or("");
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            names.push(name);
        }
    }
    names.sort_unstable();
    names.dedup();
    assert_eq!(
        names,
        [
            "build",
            "ci",
            "default",
            "docs",
            "embed",
            "lint",
            "release-build",
            "test"
        ],
        "the root justfile surface changed — update this guard and the docs deliberately"
    );
}

/// Every module the root justfile declares. `include_str!` proves each file
/// exists at compile time, so a deleted or renamed module breaks this test
/// target's build rather than failing only at `just --list` time.
#[test]
fn declared_modules_exist() {
    let _audit = include_str!("../just/audit/mod.just");
    let _bdd = include_str!("../just/bdd/mod.just");
    let _check = include_str!("../just/check/mod.just");
    let _e2e = include_str!("../just/e2e/mod.just");
    let _kernel = include_str!("../just/kernel/mod.just");
    let _lints = include_str!("../just/lints/mod.just");
    let _maint = include_str!("../just/maint/mod.just");
    let _mem = include_str!("../just/mem/mod.just");
    let _payload = include_str!("../just/payload/mod.just");
    let _release = include_str!("../just/release/mod.just");
    let _sdk = include_str!("../just/sdk/mod.just");
    let _site = include_str!("../just/site/mod.just");
    let _tests = include_str!("../just/tests/mod.just");
}
