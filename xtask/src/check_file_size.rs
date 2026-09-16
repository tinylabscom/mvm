//! `xtask check-file-size` — asserts no non-test source file carries an
//! oversized production body.
//!
//! "Production lines" are lines outside items gated exclusively to tests.
//! Inline test modules and functions therefore don't count, even when they are
//! interleaved with production items. Dedicated test/fixture files and modules
//! gated at their declaration site are exempt too.
//!
//! The threshold keeps files small enough to hold in one reading; when a file
//! trips it, decompose its production body into a module tree and move each
//! inline test with the code it exercises.

use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use crate::rust_source::blank_comments_and_strings;

/// Maximum production (non-test) lines a single source file may carry.
const MAX_PROD_LINES: usize = 1500;

/// Existing oversized files. Each ceiling is pinned to the honest count when
/// the gate was repaired: a file may shrink, but may not grow, and its entry
/// must disappear once the ordinary limit is met.
const GRANDFATHERED: &[(&str, usize)] = &[
    ("crates/mvm-agentd/src/guest_mount.rs", 1620),
    ("crates/mvm-build/src/bin/mvm-host-vm-init.rs", 3637),
    ("crates/mvm-build/src/libkrun_builder.rs", 4485),
    ("crates/mvm-cli/src/commands/machine/mod.rs", 1745),
    ("crates/mvm-cli/src/commands/ops/audit.rs", 1649),
    ("crates/mvm-cli/src/commands/vm/exec.rs", 1654),
    ("crates/mvm-hostd/src/audit/emitter.rs", 1515),
    ("crates/mvm-hostd/src/plan_admission.rs", 2256),
    (
        "crates/mvm-hostd/src/supervisor/network_endpoint_proxy.rs",
        2422,
    ),
    ("crates/mvm-runtime/src/backends/hvf/kernel_boot.rs", 2208),
];

#[derive(Debug)]
struct SourceAnalysis {
    production_lines: usize,
    external_modules: Vec<ExternalModule>,
}

#[derive(Debug)]
struct ExternalModule {
    name: String,
    test_only: bool,
}

pub fn run(workspace: &Path) -> Result<()> {
    let mut files = Vec::new();
    for root in ["crates", "src", "xtask"] {
        collect_rs_files(&workspace.join(root), &mut files)?;
    }
    let build_rs = workspace.join("build.rs");
    if build_rs.is_file() {
        files.push(build_rs);
    }
    files.sort();

    let analyses = files
        .iter()
        .map(|file| {
            let src = std::fs::read_to_string(file)?;
            Ok((file.clone(), analyze_source(&src)))
        })
        .collect::<Result<HashMap<_, _>>>()?;
    let test_only_modules = test_only_external_modules(&analyses);

    let mut violations = Vec::new();
    let mut stale_grandfather_entries = Vec::new();
    let mut grandfathered = 0usize;
    for file in &files {
        let rel = file
            .strip_prefix(workspace)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        if is_exempt(&rel) || test_only_modules.contains(file) {
            continue;
        }
        let prod = analyses
            .get(file)
            .map(|analysis| analysis.production_lines)
            .unwrap_or_default();
        let allowance = GRANDFATHERED
            .iter()
            .find_map(|(path, limit)| (*path == rel).then_some(*limit));
        if prod > MAX_PROD_LINES {
            match allowance {
                Some(limit) if prod <= limit => grandfathered += 1,
                Some(limit) => violations.push(format!(
                    "  {prod:>5}  {rel} (grew past grandfathered ceiling {limit})"
                )),
                None => violations.push(format!("  {prod:>5}  {rel}")),
            }
        } else if allowance.is_some() {
            stale_grandfather_entries.push(rel);
        }
    }

    if !violations.is_empty() {
        violations.sort();
        bail!(
            "check-file-size: {} file(s) exceed {MAX_PROD_LINES} production lines \
             without a current shrinking allowance. Decompose the production body \
             into a module tree and move each inline test with the code it exercises:\n{}",
            violations.len(),
            violations.join("\n")
        );
    }
    if !stale_grandfather_entries.is_empty() {
        stale_grandfather_entries.sort();
        bail!(
            "check-file-size: remove {} stale grandfather entry/entries now at or below \
             {MAX_PROD_LINES} production lines:\n  {}",
            stale_grandfather_entries.len(),
            stale_grandfather_entries.join("\n  ")
        );
    }

    println!(
        "check-file-size: clean ({} files scanned; all new files \
         <= {MAX_PROD_LINES} production lines; {grandfathered} shrinking exception(s))",
        files.len(),
    );
    Ok(())
}

/// Files that are entirely test/fixture/generated code and carry no production
/// body of their own.
fn is_exempt(rel: &str) -> bool {
    rel.contains("/tests/")
        || rel.contains("/fuzz/")
        || rel.contains("/benches/")
        || rel.contains("/examples/")
        || rel.ends_with("/tests.rs")
        || rel.ends_with("_test.rs")
        || rel.ends_with("_tests.rs")
}

#[cfg(test)]
fn production_lines(src: &str) -> usize {
    analyze_source(src).production_lines
}

fn analyze_source(src: &str) -> SourceAnalysis {
    let syntax = blank_comments_and_strings(src);
    let chars = syntax.chars().collect::<Vec<_>>();
    let test_spans = test_item_spans(&chars);
    SourceAnalysis {
        production_lines: count_production_lines(&chars, &test_spans),
        external_modules: external_modules(&chars, &test_spans),
    }
}

fn test_item_spans(chars: &[char]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut cursor = 0usize;
    while cursor < chars.len() {
        let Some(first) = parse_attribute(chars, cursor) else {
            cursor += 1;
            continue;
        };

        let group_start = cursor;
        let mut group_end = first.end;
        let mut test_only = attribute_is_test_only(chars, &first);
        let mut inner_test_only = first.inner && test_only;
        loop {
            let next = skip_whitespace(chars, group_end);
            let Some(attribute) = parse_attribute(chars, next) else {
                group_end = next;
                break;
            };
            let attribute_test_only = attribute_is_test_only(chars, &attribute);
            test_only |= attribute_test_only;
            inner_test_only |= attribute.inner && attribute_test_only;
            group_end = attribute.end;
        }

        if inner_test_only {
            spans.push((group_start, chars.len()));
            break;
        }
        if test_only {
            let item_end = find_item_end(chars, group_end);
            spans.push((group_start, item_end));
            cursor = item_end.max(group_end);
        } else {
            cursor = group_end.max(cursor + 1);
        }
    }
    spans
}

struct Attribute {
    inner: bool,
    content_start: usize,
    content_end: usize,
    end: usize,
}

fn parse_attribute(chars: &[char], start: usize) -> Option<Attribute> {
    if chars.get(start) != Some(&'#') {
        return None;
    }
    let mut cursor = start + 1;
    let inner = chars.get(cursor) == Some(&'!');
    if inner {
        cursor += 1;
    }
    if chars.get(cursor) != Some(&'[') {
        return None;
    }
    let content_start = cursor + 1;
    let mut depth = 1usize;
    cursor += 1;
    while cursor < chars.len() {
        match chars[cursor] {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(Attribute {
                        inner,
                        content_start,
                        content_end: cursor,
                        end: cursor + 1,
                    });
                }
            }
            _ => {}
        }
        cursor += 1;
    }
    None
}

fn attribute_is_test_only(chars: &[char], attribute: &Attribute) -> bool {
    let content = &chars[attribute.content_start..attribute.content_end];
    let mut cursor = TokenCursor::new(content);
    let Some(name) = cursor.identifier() else {
        return false;
    };
    if name == "test" {
        return cursor.only_whitespace_remains();
    }
    name == "cfg" && cursor.take('(') && cfg_expression_requires_test(&mut cursor)
}

struct TokenCursor<'a> {
    chars: &'a [char],
    position: usize,
}

impl<'a> TokenCursor<'a> {
    fn new(chars: &'a [char]) -> Self {
        Self { chars, position: 0 }
    }

    fn skip_whitespace(&mut self) {
        self.position = skip_whitespace(self.chars, self.position);
    }

    fn identifier(&mut self) -> Option<String> {
        self.skip_whitespace();
        let start = self.position;
        while self
            .chars
            .get(self.position)
            .is_some_and(|ch| ch.is_alphanumeric() || *ch == '_')
        {
            self.position += 1;
        }
        (self.position > start).then(|| self.chars[start..self.position].iter().collect())
    }

    fn take(&mut self, expected: char) -> bool {
        self.skip_whitespace();
        if self.chars.get(self.position) == Some(&expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn only_whitespace_remains(&mut self) -> bool {
        self.skip_whitespace();
        self.position == self.chars.len()
    }

    fn skip_argument_value(&mut self) {
        while self
            .chars
            .get(self.position)
            .is_some_and(|ch| !matches!(ch, ',' | ')'))
        {
            self.position += 1;
        }
    }
}

fn cfg_expression_requires_test(cursor: &mut TokenCursor<'_>) -> bool {
    let Some(name) = cursor.identifier() else {
        return false;
    };
    if !cursor.take('(') {
        cursor.skip_argument_value();
        return name == "test";
    }

    let mut arguments = Vec::new();
    loop {
        cursor.skip_whitespace();
        if cursor.take(')') {
            break;
        }
        arguments.push(cfg_expression_requires_test(cursor));
        cursor.skip_whitespace();
        if cursor.take(')') {
            break;
        }
        if !cursor.take(',') {
            return false;
        }
    }

    match name.as_str() {
        "all" => arguments.into_iter().any(|requires_test| requires_test),
        "any" => !arguments.is_empty() && arguments.into_iter().all(|requires_test| requires_test),
        _ => false,
    }
}

fn skip_whitespace(chars: &[char], mut cursor: usize) -> usize {
    while chars.get(cursor).is_some_and(|ch| ch.is_whitespace()) {
        cursor += 1;
    }
    cursor
}

fn find_item_end(chars: &[char], start: usize) -> usize {
    let mut cursor = skip_whitespace(chars, start);
    let mut parentheses = 0usize;
    let mut brackets = 0usize;
    while cursor < chars.len() {
        match chars[cursor] {
            '(' => parentheses += 1,
            ')' => parentheses = parentheses.saturating_sub(1),
            '[' => brackets += 1,
            ']' => brackets = brackets.saturating_sub(1),
            ';' if parentheses == 0 && brackets == 0 => return cursor + 1,
            '{' if parentheses == 0 && brackets == 0 => {
                let end = matching_brace_end(chars, cursor);
                let after = skip_whitespace(chars, end);
                return if chars.get(after) == Some(&';') {
                    after + 1
                } else {
                    end
                };
            }
            _ => {}
        }
        cursor += 1;
    }
    chars.len()
}

fn matching_brace_end(chars: &[char], start: usize) -> usize {
    let mut depth = 0usize;
    for (offset, ch) in chars[start..].iter().enumerate() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return start + offset + 1;
                }
            }
            _ => {}
        }
    }
    chars.len()
}

fn count_production_lines(chars: &[char], spans: &[(usize, usize)]) -> usize {
    if chars.is_empty() {
        return 0;
    }
    let mut masked = vec![false; chars.len()];
    for &(start, end) in spans {
        for item in &mut masked[start..end.min(chars.len())] {
            *item = true;
        }
    }

    let mut line_ends = chars
        .iter()
        .enumerate()
        .filter_map(|(index, ch)| (*ch == '\n').then_some(index))
        .collect::<Vec<_>>();
    if chars.last() != Some(&'\n') {
        line_ends.push(chars.len());
    }

    let mut count = 0usize;
    let mut line_start = 0usize;
    for line_end in line_ends {
        // A genuinely blank line (no characters between this newline and the
        // last one) has an empty `line_start..line_end` slice, so it can't
        // tell the blank line apart from a truly unmasked one that way — the
        // slice is empty either way. Its own newline character carries the
        // real answer instead: `analyze_source` masks every character of a
        // test span, including interior blank lines' newlines, so folding
        // that one character in (when the file has one to fold in) recovers
        // whether the blank line sits inside a test span or a production one.
        let mask_check_end = line_end.saturating_add(1).min(chars.len());
        let has_masked = masked[line_start..mask_check_end]
            .iter()
            .any(|value| *value);
        let has_unmasked_syntax = chars[line_start..line_end]
            .iter()
            .zip(&masked[line_start..line_end])
            .any(|(ch, is_masked)| !is_masked && !ch.is_whitespace());
        if !has_masked || has_unmasked_syntax {
            count += 1;
        }
        line_start = line_end.saturating_add(1);
    }
    count
}

fn external_modules(chars: &[char], test_spans: &[(usize, usize)]) -> Vec<ExternalModule> {
    let mut modules = Vec::new();
    let mut cursor = 0usize;
    while cursor < chars.len() {
        if !keyword_at(chars, cursor, "mod") {
            cursor += 1;
            continue;
        }
        let mut after = skip_whitespace(chars, cursor + 3);
        let name_start = after;
        while chars
            .get(after)
            .is_some_and(|ch| ch.is_alphanumeric() || *ch == '_')
        {
            after += 1;
        }
        if after > name_start && chars.get(skip_whitespace(chars, after)) == Some(&';') {
            modules.push(ExternalModule {
                name: chars[name_start..after].iter().collect(),
                test_only: test_spans
                    .iter()
                    .any(|(start, end)| cursor >= *start && cursor < *end),
            });
        }
        cursor = after.max(cursor + 1);
    }
    modules
}

fn keyword_at(chars: &[char], start: usize, keyword: &str) -> bool {
    let keyword_chars = keyword.chars().collect::<Vec<_>>();
    chars.get(start..start + keyword_chars.len()) == Some(keyword_chars.as_slice())
        && start
            .checked_sub(1)
            .and_then(|before| chars.get(before))
            .is_none_or(|ch| !ch.is_alphanumeric() && *ch != '_')
        && chars
            .get(start + keyword_chars.len())
            .is_none_or(|ch| !ch.is_alphanumeric() && *ch != '_')
}

fn test_only_external_modules(analyses: &HashMap<PathBuf, SourceAnalysis>) -> HashSet<PathBuf> {
    let mut test_only = HashSet::new();
    let mut queue = VecDeque::new();
    for (parent, analysis) in analyses {
        for module in analysis
            .external_modules
            .iter()
            .filter(|module| module.test_only)
        {
            if let Some(path) = resolve_external_module(parent, &module.name, analyses)
                && test_only.insert(path.clone())
            {
                queue.push_back(path);
            }
        }
    }

    while let Some(parent) = queue.pop_front() {
        let Some(analysis) = analyses.get(&parent) else {
            continue;
        };
        for module in &analysis.external_modules {
            if let Some(path) = resolve_external_module(&parent, &module.name, analyses)
                && test_only.insert(path.clone())
            {
                queue.push_back(path);
            }
        }
    }
    test_only
}

fn resolve_external_module(
    parent: &Path,
    name: &str,
    analyses: &HashMap<PathBuf, SourceAnalysis>,
) -> Option<PathBuf> {
    let file_name = parent.file_name()?.to_str()?;
    let parent_dir = parent.parent()?;
    let module_dir = if matches!(file_name, "lib.rs" | "main.rs" | "mod.rs" | "build.rs") {
        parent_dir.to_path_buf()
    } else {
        parent_dir.join(parent.file_stem()?)
    };
    [
        module_dir.join(format!("{name}.rs")),
        module_dir.join(name).join("mod.rs"),
    ]
    .into_iter()
    .find(|candidate| analyses.contains_key(candidate))
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        for (rel_path, content) in files {
            let full = dir.path().join(rel_path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(&full, content).unwrap();
        }
        dir
    }

    fn body(prod: usize, tests: usize) -> String {
        let mut s = "// header\n".repeat(prod);
        s.push_str("#[cfg(test)]\nmod tests {\n");
        s.push_str(&"    // t\n".repeat(tests));
        s.push_str("}\n");
        s
    }

    #[test]
    fn oversized_production_body_fails() {
        let tree = make_tree(&[("crates/x/src/big.rs", &body(1600, 10))]);
        let err = run(tree.path()).expect_err("1600 production lines must fail");
        assert!(err.to_string().contains("big.rs"), "{err}");
    }

    #[test]
    fn test_heavy_small_production_passes() {
        // 200 production lines, 6000 lines of trailing tests — must pass.
        let tree = make_tree(&[("crates/x/src/probe.rs", &body(200, 6000))]);
        run(tree.path()).expect("small production body must pass regardless of test size");
    }

    #[test]
    fn dedicated_test_file_is_exempt() {
        // A `tests.rs` that is all code (no #[cfg(test)] inside) must not count.
        let tree = make_tree(&[("crates/x/src/tests.rs", &"let _ = 1;\n".repeat(2000))]);
        run(tree.path()).expect("tests.rs is exempt by name");
    }

    #[test]
    fn production_line_count_stops_at_first_cfg_test() {
        assert_eq!(production_lines("a\nb\n#[cfg(test)]\nmod t { x }\n"), 2);
        assert_eq!(production_lines("a\nb\nc\n"), 3);
        assert_eq!(production_lines("    #[cfg(test)]\nmod t {}\n"), 0);
    }

    #[test]
    fn production_after_an_inline_test_module_still_counts() {
        let src = "fn before() {}\n#[cfg(test)]\nmod tests { fn probe() {} }\nfn after() {}\n";
        assert_eq!(production_lines(src), 2);
    }

    #[test]
    fn multiline_cfg_all_test_item_does_not_count() {
        let src = "fn production() {}\n#[cfg(all(\n    test,\n    feature = \"probe\"\n))]\nfn probe() {\n    assert!(true);\n}\n";
        assert_eq!(production_lines(src), 1);
    }

    #[test]
    fn bare_test_function_does_not_count() {
        let src = "fn production() {}\n#[test]\nfn probe() {\n    assert!(true);\n}\n";
        assert_eq!(production_lines(src), 1);
    }

    #[test]
    fn cfg_any_test_or_feature_still_counts_as_production() {
        let src = "#[cfg(any(test, feature = \"probe\"))]\nfn available_in_production() {}\n";
        assert_eq!(production_lines(src), 2);
    }

    #[test]
    fn raw_string_braces_do_not_end_a_test_item_early() {
        let src = r###"fn before() {}
#[cfg(test)]
mod tests {
    const FIXTURE: &str = r#"{ \"nested\": { \"value\": true } }"#;
    fn probe() {}
}
fn after() {}
"###;
        assert_eq!(production_lines(src), 2);
    }

    #[test]
    fn blank_line_inside_inline_test_module_does_not_count() {
        let src = "fn before() {}\n#[cfg(test)]\nmod tests {\n    fn probe() {}\n}\n";
        let before = production_lines(src);

        let src_with_new_test = "fn before() {}\n#[cfg(test)]\nmod tests {\n    fn probe() {}\n\n    #[test]\n    fn added() {}\n}\n";
        let after = production_lines(src_with_new_test);

        assert_eq!(
            before, after,
            "adding a test function (with surrounding blank lines) inside an \
             existing inline test module must not change the production count"
        );
    }

    #[test]
    fn parent_gated_external_test_module_is_exempt() {
        let child = "fn helper() {}\n".repeat(1600);
        let tree = make_tree(&[
            ("crates/x/src/lib.rs", "#[cfg(test)]\nmod support;\n"),
            ("crates/x/src/support.rs", &child),
        ]);
        run(tree.path()).expect("a module gated at its declaration site is test-only");
    }

    #[test]
    fn descendants_of_a_parent_gated_module_are_exempt() {
        let nested = "fn helper() {}\n".repeat(1600);
        let tree = make_tree(&[
            ("crates/x/src/lib.rs", "#[cfg(test)]\nmod support;\n"),
            ("crates/x/src/support.rs", "mod nested;\n"),
            ("crates/x/src/support/nested.rs", &nested),
        ]);
        run(tree.path()).expect("test-only module descendants are also test-only");
    }

    #[test]
    fn grandfathered_file_cannot_grow() {
        let grown = "fn production() {}\n".repeat(1516);
        let tree = make_tree(&[("crates/mvm-hostd/src/audit/emitter.rs", &grown)]);
        let err = run(tree.path()).expect_err("a grandfathered file may not grow");
        assert!(err.to_string().contains("grew past"), "{err}");
    }

    #[test]
    fn grandfathered_file_must_leave_the_list_at_the_ordinary_limit() {
        let shrunk = "fn production() {}\n".repeat(MAX_PROD_LINES);
        let tree = make_tree(&[("crates/mvm-hostd/src/audit/emitter.rs", &shrunk)]);
        let err = run(tree.path()).expect_err("a stale grandfather entry must fail");
        assert!(err.to_string().contains("stale grandfather"), "{err}");
    }

    #[test]
    fn grandfathered_file_at_its_ceiling_passes() {
        let pinned = "fn production() {}\n".repeat(1515);
        let tree = make_tree(&[("crates/mvm-hostd/src/audit/emitter.rs", &pinned)]);
        run(tree.path()).expect("the pinned baseline itself remains admitted");
    }

    #[test]
    fn root_source_and_xtask_source_are_scanned() {
        let oversized = "fn production() {}\n".repeat(1600);
        for path in ["src/big.rs", "xtask/src/big.rs", "build.rs"] {
            let tree = make_tree(&[(path, &oversized)]);
            let err = run(tree.path()).expect_err("every production source root is gated");
            assert!(err.to_string().contains(path), "{path}: {err}");
        }
    }
}
