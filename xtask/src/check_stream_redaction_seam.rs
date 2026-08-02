//! `xtask check-stream-redaction-seam`
//!
//! One redaction seam, and no way to build a broker that skips it. Every byte
//! a workload writes crosses `StreamRedaction` exactly once, before it is
//! hashed, persisted, or handed to a follower — so a broker constructed over a
//! seam that redacts nothing is a silent leak of the whole output stream.
//!
//! The type system does most of the work: `StreamRedaction` wraps a private
//! `Box<dyn StreamRedactor>`, and its only non-test constructor installs the
//! curated ruleset. This gate is that arrangement in executable form, for the
//! edits the compiler would happily accept — a second public constructor, a
//! `#[cfg(test)]` quietly dropped, a `Box<dyn StreamRedactor>` door reopened on
//! the broker, or a call site handing the broker something other than the
//! curated seam.
//!
//! Three assertions:
//!
//! - **A — the seam is unforgeable.** `redact.rs` keeps `StreamRedaction` a
//!   newtype over a private `Box<dyn StreamRedactor>`; `curated` still names
//!   `PiiRedactor::with_default_rules` (it reads the workload's redaction
//!   policy, and that is the floor it falls back to — never an empty ruleset);
//!   and every *other* fn returning `Self` or `StreamRedaction` — in any impl
//!   block for the type, or as a free function in the module — is
//!   `#[cfg(test)]`-gated.
//! - **B — the broker has one door.** `StreamBroker::new` takes a
//!   `StreamRedaction`, and `broker.rs` grows no constructor accepting a bare
//!   `Box<dyn StreamRedactor>` or a raw `PiiRedactor`.
//! - **C — every construction site uses the curated seam.** Outside the
//!   `stream` module that owns the type, a `StreamBroker::new(...)` must pass
//!   `StreamRedaction::curated(...)`, and `from_seam` must not appear at all.
//!
//! Scope — assertion C has nothing to scan until the console source and the
//! log follower attach their brokers; it reports the count so a zero is
//! visible rather than implied. A and B hold from today.

use anyhow::{Result, bail};
use regex::Regex;
use std::path::{Path, PathBuf};

/// Where the seam type lives — the file assertion A reads.
const REDACT_RS: &str = "crates/mvm-hostd/src/stream/redact.rs";

/// The broker whose one door assertion B reads.
const BROKER_RS: &str = "crates/mvm-hostd/src/stream/broker.rs";

/// The module that owns `StreamRedaction`, and the only place its test-only
/// constructor is reachable. Assertion C scans everything else.
const SEAM_MODULE: &str = "crates/mvm-hostd/src/stream";

/// The newtype declaration assertion A requires, verbatim. A tuple field with
/// no `pub` is what makes the type unforgeable from outside the module.
const SEAM_DECL: &str = "pub struct StreamRedaction(Box<dyn StreamRedactor>);";

/// The one production constructor, in prose for the failure message. Its
/// signature carries the workload's redaction policy; what the gate matches is
/// [`curated_fn`].
const CURATED_FN: &str = "pub fn curated(…) -> Self";

/// What `curated()` must install — as the ruleset outright, or as the fallback
/// when a policy resolves to nothing. An empty ruleset satisfies the trait
/// exactly as well, which is the whole reason this gate exists.
const CURATED_RULESET: &str = "PiiRedactor::with_default_rules";

/// Constructor shapes on the broker that would reopen the bypass.
const FORBIDDEN_BROKER_PARAMS: &[&str] = &["Box<dyn StreamRedactor>", "redactor: PiiRedactor"];

/// How many lines after a `StreamBroker::new(` a rustfmt-wrapped argument list
/// may run before assertion C stops looking for the curated seam.
const CALL_WINDOW_LINES: usize = 5;

pub fn run(workspace: &Path) -> Result<()> {
    check_seam_is_unforgeable(workspace)?;
    check_broker_has_one_door(workspace)?;
    let sites = check_call_sites_use_curated(workspace)?;
    eprintln!(
        "check-stream-redaction-seam: clean (StreamRedaction is newtype-sealed over the curated \
         ruleset, StreamBroker takes no bare redactor, {sites} construction site(s) outside the \
         stream module use StreamRedaction::curated(...))"
    );
    Ok(())
}

/// Assertion A — the seam type cannot be built from a no-op redactor.
fn check_seam_is_unforgeable(workspace: &Path) -> Result<()> {
    let text = read_required(workspace, REDACT_RS)?;

    if !text.contains(SEAM_DECL) {
        bail!(
            "check-stream-redaction-seam: {REDACT_RS} no longer declares the sealed seam.\n    \
             Expected exactly: `{SEAM_DECL}`\n    A public field, or a plain `Box<dyn \
             StreamRedactor>` in its place, lets a caller build a broker that redacts nothing."
        );
    }

    let Some(body) = impl_block(&text, "impl StreamRedaction {") else {
        bail!("check-stream-redaction-seam: {REDACT_RS} has no `impl StreamRedaction` block");
    };
    if !curated_fn().is_match(body) {
        bail!(
            "check-stream-redaction-seam: `{CURATED_FN}` is gone from {REDACT_RS}. It is the one \
             production constructor; without it every caller needs a different door."
        );
    }
    if !body.contains(CURATED_RULESET) {
        bail!(
            "check-stream-redaction-seam: `curated()` no longer installs \
             `{CURATED_RULESET}`. An empty ruleset satisfies StreamRedactor exactly as well as \
             the real one and redacts nothing."
        );
    }

    let ungated = ungated_constructors(&text);
    if !ungated.is_empty() {
        bail!(
            "check-stream-redaction-seam: `{}` return a StreamRedaction without a \
             `#[cfg(test)]` above them. `curated` must stay the only constructor a production \
             build can reach, or the sealed newtype buys nothing.",
            ungated.join("`, `")
        );
    }
    Ok(())
}

/// Assertion B — the broker accepts the seam type and nothing looser.
fn check_broker_has_one_door(workspace: &Path) -> Result<()> {
    let text = read_required(workspace, BROKER_RS)?;
    if !new_takes_seam().is_match(&text) {
        bail!(
            "check-stream-redaction-seam: `StreamBroker::new` no longer takes a \
             `StreamRedaction`. The constructor parameter is what forces every broker through \
             the curated seam."
        );
    }
    for (n, line) in code_lines(&text) {
        for shape in FORBIDDEN_BROKER_PARAMS {
            if line.contains(shape) {
                bail!(
                    "check-stream-redaction-seam: {BROKER_RS}:{n}: `{shape}` reopens the \
                     redactor bypass — a broker built this way can be handed a seam that \
                     redacts nothing. Take a `StreamRedaction` instead.\n    {}",
                    line.trim()
                );
            }
        }
    }
    Ok(())
}

/// Assertion C — every construction site outside the owning module passes the
/// curated seam. Returns how many sites were checked.
fn check_call_sites_use_curated(workspace: &Path) -> Result<usize> {
    let mut sites = 0usize;
    let mut hits = Vec::new();
    for file in workspace_rs_files(workspace)? {
        if file.starts_with(workspace.join(SEAM_MODULE)) {
            continue;
        }
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        for (n, line) in code_lines(&text) {
            if line.contains("StreamRedaction::from_seam") {
                hits.push(format!(
                    "{}:{n}: `StreamRedaction::from_seam` is the test-only door and belongs \
                     inside {SEAM_MODULE}",
                    rel(workspace, &file)
                ));
                continue;
            }
            if !line.contains("StreamBroker::new(") {
                continue;
            }
            sites += 1;
            let window = lines[n - 1..lines.len().min(n - 1 + CALL_WINDOW_LINES)].join("\n");
            if !window.contains("StreamRedaction::curated(") {
                hits.push(format!(
                    "{}:{n}: builds a StreamBroker without `StreamRedaction::curated(...)`",
                    rel(workspace, &file)
                ));
            }
        }
    }
    if !hits.is_empty() {
        bail!(
            "check-stream-redaction-seam: a broker is built outside the curated redaction \
             seam. Every workload byte crosses that seam exactly once; a broker built any \
             other way ships unredacted output to its followers and its transcript:\n{}",
            hits.join("\n")
        );
    }
    Ok(sites)
}

/// The body of `header`'s impl block, brace-matched so a nested block does not
/// end it early.
fn impl_block<'a>(text: &'a str, header: &str) -> Option<&'a str> {
    let start = text.find(header)? + header.len();
    block_end(text, start).map(|end| &text[start..end])
}

/// Byte offset of the `}` that closes the block whose body starts at
/// `start` — the position right after its opening `{` — brace-matched so a
/// nested block does not end it early.
fn block_end(text: &str, start: usize) -> Option<usize> {
    let mut depth = 1usize;
    for (offset, ch) in text[start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(start + offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// Byte spans of the body of every impl block whose header names
/// `StreamRedaction` — the inherent impl and every trait impl (`Default`,
/// `StreamRedactor`, or any future one). [`impl_block`] only ever finds the
/// one literal header text it is handed, so a constructor hidden behind
/// `impl Default for StreamRedaction` — a different header entirely — would
/// never reach the ungated-constructor scan without this.
fn stream_redaction_impl_spans(text: &str) -> Vec<(usize, usize)> {
    let header = Regex::new(r"impl\b[^{]*\{").expect("static regex");
    header
        .find_iter(text)
        .filter(|m| m.as_str().contains("StreamRedaction"))
        .filter_map(|m| {
            let start = m.end();
            block_end(text, start).map(|end| (start, end))
        })
        .collect()
}

/// Depth of unmatched `{` at byte offset `pos`, by the same naive brace
/// count [`block_end`] uses. Zero means `pos` sits at module scope — not
/// inside any impl, fn body, or other block — which is what tells a free
/// function apart from a method.
fn brace_depth_before(text: &str, pos: usize) -> i32 {
    text[..pos].chars().fold(0i32, |depth, ch| match ch {
        '{' => depth + 1,
        '}' => depth - 1,
        _ => depth,
    })
}

/// Constructors the compiler would accept as producing a `StreamRedaction`:
/// every `fn` inside a `StreamRedaction`-named impl block (inherent or
/// trait) that returns `Self` or `StreamRedaction`, plus every free function
/// at module scope that returns `StreamRedaction` outright — the field is
/// only private *outside* this module, so a free function declared right
/// here can still build one with the tuple-struct literal. Matched against
/// the whole file rather than line by line, so a rustfmt-wrapped signature
/// cannot dodge the scan by splitting `-> Self` onto its own line. Anything
/// found this way other than `curated` must be `#[cfg(test)]`-gated.
fn ungated_constructors(text: &str) -> Vec<String> {
    let signature = Regex::new(r"fn\s+(\w+)\s*\([^)]*\)\s*->\s*(?:Self|StreamRedaction)")
        .expect("static regex");
    let impl_spans = stream_redaction_impl_spans(text);
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for caps in signature.captures_iter(text) {
        let Some(whole) = caps.get(0) else {
            continue;
        };
        let in_seam_impl = impl_spans
            .iter()
            .any(|&(start, end)| whole.start() >= start && whole.start() < end);
        let is_free_fn = brace_depth_before(text, whole.start()) == 0;
        if !in_seam_impl && !is_free_fn {
            // A method on some other type — not a StreamRedaction constructor.
            continue;
        }
        let name = &caps[1];
        if name == "curated" {
            continue;
        }
        let line_index = text[..whole.start()].matches('\n').count();
        if !preceded_by_cfg_test(&lines, line_index) {
            out.push(name.to_string());
        }
    }
    out
}

/// Whether the attributes immediately above `index` include `#[cfg(test)]`.
/// Doc comments and other attributes may sit between it and the signature.
fn preceded_by_cfg_test(lines: &[&str], index: usize) -> bool {
    for line in lines[..index].iter().rev() {
        let trimmed = line.trim();
        if trimmed.contains("#[cfg(test)]") {
            return true;
        }
        if trimmed.is_empty() || trimmed.starts_with("///") || trimmed.starts_with("#[") {
            continue;
        }
        return false;
    }
    false
}

fn new_takes_seam() -> Regex {
    Regex::new(r"pub\s+fn\s+new\s*\([^)]*:\s*StreamRedaction").expect("static regex")
}

/// The production constructor's signature, whatever it takes. Matching the
/// shape rather than one literal string keeps the gate from breaking every
/// time the seam learns about another input, while still failing if `curated`
/// stops returning the sealed type — or disappears.
fn curated_fn() -> Regex {
    Regex::new(r"pub\s+fn\s+curated\s*\([^)]*\)\s*->\s*(?:Self|StreamRedaction)")
        .expect("static regex")
}

/// Non-comment code lines as (1-based line number, line). Prose explaining the
/// invariant legitimately names the shapes the gate forbids.
fn code_lines(text: &str) -> Vec<(usize, &str)> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let trimmed = line.trim_start();
            !(trimmed.starts_with("//") || trimmed.starts_with('*'))
        })
        .map(|(i, line)| (i + 1, line))
        .collect()
}

fn read_required(workspace: &Path, rel_path: &str) -> Result<String> {
    std::fs::read_to_string(workspace.join(rel_path)).map_err(|err| {
        anyhow::anyhow!(
            "check-stream-redaction-seam: cannot read {rel_path} — the single redaction seam \
             must exist ({err})"
        )
    })
}

fn rel(workspace: &Path, file: &Path) -> String {
    file.strip_prefix(workspace)
        .unwrap_or(file)
        .display()
        .to_string()
}

/// Every `.rs` file that could construct a broker: the workspace crates and
/// the root facade. `xtask/` is out of scope — it does not depend on
/// `mvm-hostd`, so it cannot build a broker, and scanning it would only make
/// this gate flag its own fixtures.
fn workspace_rs_files(workspace: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for root in ["crates", "src"] {
        collect_rs_files(&workspace.join(root), &mut out)?;
    }
    Ok(out)
}

fn collect_rs_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !path.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(path)?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
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

    fn workspace_root() -> PathBuf {
        // xtask/src/check_stream_redaction_seam.rs → workspace root is two up.
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask has a parent")
            .to_path_buf()
    }

    fn write(root: &Path, rel_path: &str, body: &str) {
        let path = root.join(rel_path);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dirs");
        std::fs::write(path, body).expect("write fixture");
    }

    const GOOD_REDACT: &str = "\
pub struct StreamRedaction(Box<dyn StreamRedactor>);

impl StreamRedaction {
    pub fn curated(policy: &RedactionPolicy) -> Self {
        Self(Box::new(PiiRedactor::from_policy(&policy.default.pii).ok().flatten()
            .unwrap_or_else(PiiRedactor::with_default_rules)))
    }

    #[cfg(test)]
    pub(in crate::stream) fn from_seam(seam: Box<dyn StreamRedactor>) -> Self {
        Self(seam)
    }
}
";

    const GOOD_BROKER: &str = "\
impl StreamBroker {
    pub fn new(vm: &str, writer: TranscriptWriter, redaction: StreamRedaction) -> Self {
        Self { vm: vm.to_string(), writer, redaction }
    }
}
";

    #[test]
    fn current_tree_passes() {
        run(&workspace_root()).expect("the redaction-seam gate must pass on the current tree");
    }

    #[test]
    fn a_second_ungated_constructor_fails() {
        let root = tempfile::tempdir().expect("tempdir");
        write(
            root.path(),
            REDACT_RS,
            &GOOD_REDACT.replace("    #[cfg(test)]\n", ""),
        );
        let err = check_seam_is_unforgeable(root.path())
            .expect_err("an ungated second constructor must fail the gate");
        assert!(err.to_string().contains("from_seam"), "got {err}");
    }

    #[test]
    fn a_curated_built_from_an_empty_ruleset_fails() {
        let root = tempfile::tempdir().expect("tempdir");
        write(
            root.path(),
            REDACT_RS,
            &GOOD_REDACT.replace(
                "PiiRedactor::with_default_rules()",
                "PiiRedactor::new(&[], Mode::Detect).expect(\"empty\")",
            ),
        );
        let err = check_seam_is_unforgeable(root.path())
            .expect_err("a no-op curated ruleset must fail the gate");
        assert!(err.to_string().contains("with_default_rules"), "got {err}");
    }

    #[test]
    fn an_unwrapped_seam_field_fails() {
        let root = tempfile::tempdir().expect("tempdir");
        write(
            root.path(),
            REDACT_RS,
            &GOOD_REDACT.replace(
                "pub struct StreamRedaction(Box<dyn StreamRedactor>);",
                "pub struct StreamRedaction(pub Box<dyn StreamRedactor>);",
            ),
        );
        let err = check_seam_is_unforgeable(root.path())
            .expect_err("a public seam field must fail the gate");
        assert!(err.to_string().contains("sealed seam"), "got {err}");
    }

    #[test]
    fn a_default_impl_constructor_fails() {
        // A trait impl is a different header than `impl StreamRedaction {`
        // entirely — the exact bypass the scan was widened to cover.
        let root = tempfile::tempdir().expect("tempdir");
        let text = format!(
            "{GOOD_REDACT}\nimpl Default for StreamRedaction {{\n    fn default() -> Self {{ \
             todo!() }}\n}}\n"
        );
        write(root.path(), REDACT_RS, &text);
        let err = check_seam_is_unforgeable(root.path())
            .expect_err("a constructor hidden behind `impl Default` must fail the gate");
        assert!(err.to_string().contains("default"), "got {err}");
    }

    const WRAPPED_SIGNATURE_REDACT: &str = "\
pub struct StreamRedaction(Box<dyn StreamRedactor>);

impl StreamRedaction {
    pub fn curated(policy: &RedactionPolicy) -> Self {
        Self(Box::new(PiiRedactor::from_policy(&policy.default.pii).ok().flatten()
            .unwrap_or_else(PiiRedactor::with_default_rules)))
    }

    pub fn with_redactor(
        seam: Box<dyn StreamRedactor>,
    ) -> Self {
        Self(seam)
    }

    #[cfg(test)]
    pub(in crate::stream) fn from_seam(seam: Box<dyn StreamRedactor>) -> Self {
        Self(seam)
    }
}
";

    #[test]
    fn a_rustfmt_wrapped_constructor_without_cfg_test_fails() {
        // Per-line matching would miss this: no single line contains the
        // whole `fn ... -> Self`. The gate must read the joined body.
        let root = tempfile::tempdir().expect("tempdir");
        write(root.path(), REDACT_RS, WRAPPED_SIGNATURE_REDACT);
        let err = check_seam_is_unforgeable(root.path())
            .expect_err("a rustfmt-wrapped constructor must not dodge the scan");
        assert!(err.to_string().contains("with_redactor"), "got {err}");
    }

    #[test]
    fn a_constructor_returning_the_bare_type_name_fails() {
        // `-> StreamRedaction` builds the type exactly as well as `-> Self`.
        let root = tempfile::tempdir().expect("tempdir");
        let text = GOOD_REDACT.replace(
            "impl StreamRedaction {",
            "impl StreamRedaction {\n    pub fn insecure() -> StreamRedaction { todo!() }\n",
        );
        write(root.path(), REDACT_RS, &text);
        let err = check_seam_is_unforgeable(root.path())
            .expect_err("a constructor spelled `-> StreamRedaction` must still be caught");
        assert!(err.to_string().contains("insecure"), "got {err}");
    }

    #[test]
    fn a_free_function_constructor_fails() {
        // The field is only private outside this module — a free function
        // declared right here can still build one with the tuple literal.
        let root = tempfile::tempdir().expect("tempdir");
        let text =
            format!("{GOOD_REDACT}\npub fn insecure_seam() -> StreamRedaction {{ todo!() }}\n");
        write(root.path(), REDACT_RS, &text);
        let err = check_seam_is_unforgeable(root.path())
            .expect_err("a free-function constructor outside any impl block must fail the gate");
        assert!(err.to_string().contains("insecure_seam"), "got {err}");
    }

    #[test]
    fn a_broker_constructor_taking_a_bare_redactor_fails() {
        let root = tempfile::tempdir().expect("tempdir");
        write(
            root.path(),
            BROKER_RS,
            &format!(
                "{GOOD_BROKER}\nimpl StreamBroker {{\n    pub fn with_redactor(vm: &str, \
                 redactor: Box<dyn StreamRedactor>) -> Self {{ todo!() }}\n}}\n"
            ),
        );
        let err = check_broker_has_one_door(root.path())
            .expect_err("a second bare-redactor door must fail the gate");
        assert!(
            err.to_string().contains("Box<dyn StreamRedactor>"),
            "got {err}"
        );
    }

    #[test]
    fn a_construction_site_without_the_curated_seam_fails() {
        let root = tempfile::tempdir().expect("tempdir");
        write(
            root.path(),
            "crates/mvm-hostd/src/daemon.rs",
            "fn attach(w: TranscriptWriter, seam: StreamRedaction) -> StreamBroker {\n    \
             StreamBroker::new(\"vm\", w, seam)\n}\n",
        );
        let err = check_call_sites_use_curated(root.path())
            .expect_err("a broker built off the curated seam must fail the gate");
        assert!(
            err.to_string().contains("StreamRedaction::curated("),
            "got {err}"
        );
    }

    #[test]
    fn a_wrapped_construction_site_with_the_curated_seam_passes() {
        // rustfmt splits a long call across lines; the gate must read the
        // argument list, not just the line the call name lands on.
        let root = tempfile::tempdir().expect("tempdir");
        write(
            root.path(),
            "crates/mvm-hostd/src/daemon.rs",
            "fn attach(w: TranscriptWriter) -> StreamBroker {\n    StreamBroker::new(\n        \
             vm_name,\n        w,\n        StreamRedaction::curated(&redaction),\n    )\n}\n",
        );
        assert_eq!(
            check_call_sites_use_curated(root.path()).expect("the curated seam passes"),
            1
        );
    }

    #[test]
    fn the_test_only_door_outside_the_stream_module_fails() {
        let root = tempfile::tempdir().expect("tempdir");
        write(
            root.path(),
            "crates/mvm-hostd/src/daemon.rs",
            "fn attach() {\n    let seam = StreamRedaction::from_seam(Box::new(NoOp));\n}\n",
        );
        let err = check_call_sites_use_curated(root.path())
            .expect_err("the test-only door must not escape the stream module");
        assert!(err.to_string().contains("from_seam"), "got {err}");
    }

    #[test]
    fn a_comment_naming_a_forbidden_shape_is_ignored() {
        let root = tempfile::tempdir().expect("tempdir");
        write(
            root.path(),
            BROKER_RS,
            &format!("// never take a Box<dyn StreamRedactor> here\n{GOOD_BROKER}"),
        );
        check_broker_has_one_door(root.path()).expect("a comment-only mention must not trip");
    }
}
