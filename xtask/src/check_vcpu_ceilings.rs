//! `xtask check-vcpu-ceilings`
//!
//! A backend's declared `VmCapabilities::max_vcpus` is the number the clamp
//! above the backends grants an over-large `--cpus` request. It must therefore
//! be a count the VMM will *boot*, and this gate fails a declaration derived
//! from an integer type's `MAX`.
//!
//! That is the exact defect this gate exists for, made twice. Firecracker and
//! libkrun both declared `Some(u32::from(u8::MAX))`, each reasoning that the
//! vCPU count is a byte on the wire — true of both, and the limit of neither.
//! `/machine-config` refuses anything above 32; libkrun's `krun_set_vm_config`
//! accepts all 255 and then aborts inside `krun_start_enter` at 65. So the
//! clamp faithfully produced a count that would not run, and `--cpus 9999`
//! failed on both while succeeding on HVF, whose ceiling is asked of the host.
//!
//! The rule is narrow on purpose: *how* a real ceiling is obtained is the
//! backend's business — a measured constant (`Some(MAX_VCPUS)`) and a host
//! query (`hvf_max_vcpus()`) are both fine, and this gate deliberately does
//! not prefer one. What it refuses is the one derivation that cannot be right,
//! because the width of a field says nothing about what the VMM behind it will
//! accept.
//!
//! What this does **not** reach: an assertion that names the wrong number
//! without declaring it. `mvm-client`'s clamp test read `assert_eq!(...,
//! Some(u32::from(u8::MAX)))`, pinning the defect as the expected behaviour —
//! and that is an `assert_eq!` argument, not a `max_vcpus` declaration, so
//! this gate walks past it. Catching it would mean flagging a wire-type `MAX`
//! anywhere *near* vCPU text, which immediately hits honest uses: the libkrun
//! driver's `u8::try_from(spec.vcpus.clamp(1, MAX_VCPUS)).unwrap_or(u8::MAX)`
//! is an infallible-conversion fallback on an already-clamped value, on a line
//! that says `vcpus`. A gate that cried wolf there would be turned off, so the
//! rule stays narrow and the wrong assertion stays CI's job — which is how
//! that one was in fact caught, by going red the moment the ceiling was fixed.
//!
//! Test code is still scanned, since a *declaration* in a fixture is as
//! binding as one in a driver.
//!
//! Comments and string literals are blanked first via the shared
//! [`crate::rust_source`] scanner — this file's own prose says `u8::MAX`
//! several times, and a scanner that reads comments as code would fail the
//! gate on its own explanation.

use anyhow::{Result, bail};
use std::path::Path;

/// Trees that declare or assert a backend vCPU ceiling.
const SCANNED_DIRS: &[&str] = &[
    "crates/mvm-backends/src",
    "crates/mvm-client/src",
    "crates/mvm-runtime/src",
];

/// The struct field whose value this gate governs.
const FIELD: &str = "max_vcpus";

/// Declarations that must exist. A gate that passes because every ceiling has
/// been deleted has stopped noticing that ceilings used to be declared — the
/// same failure `check-backend-resource-controls` guards with its matrix floor.
/// Two of the three microVM backends declare a constant and one queries the
/// host; this floor keeps at least the constants honest.
const MINIMUM_DECLARATIONS: usize = 2;

pub fn run(workspace: &Path) -> Result<()> {
    let mut findings: Vec<String> = Vec::new();
    let mut declarations = 0usize;

    for dir in SCANNED_DIRS {
        let root = workspace.join(dir);
        if !root.is_dir() {
            bail!("{dir} is not a directory; check-vcpu-ceilings is scanning a stale path");
        }
        for file in rust_files(&root)? {
            let raw = std::fs::read_to_string(&file)
                .map_err(|e| anyhow::anyhow!("reading {}: {e}", file.display()))?;
            let body = crate::rust_source::blank_comments_and_strings(&raw);
            let relative = file
                .strip_prefix(workspace)
                .unwrap_or(&file)
                .display()
                .to_string();

            for (line_no, line) in body.lines().enumerate() {
                let Some(value) = ceiling_value(line) else {
                    continue;
                };
                declarations += 1;
                if let Some(spelling) = wire_type_max(value) {
                    findings.push(format!(
                        "{relative}:{}: `{FIELD}` is derived from `{spelling}` — that is the \
                         width of the wire field, not a count the VMM boots. Declare what the \
                         backend will actually start (a measured constant, or a value queried \
                         from the host/library) so the clamp above the backends grants a \
                         request that runs.",
                        line_no + 1
                    ));
                }
            }
        }
    }

    if !findings.is_empty() {
        bail!(
            "vCPU ceilings derived from a wire type:\n\n{}\n",
            findings.join("\n\n")
        );
    }

    if declarations < MINIMUM_DECLARATIONS {
        bail!(
            "expected at least {MINIMUM_DECLARATIONS} `{FIELD}` declarations across {:?}; \
             found {declarations}. Ceilings that have all disappeared is a question, not a pass.",
            SCANNED_DIRS
        );
    }

    println!(
        "check-vcpu-ceilings: {declarations} ceiling declarations, none derived from a wire type"
    );
    Ok(())
}

/// The value assigned to `max_vcpus:` on this line, if it is an assignment.
///
/// A read (`caps.max_vcpus`) or the field's own declaration in the struct
/// (`pub max_vcpus: Option<u32>`) is not an assignment and is left alone: only
/// the value a backend *declares* is this gate's business. The type-annotation
/// form is told apart by its leading visibility/binding keyword rather than by
/// guessing at the value, so a field renamed or re-typed does not slip past.
fn ceiling_value(line: &str) -> Option<&str> {
    // An assignment starts the line with the field itself. `pub max_vcpus:` is
    // the struct's own declaration and never gets past this, and a read
    // (`caps.max_vcpus`) has the field mid-line rather than at its head.
    let value = line
        .trim()
        .strip_prefix(FIELD)?
        .strip_prefix(':')?
        .trim()
        .trim_end_matches(',');
    // `max_vcpus: Option<u32>` is the struct's own field declaration, and
    // `max_vcpus: u32` its display mirror — neither declares a ceiling.
    if value.starts_with("Option<") || value.starts_with("u32") || value.is_empty() {
        return None;
    }
    Some(value)
}

/// The integer-type `MAX` this expression is built from, if any.
///
/// Matches any width and both signednesses rather than `u8::MAX` alone: the
/// reasoning that produced the bug — "the field is N bits wide, so its ceiling
/// is what N bits hold" — is not specific to a byte, and a future backend
/// whose count travels as a `u16` would repeat it verbatim.
fn wire_type_max(value: &str) -> Option<String> {
    let bytes: Vec<char> = value.chars().collect();
    for (i, _) in bytes.iter().enumerate() {
        if !bytes[i..].starts_with(&[':', ':', 'M', 'A', 'X']) {
            continue;
        }
        // Walk back over the digits and the leading `u`/`i` of the type name.
        let mut start = i;
        while start > 0 && bytes[start - 1].is_ascii_digit() {
            start -= 1;
        }
        if start == i {
            continue; // `::MAX` with no width in front — not an integer type.
        }
        if start == 0 || !matches!(bytes[start - 1], 'u' | 'i') {
            continue;
        }
        start -= 1;
        // A qualified path (`std::u8::MAX`) still ends in the type, but a
        // longer identifier (`FOO_u8::MAX`) does not name a primitive.
        if start > 0 && (bytes[start - 1].is_alphanumeric() || bytes[start - 1] == '_') {
            continue;
        }
        return Some(bytes[start..i + 5].iter().collect());
    }
    None
}

fn rust_files(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", dir.display()))?
        {
            let path = entry
                .map_err(|e| anyhow::anyhow!("reading an entry of {}: {e}", dir.display()))?
                .path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wire_type_ceiling_is_caught_however_it_is_spelled() {
        for value in [
            "Some(u8::MAX)",
            "Some(u32::from(u8::MAX))",
            "Some(u16::MAX)",
            "Some(std::u8::MAX)",
            "Some(u32::from(i8::MAX))",
        ] {
            assert!(
                wire_type_max(value).is_some(),
                "{value} derives a ceiling from a wire type and must be refused"
            );
        }
    }

    /// A real ceiling is not flagged, whichever way the backend got it. The
    /// gate governs the derivation, not the mechanism — a measured constant
    /// and a host query are equally acceptable answers.
    #[test]
    fn a_measured_or_queried_ceiling_passes() {
        for value in [
            "Some(MAX_VCPUS)",
            "hvf_backend::hvf_max_vcpus()",
            "Some(32)",
            "None",
        ] {
            assert_eq!(
                wire_type_max(value),
                None,
                "{value} is a real ceiling and must pass"
            );
        }
    }

    /// `MAX_VCPUS` ends in `MAX` but names no integer type, and a constant
    /// whose identifier merely ends in one is not a primitive path either.
    #[test]
    fn an_identifier_ending_in_max_is_not_a_wire_type() {
        assert_eq!(wire_type_max("Some(MAX_VCPUS)"), None);
        assert_eq!(wire_type_max("Some(FALLBACK_u8::MAX)"), None);
        assert_eq!(wire_type_max("Some(SELF::MAX)"), None);
    }

    #[test]
    fn only_assignments_are_read_not_reads_or_field_declarations() {
        assert_eq!(
            ceiling_value("            max_vcpus: Some(MAX_VCPUS),"),
            Some("Some(MAX_VCPUS)")
        );
        assert_eq!(ceiling_value("    pub max_vcpus: Option<u32>,"), None);
        assert_eq!(ceiling_value("    pub max_vcpus: u32,"), None);
        assert_eq!(ceiling_value("        let c = caps.max_vcpus;"), None);
    }

    /// The gate must pass on the tree that ships it.
    #[test]
    fn passes_on_this_workspace() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask has a parent workspace")
            .to_path_buf();
        run(&workspace).expect("this workspace declares no wire-type vCPU ceiling");
    }
}
