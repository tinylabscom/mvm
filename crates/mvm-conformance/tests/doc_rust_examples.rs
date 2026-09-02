//! Compile every Rust example the documentation prints.
//!
//! The bodies come from `build.rs`, which extracts each ```rust block into
//! `$OUT_DIR`. Nothing here calls them — compiling *is* the assertion, exactly
//! as a doctest works. A block that names a crate that does not exist, or a
//! path that moved, fails the build with the doc's `file:line` in a comment
//! directly above the offending function.
//!
//! Blocks that cannot compile as written (IR shape sketches carrying `…`) opt
//! out with ```rust,ignore and must state why; the `bdd` suite checks that the
//! reason is there.

include!(concat!(env!("OUT_DIR"), "/doc_rust_examples.rs"));

/// The generated file is included for its compile-time effect. This keeps the
/// target a valid test binary and records how many examples were compiled.
#[test]
fn documented_rust_examples_compile() {
    // Reaching this point means every generated function type-checked.
}
