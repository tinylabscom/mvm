//! Tree-sitter-nix validator for hand-authored Nix bodies bundled
//! with addons. v1 is parse-only.
//!
//! v1 scope: parse the input under tree-sitter-nix; report any
//! `ERROR` or `MISSING` nodes with their byte offsets so the publish
//! flow can surface line/column to the addon author.
//!
//! Future scope: AST-level merging of in-VM addon Nix fragments into
//! the consumer's `mkGuest` flake. This module's trait shape (single
//! `validate(&str) -> Result<(), Vec<NixSyntaxError>>` entry point) is
//! the substrate that future merging machinery slots into.

use tree_sitter::{Node, Parser};

/// One parse error in an addon's Nix body. Caller resolves byte
/// offsets into line/column via the original source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NixSyntaxError {
    /// Byte offset where the error starts in the source.
    pub start_byte: usize,
    /// Byte offset where the error ends.
    pub end_byte: usize,
    /// Human-readable hint about what tree-sitter saw.
    pub message: String,
}

/// Validate a Nix source string. Returns `Ok(())` if the parse tree
/// has no `ERROR` or `MISSING` nodes, or `Err(errors)` enumerating
/// every problem tree-sitter found.
///
/// `validate` is intentionally cheap to call: it parses but does not
/// run any semantic checks. AST-level rules (e.g. "the fragment is a
/// function from `{ pkgs, params }: ...`") are layered on top by
/// follow-up passes when the in-VM addon tier lands.
pub fn validate(nix_source: &str) -> Result<(), Vec<NixSyntaxError>> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_nix::LANGUAGE.into())
        .expect("tree-sitter-nix grammar is compatible with tree-sitter 0.26");

    let tree = match parser.parse(nix_source, None) {
        Some(t) => t,
        None => {
            return Err(vec![NixSyntaxError {
                start_byte: 0,
                end_byte: nix_source.len(),
                message:
                    "tree-sitter-nix returned no parse tree (likely empty input or grammar bug)"
                        .to_string(),
            }]);
        }
    };

    let mut errors = vec![];
    collect_errors(tree.root_node(), nix_source.as_bytes(), &mut errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn collect_errors(node: Node, source: &[u8], errors: &mut Vec<NixSyntaxError>) {
    if node.is_error() || node.is_missing() {
        let snippet = std::str::from_utf8(&source[node.byte_range()])
            .unwrap_or("<invalid utf-8>")
            .chars()
            .take(40)
            .collect::<String>();
        errors.push(NixSyntaxError {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            message: if node.is_missing() {
                format!("missing {} (parser expected one here)", node.kind())
            } else {
                format!("syntax error near {snippet:?}")
            },
        });
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_errors(child, source, errors);
    }
}

/// Resolve a byte offset to a 1-based `(line, column)` pair. Useful
/// for surfacing tree-sitter parse errors with the same shape as the
/// rest of the toolchain's diagnostic surfaces.
pub fn line_column(source: &str, byte_offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut col = 1usize;
    for (i, ch) in source.char_indices() {
        if i >= byte_offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_minimal_nix_function() {
        let src = "{ pkgs, ... }: { packages = [ pkgs.hello ]; }";
        validate(src).expect("valid Nix should parse cleanly");
    }

    #[test]
    fn accepts_realistic_addon_fragment() {
        let src = r#"
            { pkgs, params, ... }: {
              packages = [ pkgs.postgresql_16 ];
              services.postgres = {
                command = "${pkgs.postgresql_16}/bin/postgres";
                env = { PGDATA = "/var/lib/postgres"; };
              };
            }
        "#;
        validate(src).expect("addon fragment should parse cleanly");
    }

    #[test]
    fn rejects_malformed_nix() {
        let bad = "{ broken syntax }} let in";
        let errs = validate(bad).expect_err("malformed Nix should fail");
        assert!(!errs.is_empty(), "expected at least one syntax error");
    }

    #[test]
    fn line_column_resolves_offsets() {
        let src = "abc\ndef\nghi";
        assert_eq!(line_column(src, 0), (1, 1));
        assert_eq!(line_column(src, 4), (2, 1));
        assert_eq!(line_column(src, 5), (2, 2));
        assert_eq!(line_column(src, 8), (3, 1));
    }
}
