//! Extract the `mvmctl …` commands that mvmctl's own output names.
//!
//! The documentation harness reads Markdown. It cannot see the other place a
//! reader is told to run something: the CLI's own strings — hints, error
//! messages, "Run with:" lines. Those drift exactly like docs do, and nothing
//! checked them, so `mvmctl bundle install` closed by printing
//! `launch with: mvmctl up --manifest <sha>` long after `up` stopped being a
//! dispatched verb.
//!
//! This module is only the extractor; deciding whether a command is real needs
//! the clap tree and lives with the step that owns it.

/// A `mvmctl …` command named inside a Rust string literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceCommand {
    pub file: String,
    /// 1-based line of the `mvmctl` token itself, not of the literal's start —
    /// a multi-line message should point at the offending line.
    pub line: usize,
    /// The command words following `mvmctl`, at most two. Only the first two
    /// are ever judged — a third word is an argument, not a command path — and
    /// capturing more only drags prose in ("mvmctl bootstrap or mvmctl doctor").
    pub words: Vec<String>,
}

impl SourceCommand {
    /// The command as written, for reporting and for allow-list matching.
    pub fn rendered(&self) -> String {
        format!("mvmctl {}", self.words.join(" "))
    }
}

/// One string literal's body together with the offset it started at.
struct Literal {
    body: String,
    /// Offset of the body's first byte within the original source.
    offset: usize,
}

/// Scan Rust source for string literals, skipping comments.
///
/// Hand-rolled rather than regex-driven for two reasons, both of which cost me
/// a wrong answer first: a literal may contain escapes (`"\nRun with: …"`), and
/// a literal may span lines (a `\`-continued error message). A regex that
/// excludes backslashes silently drops the first, and a line-at-a-time scan
/// silently drops the second. Both failures are invisible — the extractor
/// returns fewer items and every downstream assertion still passes.
fn string_literals(source: &str) -> Vec<Literal> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        // Line comment.
        if bytes[i..].starts_with(b"//") {
            i += source[i..].find('\n').map_or(source.len() - i, |n| n + 1);
            continue;
        }
        // Block comment. Rust nests them; track depth so an inner `*/` does not
        // end the outer comment early.
        if bytes[i..].starts_with(b"/*") {
            let mut depth = 1;
            i += 2;
            while i < bytes.len() && depth > 0 {
                if bytes[i..].starts_with(b"/*") {
                    depth += 1;
                    i += 2;
                } else if bytes[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        // Raw string: r, r#, r##… followed by a quote. Escapes are literal and
        // the terminator is the quote plus the same run of hashes.
        if bytes[i] == b'r' && !preceded_by_ident_char(bytes, i) {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] == b'#' {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                let hashes = j - (i + 1);
                let terminator = format!("\"{}", "#".repeat(hashes));
                let start = j + 1;
                if let Some(end) = source[start..].find(&terminator) {
                    out.push(Literal {
                        body: source[start..start + end].to_string(),
                        offset: start,
                    });
                    i = start + end + terminator.len();
                    continue;
                }
                break;
            }
        }
        if bytes[i] == b'"' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() {
                match bytes[j] {
                    b'\\' => j += 2,
                    b'"' => break,
                    _ => j += 1,
                }
            }
            let end = j.min(bytes.len());
            out.push(Literal {
                body: source[start..end].to_string(),
                offset: start,
            });
            i = end + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// Is the byte before `i` part of an identifier? Guards against reading the
/// `r` of `letर…`-style identifiers (or `char_indices`) as a raw-string sigil.
fn preceded_by_ident_char(bytes: &[u8], i: usize) -> bool {
    i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_')
}

/// A bare lowercase command word: `machine`, `shell-init`, `verify-cert`.
///
/// Edge punctuation is trimmed first. CLI messages overwhelmingly write a
/// command as `` `mvmctl compile` ``, and a scanner that rejects the trailing
/// backtick drops the occurrence entirely rather than reporting it — the
/// failure mode that hides the very drift this exists to catch.
fn command_word(token: &str) -> Option<&str> {
    let token = token.trim_matches(|c: char| "`'\"(),.:;?!".contains(c));
    let ok = !token.is_empty()
        && token.starts_with(|c: char| c.is_ascii_lowercase())
        && token
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    ok.then_some(token)
}

/// How many words of a command path are ever meaningful: a verb and its
/// subcommand. `mvmctl image pull alpine` — `alpine` is an argument.
const MAX_COMMAND_WORDS: usize = 2;

/// Every `mvmctl …` command named in `contents`.
pub fn source_commands(file: &str, contents: &str) -> Vec<SourceCommand> {
    let mut out = Vec::new();
    for literal in string_literals(contents) {
        let mut search = 0;
        while let Some(found) = literal.body[search..].find("mvmctl ") {
            let at = search + found;
            let rest = &literal.body[at + "mvmctl ".len()..];
            let words: Vec<String> = rest
                .split_whitespace()
                // A second `mvmctl` starts a new command; it is not an
                // argument of this one.
                .take_while(|token| *token != "mvmctl")
                .map_while(|token| command_word(token).map(str::to_string))
                .take(MAX_COMMAND_WORDS)
                .collect();
            if !words.is_empty() {
                let absolute = literal.offset + at;
                out.push(SourceCommand {
                    file: file.to_string(),
                    line: contents[..absolute.min(contents.len())]
                        .matches('\n')
                        .count()
                        + 1,
                    words,
                });
            }
            search = at + "mvmctl ".len();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commands(source: &str) -> Vec<String> {
        source_commands("x.rs", source)
            .iter()
            .map(SourceCommand::rendered)
            .collect()
    }

    #[test]
    fn reads_a_plain_literal() {
        assert_eq!(
            commands(r#"println!("launch with: mvmctl machine run");"#),
            ["mvmctl machine run"]
        );
    }

    /// The first bug this extractor had. A regex body of `[^"\\]*` cannot match
    /// a literal containing `\n`, so every message that opens with a newline —
    /// which is most "Run with:" hints — was invisible.
    #[test]
    fn reads_a_literal_containing_escapes() {
        assert_eq!(
            commands(r#"ui::info(&format!("\nRun with: mvmctl machine start {}", n));"#),
            ["mvmctl machine start"]
        );
    }

    /// The second bug. A line-at-a-time scan needs the closing quote on the
    /// same line, so `\`-continued messages were dropped whole.
    #[test]
    fn reads_a_literal_spanning_lines() {
        let source = "let e = format!(\n    \"`mvmctl run --prod` redirects to \\\n     `mvmctl build compile`, where record is default\"\n);";
        assert_eq!(
            commands(source),
            ["mvmctl run", "mvmctl build compile"],
            "a continued literal must be scanned as one string"
        );
    }

    #[test]
    fn line_number_points_at_the_mvmctl_token_not_the_literal_start() {
        let source = "let e = format!(\n    \"a long preamble \\\n     mvmctl machine run\"\n);";
        let found = source_commands("x.rs", source);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 3, "should point at the line naming it");
    }

    #[test]
    fn ignores_comments() {
        assert_eq!(commands("// mvmctl up --manifest x\nlet a = 1;"), [""; 0]);
        assert_eq!(commands("/* mvmctl up */ let a = 1;"), [""; 0]);
    }

    #[test]
    fn ignores_nested_block_comments() {
        assert_eq!(
            commands("/* outer /* inner */ mvmctl up */ let a = 1;"),
            [""; 0]
        );
    }

    #[test]
    fn reads_raw_strings() {
        assert_eq!(
            commands(r##"let s = r#"run mvmctl machine ls now"#;"##),
            ["mvmctl machine ls"]
        );
    }

    #[test]
    fn stops_at_the_first_non_word_token() {
        assert_eq!(
            commands(r#"let s = "mvmctl machine run --manifest {sha}";"#),
            ["mvmctl machine run"]
        );
        assert_eq!(
            commands(r#"let s = "mvmctl image pull alpine:latest";"#),
            ["mvmctl image pull"]
        );
    }

    #[test]
    fn finds_every_occurrence_in_one_literal() {
        assert_eq!(
            commands(r#"let s = "use mvmctl bootstrap or mvmctl doctor";"#),
            ["mvmctl bootstrap or", "mvmctl doctor"]
        );
    }

    #[test]
    fn keeps_hyphenated_verbs() {
        assert_eq!(
            commands(r#"let s = "mvmctl shell-init";"#),
            ["mvmctl shell-init"]
        );
    }
}
