//! One comment- and string-aware blanker for the text gates that read Rust
//! source.
//!
//! Several gates decide a security question by matching tokens in source
//! text, and every one of them has to answer the same two questions first:
//! is this token real code, or is it inside a comment, or inside a string
//! literal? Each gate that answers those questions for itself answers them
//! slightly differently, and the differences are where the holes live — one
//! gate stripping only `//` while its neighbour also stripped `/* */` is how
//! a wildcard match arm disguised as `_ /* BackendKind::Mock */ =>` survived,
//! and neither understanding strings is how `_ if reason ==
//! "BackendKind::Mock" =>` stayed a passing bare wildcard. Two copies of a
//! security check diverge; one shared copy cannot.
//!
//! [`blank_comments_and_strings`] returns text of the same length as its
//! input, with every comment and every literal (string, raw string, byte
//! string, char) replaced by spaces and newlines preserved. Same length and
//! same line structure means a caller may keep using byte offsets and line
//! numbers from the blanked text against the original file; blanking rather
//! than deleting means tokens on either side of a removed literal never fuse
//! into one.
//!
//! What it deliberately does not do is parse Rust. It is a lexer for the
//! three constructs that make a substring lie — comments, literals, and the
//! lifetime/char-literal ambiguity that separates them — and nothing else. A
//! gate needing real syntax needs a parser, not this.

/// Replace every comment and every literal in `source` with spaces, keeping
/// the text's length and its newlines.
///
/// Delimiters go too: a blanked string leaves no `"` behind, so a gate
/// counting braces or splitting on delimiters never meets half a literal.
#[must_use]
pub fn blank_comments_and_strings(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0usize;
    while i < chars.len() {
        i = match classify(&chars, i) {
            Span::LineComment => blank_line_comment(&chars, i, &mut out),
            Span::BlockComment => blank_block_comment(&chars, i, &mut out),
            Span::Quoted => blank_quoted(&chars, i, &mut out),
            Span::RawString => blank_raw_string(&chars, i, &mut out),
            Span::CharLiteral => blank_char_literal(&chars, i, &mut out),
            Span::Code => {
                out.push(chars[i]);
                i + 1
            }
        };
    }
    out
}

/// What starts at `chars[i]`.
enum Span {
    LineComment,
    BlockComment,
    /// A `"…"` or `b"…"` string.
    Quoted,
    /// An `r"…"` / `r#"…"#` / `br#"…"#` raw string.
    RawString,
    CharLiteral,
    Code,
}

fn classify(chars: &[char], i: usize) -> Span {
    match chars[i] {
        '/' if chars.get(i + 1) == Some(&'/') => Span::LineComment,
        '/' if chars.get(i + 1) == Some(&'*') => Span::BlockComment,
        '"' => Span::Quoted,
        'r' if starts_raw_string(chars, i) => Span::RawString,
        '\'' if starts_char_literal(chars, i) => Span::CharLiteral,
        _ => Span::Code,
    }
}

/// Whether the `r` at `i` opens a raw string rather than sitting inside an
/// identifier or opening a raw identifier.
///
/// Three things have to hold: the `r` is not a continuation of a preceding
/// identifier (`iter` must not be read as an `r` string opener), and after any
/// run of `#` there is a `"`. The `#` test is what separates the raw string
/// `r#"x"#` from the raw *identifier* `r#type`, which is ordinary code.
fn starts_raw_string(chars: &[char], i: usize) -> bool {
    if i > 0 && is_ident_char(chars[i - 1]) && chars[i - 1] != 'b' {
        return false;
    }
    if i > 0 && chars[i - 1] == 'b' && i > 1 && is_ident_char(chars[i - 2]) {
        return false;
    }
    let mut j = i + 1;
    while chars.get(j) == Some(&'#') {
        j += 1;
    }
    chars.get(j) == Some(&'"')
}

/// Whether the `'` at `i` opens a char literal rather than a lifetime.
///
/// A lifetime (`'a`, `'static`) and a char literal (`'a'`, `'\n'`) both start
/// with `'`, and blanking a lifetime as if it were an unterminated literal
/// would swallow the rest of the file. An escape (`'\`) is always a literal;
/// otherwise a literal is exactly the case where the character two positions
/// on closes it.
fn starts_char_literal(chars: &[char], i: usize) -> bool {
    match chars.get(i + 1) {
        Some('\\') => true,
        Some(_) => chars.get(i + 2) == Some(&'\''),
        None => false,
    }
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Push one blanked character: a newline stays a newline so line numbers and
/// any line-oriented caller survive; everything else becomes a space so byte
/// offsets do too.
fn blank_char(c: char, out: &mut String) {
    out.push(if c == '\n' { '\n' } else { ' ' });
}

fn blank_line_comment(chars: &[char], start: usize, out: &mut String) -> usize {
    let mut i = start;
    while i < chars.len() && chars[i] != '\n' {
        blank_char(chars[i], out);
        i += 1;
    }
    i
}

/// Blank a `/* … */`, honouring nesting: Rust's block comments nest, so the
/// first `*/` does not necessarily close the comment that the first `/*`
/// opened.
fn blank_block_comment(chars: &[char], start: usize, out: &mut String) -> usize {
    let mut depth = 0usize;
    let mut i = start;
    while i < chars.len() {
        if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
            depth += 1;
            blank_char(chars[i], out);
            blank_char(chars[i + 1], out);
            i += 2;
            continue;
        }
        if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
            depth -= 1;
            blank_char(chars[i], out);
            blank_char(chars[i + 1], out);
            i += 2;
            if depth == 0 {
                return i;
            }
            continue;
        }
        blank_char(chars[i], out);
        i += 1;
    }
    i
}

/// Blank a `"…"`, respecting backslash escapes so an escaped quote does not
/// end the literal early.
fn blank_quoted(chars: &[char], start: usize, out: &mut String) -> usize {
    blank_char(chars[start], out);
    let mut i = start + 1;
    while i < chars.len() {
        if chars[i] == '\\' {
            blank_char(chars[i], out);
            if let Some(&next) = chars.get(i + 1) {
                blank_char(next, out);
            }
            i += 2;
            continue;
        }
        blank_char(chars[i], out);
        i += 1;
        if chars[i - 1] == '"' {
            return i;
        }
    }
    i
}

/// Blank an `r#…"…"#…` raw string. There are no escapes; the literal ends at
/// the first `"` followed by as many `#` as opened it.
fn blank_raw_string(chars: &[char], start: usize, out: &mut String) -> usize {
    let mut i = start;
    blank_char(chars[i], out);
    i += 1;
    let mut hashes = 0usize;
    while chars.get(i) == Some(&'#') {
        hashes += 1;
        blank_char(chars[i], out);
        i += 1;
    }
    // The opening quote, which `starts_raw_string` already confirmed.
    if i < chars.len() {
        blank_char(chars[i], out);
        i += 1;
    }
    while i < chars.len() {
        if chars[i] == '"' && closing_hashes(chars, i + 1) >= hashes {
            blank_char(chars[i], out);
            i += 1;
            for _ in 0..hashes {
                blank_char(chars[i], out);
                i += 1;
            }
            return i;
        }
        blank_char(chars[i], out);
        i += 1;
    }
    i
}

fn closing_hashes(chars: &[char], from: usize) -> usize {
    let mut n = 0usize;
    while chars.get(from + n) == Some(&'#') {
        n += 1;
    }
    n
}

fn blank_char_literal(chars: &[char], start: usize, out: &mut String) -> usize {
    blank_char(chars[start], out);
    let mut i = start + 1;
    while i < chars.len() {
        if chars[i] == '\\' {
            blank_char(chars[i], out);
            if let Some(&next) = chars.get(i + 1) {
                blank_char(next, out);
            }
            i += 2;
            continue;
        }
        blank_char(chars[i], out);
        i += 1;
        if chars[i - 1] == '\'' {
            return i;
        }
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every caller relies on offsets and line numbers still lining up.
    fn assert_shape_preserved(source: &str, blanked: &str) {
        assert_eq!(
            source.chars().count(),
            blanked.chars().count(),
            "blanking must preserve length"
        );
        assert_eq!(
            source.lines().count(),
            blanked.lines().count(),
            "blanking must preserve line count"
        );
    }

    fn blank(source: &str) -> String {
        let out = blank_comments_and_strings(source);
        assert_shape_preserved(source, &out);
        out
    }

    #[test]
    fn code_passes_through_unchanged() {
        let src = "fn f(g: &Grants) -> NetworkPolicy { todo!() }";
        assert_eq!(blank(src), src);
    }

    #[test]
    fn a_line_comment_is_blanked_and_the_newline_kept() {
        assert_eq!(
            blank("let a = 1; // note\nlet b = 2;"),
            "let a = 1;        \nlet b = 2;"
        );
    }

    #[test]
    fn a_block_comment_is_blanked() {
        assert_eq!(
            blank("a /* BackendKind::Mock */ b"),
            "a                         b"
        );
    }

    #[test]
    fn a_nested_block_comment_is_blanked_whole() {
        // The first `*/` closes only the inner comment; a depth-blind scanner
        // would resume "code" at ` x */ b` and see the trailing `*/`.
        assert_eq!(blank("a /* /* x */ */ b"), "a               b");
    }

    #[test]
    fn a_string_is_blanked_including_its_quotes() {
        assert_eq!(
            blank(r#"let s = "BackendKind::Mock";"#),
            "let s =                    ;"
        );
    }

    #[test]
    fn an_escaped_quote_does_not_end_the_string_early() {
        assert_eq!(
            blank(r#"let s = "a\"b"; let t = 1;"#),
            "let s =       ; let t = 1;"
        );
    }

    #[test]
    fn a_comment_marker_inside_a_string_is_not_a_comment() {
        // The classic false strip: `//` inside a URL literal eating the rest
        // of the line, including a closing brace a caller was counting.
        let out = blank(r#"let u = "http://x"; }"#);
        assert!(
            out.ends_with("; }"),
            "the brace after the literal must survive: {out:?}"
        );
    }

    #[test]
    fn a_quote_inside_a_line_comment_does_not_open_a_string() {
        let out = blank("// he said \"hi\nlet a = 1;");
        assert!(out.contains("let a = 1;"), "{out:?}");
    }

    #[test]
    fn a_raw_string_is_blanked() {
        let out = blank(r##"let s = r#"a "quoted" b"#; let t = 1;"##);
        assert!(out.trim_end().ends_with("let t = 1;"), "{out:?}");
        assert!(!out.contains("quoted"), "{out:?}");
    }

    #[test]
    fn a_byte_string_is_blanked() {
        let out = blank(r#"let s = b"fn f(g: &Grants) -> NetworkPolicy"; let t = 1;"#);
        assert!(!out.contains("Grants"), "{out:?}");
        assert!(out.trim_end().ends_with("let t = 1;"), "{out:?}");
    }

    #[test]
    fn a_raw_identifier_is_not_a_raw_string() {
        let src = "let r#type = 1; let a = 2;";
        assert_eq!(blank(src), src);
    }

    #[test]
    fn an_r_ending_an_identifier_does_not_open_a_raw_string() {
        let src = "let iter = 1; let a = \"x\";";
        assert_eq!(blank(src), "let iter = 1; let a =    ;");
    }

    #[test]
    fn a_lifetime_is_not_a_char_literal() {
        // Misreading `'a` as an unterminated char literal would blank the
        // rest of the file — the worst failure mode available here, since a
        // gate would then see no offending code anywhere.
        let src = "fn f<'a>(x: &'a str) -> NetworkPolicy { todo!() }";
        assert_eq!(blank(src), src);
    }

    #[test]
    fn a_char_literal_is_blanked() {
        assert_eq!(blank("let c = 'x'; let d = 1;"), "let c =    ; let d = 1;");
    }

    #[test]
    fn an_escaped_char_literal_is_blanked() {
        assert_eq!(
            blank(r"let c = '\''; let d = 1;"),
            "let c =     ; let d = 1;"
        );
    }

    #[test]
    fn a_static_lifetime_followed_by_a_string_still_blanks_the_string() {
        let out = blank("const S: &'static str = \"BackendKind::Mock\";");
        assert!(!out.contains("BackendKind"), "{out:?}");
        assert!(out.starts_with("const S: &'static str = "), "{out:?}");
    }

    #[test]
    fn an_unterminated_string_does_not_panic() {
        let _ = blank("let s = \"unterminated");
    }

    #[test]
    fn an_unterminated_block_comment_does_not_panic() {
        let _ = blank("/* unterminated");
    }
}
