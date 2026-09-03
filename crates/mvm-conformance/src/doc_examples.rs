//! Extraction and tiering of the documented `mvmctl` examples.
//!
//! The README and the website docs are a user-facing contract: every command
//! they print is something a reader will paste into a shell. This module turns
//! that prose into machine-checkable data — fenced code blocks, the `mvmctl`
//! invocations inside them, and the tier each invocation is verified at — so
//! the cucumber suite can assert the contract instead of trusting it.
//!
//! Pure by construction (the only I/O is reading the doc files handed to it),
//! so the parsing rules are unit-tested here rather than through the runner.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Fence languages whose bodies are shell transcripts we extract commands from.
const SHELL_LANGUAGES: &[&str] = &["bash", "sh", "shell", "zsh", "console", "shell-session"];

/// How thoroughly a documented command is proven to work.
///
/// The tiers are a ladder, not alternatives: everything is parsed, most things
/// are additionally executed, and the subset that needs a real guest is
/// executed on a live host. A command that reaches no tier is a documentation
/// claim with no evidence behind it, which is what [`TierPolicy`] refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Parsed against the real clap tree only. For commands that mutate host
    /// state, need the network, or boot a VM, and so cannot run in PR CI.
    Parse,
    /// Parsed, and additionally executed for real against an isolated
    /// `MVM_HOME`. Reserved for commands with no side effects outside that
    /// home and no network access.
    Exec,
    /// Parsed, and additionally executed on a host with a working hypervisor,
    /// where it boots a real microVM.
    Live,
}

impl Tier {
    /// The spelling used in the tier manifest.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Parse => "parse",
            Tier::Exec => "exec",
            Tier::Live => "live",
        }
    }
}

/// Parse a manifest spelling, rejecting anything else so a typo in the
/// manifest fails loudly rather than silently downgrading coverage.
impl std::str::FromStr for Tier {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "parse" => Ok(Tier::Parse),
            "exec" => Ok(Tier::Exec),
            "live" => Ok(Tier::Live),
            other => Err(format!(
                "unknown tier {other:?} (expected \"parse\", \"exec\" or \"live\")"
            )),
        }
    }
}

/// A fenced code block lifted from a documentation file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeBlock {
    /// Repo-relative path of the file the block came from.
    pub file: String,
    /// 1-based line of the opening fence.
    pub line: usize,
    /// The fence's language token, lowercased; empty for a bare ``` fence.
    pub language: String,
    /// Comma-separated fence attributes after the language (`rust,ignore`),
    /// following rustdoc's convention.
    pub attributes: Vec<String>,
    /// The block body, newline-joined, without the fences.
    pub body: String,
}

impl CodeBlock {
    /// Whether this block is a shell transcript we extract commands from.
    pub fn is_shell(&self) -> bool {
        SHELL_LANGUAGES.contains(&self.language.as_str())
    }

    /// `file:line`, the form an editor and a CI log both linkify.
    pub fn location(&self) -> String {
        format!("{}:{}", self.file, self.line)
    }

    /// Whether the block opts out of compilation, rustdoc-style.
    pub fn is_ignored(&self) -> bool {
        self.attributes
            .iter()
            .any(|a| a == "ignore" || a == "no_compile")
    }

    /// The justification an ignored block must carry on its first line.
    ///
    /// An opt-out with no stated reason is how a wrong example survives: the
    /// marker looks deliberate and nobody can tell whether it still is.
    pub fn ignore_reason(&self) -> Option<&str> {
        self.body
            .lines()
            .next()?
            .trim()
            .strip_prefix("// illustrative:")
            .map(str::trim)
    }
}

/// Where a documented invocation was written, which decides how strictly it is
/// checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExampleSource {
    /// Inside a fenced shell block: a recipe a reader pastes and runs, so it
    /// must parse completely, arguments included.
    Fenced,
    /// An inline `` `code span` ``: usually a reference to a command in a table
    /// or a sentence ("see `mvmctl machine exec`"), which names a verb without
    /// supplying its arguments. The verb must exist; the arguments are not
    /// expected to be complete.
    Inline,
}

/// One documented `mvmctl` invocation, with the provenance needed to point a
/// failure back at the exact line an author has to edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocExample {
    /// How strictly this invocation is checked.
    pub source: ExampleSource,
    /// Repo-relative path of the file the command came from.
    pub file: String,
    /// 1-based line the command starts on.
    pub line: usize,
    /// The invocation as written, with line continuations folded into one line.
    pub command: String,
    /// The invocation split into argv, quotes removed, `mvmctl` itself dropped.
    pub argv: Vec<String>,
}

impl DocExample {
    /// `file:line`, the form an editor and a CI log both linkify.
    pub fn location(&self) -> String {
        format!("{}:{}", self.file, self.line)
    }

    /// Whether the invocation is a syntax template (`mvmctl <command> --help`)
    /// rather than something a reader could paste and run. Templates document
    /// shape, not a specific command, so they are described rather than run.
    pub fn is_template(&self) -> bool {
        self.argv.iter().any(|token| is_placeholder(token))
    }

    /// The tokens before the first placeholder, which is the concrete part of
    /// a template.
    ///
    /// A template is exempt from parsing, which would otherwise be a way to
    /// document a command that does not exist — write `<placeholders>` and
    /// nothing checks it. The leading verbs are still concrete, so the caller
    /// resolves them against the real command tree.
    pub fn concrete_prefix(&self) -> Vec<String> {
        let mut prefix = Vec::new();
        for token in &self.argv {
            if is_placeholder(token) || token == "--" || token.starts_with('-') {
                break;
            }
            prefix.push(token.clone());
        }
        prefix
    }
}

/// Whether a token is a documentation placeholder (`<NAME>`, `[DIR]`) rather
/// than a literal argument.
///
/// A bare `<` or `>` is a shell redirect, not a placeholder: `mvmctl machine fs
/// write vm /path < file` is a runnable command and must stay checked.
fn is_placeholder(token: &str) -> bool {
    // Elision and wildcards stand in for an argument list or a family of
    // subcommands: `mvmctl manifest *`, `mvmctl machine exec ...`.
    if matches!(token, "..." | "…" | "*") {
        return true;
    }
    // Slash alternation names several subcommands at once
    // (`mvmctl machine pause/resume`). A path argument also contains a slash,
    // so require the token to look like a bare word list rather than a path.
    if token.contains('/')
        && !token.starts_with('/')
        && !token.starts_with('.')
        && !token.contains(':')
        && token.split('/').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '…')
        })
    {
        return true;
    }
    let angled = token
        .find('<')
        .zip(token.find('>'))
        .is_some_and(|(open, close)| close > open + 1);
    let bracketed = token.starts_with('[') || token.ends_with(']');
    angled || bracketed
}

/// Split a documentation file into its fenced code blocks.
///
/// Info strings beyond the language (```nix "mkGuest") are ignored: only the
/// first whitespace-delimited token is the language.
pub fn code_blocks(file: &str, contents: &str) -> Vec<CodeBlock> {
    let mut blocks = Vec::new();
    let mut open: Option<CodeBlock> = None;

    for (index, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        match open.as_mut() {
            Some(block) => {
                if trimmed.starts_with("```") && trimmed.trim_end_matches('`').is_empty() {
                    blocks.push(open.take().expect("an open block"));
                } else {
                    if !block.body.is_empty() {
                        block.body.push('\n');
                    }
                    block.body.push_str(line);
                }
            }
            None => {
                if let Some(info) = trimmed.strip_prefix("```") {
                    open = Some(CodeBlock {
                        file: file.to_string(),
                        line: index + 1,
                        language: info
                            .split_whitespace()
                            .next()
                            .unwrap_or_default()
                            .split(',')
                            .next()
                            .unwrap_or_default()
                            .to_ascii_lowercase(),
                        attributes: info
                            .split_whitespace()
                            .next()
                            .unwrap_or_default()
                            .split(',')
                            .skip(1)
                            .map(|attribute| attribute.trim().to_ascii_lowercase())
                            .filter(|attribute| !attribute.is_empty())
                            .collect(),
                        body: String::new(),
                    });
                }
            }
        }
    }

    blocks
}

/// Whether a documentation file left a code fence open.
///
/// An unterminated fence silently swallows the prose after it — and, worse for
/// this harness, hides every command in the swallowed region from extraction,
/// so the examples stop being checked without anything going red.
pub fn has_unterminated_fence(contents: &str) -> bool {
    contents
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("```")
        })
        .count()
        % 2
        != 0
}

/// Lines that invoke `mvmctl` while sitting outside any fenced code block.
///
/// This is the failure mode a fence-balance check cannot see: a fence closed
/// one block too early leaves real commands stranded in the prose. They render
/// as broken Markdown for the reader and, because extraction only walks fenced
/// blocks, they vanish from this harness — the example stops being checked at
/// the same moment it stops being readable.
///
/// `known_verbs` are the CLI's real top-level subcommand names. They are what
/// separates a stranded command from an ordinary sentence that happens to open
/// with the binary's name ("mvmctl uses Nix flakes to ..."), so the caller
/// supplies them from the live command tree rather than this module guessing.
pub fn mvmctl_lines_outside_fences(contents: &str, known_verbs: &[String]) -> Vec<(usize, String)> {
    let mut stranded = Vec::new();
    let mut inside = false;

    for (index, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            inside = !inside;
            continue;
        }
        if inside {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("mvmctl ") else {
            continue;
        };
        // The word after the binary decides it: a real verb or a flag means a
        // command, anything else is prose.
        let next = rest.split_whitespace().next().unwrap_or_default();
        let is_command = next.starts_with('-') || known_verbs.iter().any(|verb| verb == next);
        if is_command {
            stranded.push((index + 1, trimmed.to_string()));
        }
    }

    stranded
}

/// Extract every `mvmctl` invocation from a documentation file's shell blocks.
pub fn doc_examples(file: &str, contents: &str) -> Vec<DocExample> {
    let mut found: Vec<DocExample> = code_blocks(file, contents)
        .into_iter()
        .filter(CodeBlock::is_shell)
        .flat_map(|block| shell_block_examples(&block))
        .collect();
    found.extend(inline_code_examples(file, contents));
    found
}

/// Extract every `mvmctl` invocation written as an inline code span.
///
/// The CLI reference documents most of its surface in Markdown tables, where a
/// command is `` `mvmctl machine build <path>` `` rather than a fenced block.
/// Those are commands a reader copies too, and nothing checked them: a whole
/// reference page of stale spellings can sit behind a green fenced-block gate.
///
/// Spans inside fenced blocks are skipped — the fence walker already has them.
pub fn inline_code_examples(file: &str, contents: &str) -> Vec<DocExample> {
    let mut found = Vec::new();
    let mut inside_fence = false;

    for (index, line) in contents.lines().enumerate() {
        if line.trim().starts_with("```") {
            inside_fence = !inside_fence;
            continue;
        }
        if inside_fence {
            continue;
        }
        for span in code_spans(line) {
            let Some(rest) = span.trim().strip_prefix("mvmctl") else {
                continue;
            };
            if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
                continue;
            }
            let argv = strip_redirections(tokenize(rest));
            if argv.is_empty() {
                continue;
            }
            found.push(DocExample {
                source: ExampleSource::Inline,
                file: file.to_string(),
                line: index + 1,
                command: span.trim().to_string(),
                argv,
            });
        }
    }

    found
}

/// The contents of each single-backtick code span on a line.
///
/// Double-backtick spans (used to quote a span containing a backtick) are read
/// the same way; the delimiters are just longer.
fn code_spans(line: &str) -> Vec<String> {
    let mut spans = Vec::new();
    let mut rest = line;

    while let Some(open) = rest.find('`') {
        let after = &rest[open..];
        let ticks = after.chars().take_while(|c| *c == '`').count();
        let delimiter = "`".repeat(ticks);
        let body = &after[ticks..];
        match body.find(&delimiter) {
            Some(close) => {
                spans.push(body[..close].to_string());
                rest = &body[close + ticks..];
            }
            None => break,
        }
    }

    spans
}

/// Pull the `mvmctl` invocations out of one shell block, folding line
/// continuations and splitting compound commands on shell operators.
fn shell_block_examples(block: &CodeBlock) -> Vec<DocExample> {
    let mut examples = Vec::new();
    let mut pending: Option<(usize, String)> = None;

    for (offset, raw) in block.body.lines().enumerate() {
        // +1 for the opening fence line itself.
        let line = block.line + offset + 1;
        let text = strip_prompt(raw);

        let (fragment, start) = match pending.take() {
            Some((start, mut accumulated)) => {
                accumulated.push(' ');
                accumulated.push_str(text.trim());
                (accumulated, start)
            }
            None => (text.trim().to_string(), line),
        };

        if let Some(without_slash) = fragment.strip_suffix('\\') {
            pending = Some((start, without_slash.trim_end().to_string()));
            continue;
        }

        for command in split_invocations(&fragment) {
            let argv = strip_redirections(tokenize(&command));
            // `tokenize` keeps `mvmctl` as argv[0]; the example stores the
            // arguments only, which is what clap's `try_get_matches_from`
            // wants after the binary name.
            let Some((first, rest)) = argv.split_first() else {
                continue;
            };
            debug_assert_eq!(first, "mvmctl");
            examples.push(DocExample {
                source: ExampleSource::Fenced,
                file: block.file.clone(),
                line: start,
                command: command.clone(),
                argv: rest.to_vec(),
            });
        }
    }

    examples
}

/// Remove a `$ ` or `% ` shell prompt, which several docs pages use.
fn strip_prompt(line: &str) -> &str {
    let trimmed = line.trim_start();
    for prompt in ["$ ", "% "] {
        if let Some(rest) = trimmed.strip_prefix(prompt) {
            return rest;
        }
    }
    line
}

/// Find each `mvmctl` invocation inside one logical shell line.
///
/// A line can hold several (`mvmctl a && mvmctl b`). The binary name is only
/// an invocation when it is the *command word* of a segment: `cargo install
/// mvmctl` and `cp target/release/mvmctl ~/.local/bin/` both mention it as an
/// argument, and neither is a command a reader runs.
fn split_invocations(line: &str) -> Vec<String> {
    // A leading `#` makes the whole line a comment.
    if line.trim_start().starts_with('#') {
        return Vec::new();
    }

    split_segments(line)
        .into_iter()
        .filter_map(|segment| {
            let segment = strip_inline_comment(segment.trim());
            let rest = command_word_arguments(segment)?;
            Some(format!("mvmctl {rest}").trim_end().to_string())
        })
        .collect()
}

/// Split a shell line on unquoted `&&`, `||`, `;` and `|` into the segments
/// each of which runs one command.
fn split_segments(line: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let bytes = line.as_bytes();
    let mut index = 0;

    while index < line.len() {
        if !line.is_char_boundary(index) {
            index += 1;
            continue;
        }
        let character = bytes[index] as char;
        // `2>&1` is one redirect, not a segment boundary.
        let redirect_ampersand = character == '&'
            && line[..index]
                .chars()
                .next_back()
                .is_some_and(|previous| previous == '>');
        if matches!(character, '&' | '|' | ';') && !redirect_ampersand && !in_quotes(line, index) {
            segments.push(&line[start..index]);
            // Consume a doubled operator (`&&`, `||`) as one separator.
            let width = if index + 1 < line.len() && bytes[index + 1] as char == character {
                2
            } else {
                1
            };
            index += width;
            start = index;
            continue;
        }
        index += 1;
    }
    segments.push(&line[start..]);
    segments
}

/// Strip a trailing inline comment. A `#` only opens one when it starts a
/// word, so `--allow-host a#b` survives.
fn strip_inline_comment(segment: &str) -> &str {
    match segment.find(" #") {
        Some(index) => segment[..index].trim_end(),
        None => segment,
    }
}

/// If `segment`'s command word is `mvmctl`, the arguments that follow it.
///
/// Leading environment assignments (`MVM_PHASE_TIMING=1 mvmctl ...`) and the
/// usual wrapper commands are stepped over, because a reader running the line
/// still runs `mvmctl`.
fn command_word_arguments(segment: &str) -> Option<&str> {
    const WRAPPERS: &[&str] = &["sudo", "env", "time", "exec", "command"];

    let mut rest = segment.trim_start();
    loop {
        let (word, tail) = match rest.split_once(char::is_whitespace) {
            Some((word, tail)) => (word, tail.trim_start()),
            None => (rest, ""),
        };
        if word == "mvmctl" {
            return Some(tail);
        }
        // An environment assignment or a wrapper: step over it and re-test.
        let is_assignment = word
            .split_once('=')
            .is_some_and(|(name, _)| !name.is_empty() && !name.contains('/'));
        if is_assignment || WRAPPERS.contains(&word) {
            if tail.is_empty() {
                return None;
            }
            rest = tail;
            continue;
        }
        return None;
    }
}

/// Whether byte `index` of `text` sits inside a quoted region.
fn in_quotes(text: &str, index: usize) -> bool {
    let mut single = false;
    let mut double = false;
    for (position, character) in text.char_indices() {
        if position >= index {
            break;
        }
        match character {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            _ => {}
        }
    }
    single || double
}

/// Split a command into argv, honouring single and double quotes and dropping
/// the quote characters themselves — the same shape a shell would hand execve.
pub fn tokenize(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut single = false;
    let mut double = false;

    for character in command.chars() {
        match character {
            '\'' if !double => {
                single = !single;
                started = true;
            }
            '"' if !single => {
                double = !double;
                started = true;
            }
            character if character.is_whitespace() && !single && !double => {
                if started || !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            character => {
                current.push(character);
                started = true;
            }
        }
    }
    if started || !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

/// Drop shell redirections from an argv.
///
/// The shell consumes `> file`, `2>/dev/null` and `< input` before it execs the
/// program, so they are not arguments and must not be parsed as any. Leaving
/// them in makes a correct documented command look broken.
fn strip_redirections(tokens: Vec<String>) -> Vec<String> {
    let mut kept = Vec::new();
    let mut skip_next = false;

    for token in tokens {
        if skip_next {
            skip_next = false;
            continue;
        }
        // A `<NAME>` placeholder is documentation, not a redirect.
        if is_placeholder(&token) {
            kept.push(token);
            continue;
        }
        // An optional file-descriptor prefix, then one or two angle brackets.
        let body = token.trim_start_matches(|character: char| character.is_ascii_digit());
        let operator = body.starts_with('<') || body.starts_with('>');
        if !operator {
            kept.push(token);
            continue;
        }
        let target = body.trim_start_matches(['<', '>', '&']);
        // `> file` names its target in the next token; `2>/dev/null` carries it.
        if target.is_empty() {
            skip_next = true;
        }
    }

    kept
}

/// One executable scenario of a feature file, with the `mvmctl` invocations
/// its steps drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioCommands {
    /// The scenario name as written after `Scenario:` / `Scenario Outline:`.
    pub name: String,
    /// Whether the scenario carries `@live` (or inherits it from the feature).
    pub is_live: bool,
    /// Each quoted `mvmctl` invocation the scenario's steps carry, as argv.
    pub commands: Vec<Vec<String>>,
}

/// Every scenario in a feature file, paired with the commands it drives.
///
/// [`live_scenario_commands`] answers "is this command exercised anywhere",
/// which is enough for a per-command-path tier. Pinning a *documented example*
/// to the scenario that covers it needs the scenarios kept apart, so the
/// witness a manifest names can be looked up and checked rather than trusted.
pub fn scenario_commands(contents: &str) -> Vec<ScenarioCommands> {
    let feature_is_live = contents
        .lines()
        .take_while(|line| !line.trim_start().starts_with("Feature:"))
        .any(|line| line.contains("@live"));

    let mut scenarios: Vec<ScenarioCommands> = Vec::new();
    let mut pending_live = feature_is_live;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('@') {
            pending_live = trimmed.contains("@live") || feature_is_live;
            continue;
        }
        if let Some(name) = trimmed
            .strip_prefix("Scenario Outline:")
            .or_else(|| trimmed.strip_prefix("Scenario:"))
        {
            scenarios.push(ScenarioCommands {
                name: name.trim().to_string(),
                is_live: pending_live,
                commands: Vec::new(),
            });
            pending_live = feature_is_live;
            continue;
        }
        let Some(current) = scenarios.last_mut() else {
            continue;
        };
        // Steps quote the command: `... with "machine run --image alpine"`.
        for fragment in line.split('"').skip(1).step_by(2) {
            let argv = strip_redirections(tokenize(fragment));
            if !argv.is_empty() {
                current.commands.push(argv);
            }
        }
    }

    scenarios
}

/// Whether `witness` exercises the same request shape as `example`.
///
/// Same command path, and every flag the example passes to `mvmctl` is also
/// passed by the witness. Values are free to differ — a scenario booting
/// `--image alpine` legitimately stands in for a README line booting
/// `--image python:3.12`, and pinning the value would make the suite a
/// transcription of the README rather than a test of it.
///
/// The flag set is what must match, and it is the half that was missing. A
/// single live `machine run --image alpine -- true` used to discharge every
/// documented `machine run`, including the `-it` form, whose console had been
/// broken on every OCI image the whole time.
#[must_use]
pub fn witness_covers(example: &[String], witness: &[String], known: &[Vec<String>]) -> bool {
    let example_path = command_path_in(example, known);
    if example_path.is_empty() || example_path != command_path_in(witness, known) {
        return false;
    }
    flag_set(example).is_subset(&flag_set(witness))
}

/// The `mvmctl` invocations inside every `@live`-tagged scenario of a feature
/// file.
///
/// A `live` tier entry claims a real guest boots that command. That claim is
/// only worth something if a live scenario actually runs it, so the suite reads
/// the scenarios back and checks. Tag inheritance is not modelled: a scenario
/// counts when `@live` sits on it or on its `Feature:` line.
pub fn live_scenario_commands(contents: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let feature_is_live = contents
        .lines()
        .take_while(|line| !line.trim_start().starts_with("Feature:"))
        .any(|line| line.contains("@live"));

    let mut pending_live = feature_is_live;
    let mut in_live_scenario = feature_is_live;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('@') {
            pending_live = trimmed.contains("@live") || feature_is_live;
            continue;
        }
        if trimmed.starts_with("Scenario") {
            in_live_scenario = pending_live;
            pending_live = feature_is_live;
            continue;
        }
        if !in_live_scenario {
            continue;
        }
        // Steps quote the command: `... with "machine run --image alpine"`.
        for fragment in line.split('"').skip(1).step_by(2) {
            let argv = strip_redirections(tokenize(fragment));
            if !argv.is_empty() {
                commands.push(argv);
            }
        }
    }

    commands
}

/// The `mvmctl` command path an invocation names, resolved against the real
/// command tree.
///
/// `known` is every verb path the CLI actually exposes, longest match wins.
/// Resolving rather than guessing is the point: `machine create web` is the
/// `machine create` verb with a positional machine name, and a rule that
/// stopped at the first non-flag token would read the name as part of the path.
/// Two scenarios naming different machines would then look like two different
/// commands, and the documented lifecycle would appear uncovered.
///
/// The tree is passed in rather than imported so this module stays free of the
/// CLI crate — it is a dev-dependency of the harness, not of this library.
#[must_use]
pub fn command_path_in(argv: &[String], known: &[Vec<String>]) -> Vec<String> {
    known
        .iter()
        .filter(|path| argv.len() >= path.len() && argv[..path.len()] == path[..])
        .max_by_key(|path| path.len())
        .cloned()
        .unwrap_or_default()
}

/// The flags an invocation passes to `mvmctl` itself.
///
/// Only what precedes `--`: everything after it is the guest's argv, and a
/// guest flag says nothing about which mvm code path runs. Clustered short
/// flags are split, so `-it` contributes `-i` and `-t` — otherwise a scenario
/// spelling them `-i -t` would not match an example spelling them `-it`, and
/// the two are the same request.
///
/// `--flag=value` keeps only the flag. The value varies freely between a
/// documented example and the scenario that exercises it — `--image alpine`
/// stands in for `--image python:3.12` — but the *set of flags* is the shape
/// of the request, and that is what has to be covered.
#[must_use]
pub fn flag_set(argv: &[String]) -> BTreeSet<String> {
    let mut flags = BTreeSet::new();
    for token in argv {
        if token == "--" {
            break;
        }
        let Some(body) = token.strip_prefix('-') else {
            continue;
        };
        if let Some(long) = body.strip_prefix('-') {
            if long.is_empty() {
                break;
            }
            let name = long.split('=').next().unwrap_or(long);
            flags.insert(format!("--{name}"));
            continue;
        }
        // A short cluster. `-vvv` is one repeated flag, not three distinct
        // ones, so the set collapses it naturally.
        for ch in body.chars() {
            if ch == '=' {
                break;
            }
            flags.insert(format!("-{ch}"));
        }
    }
    flags
}

/// Each flag in `argv` paired with the value it was given, if any.
///
/// [`flag_set`] deliberately discards values, because most of them vary freely
/// between a documented example and the scenario exercising it — `--image
/// alpine` stands in for `--image python:3.12` and the request shape is the
/// same. That is right for a path, a host, or a size, and wrong for a flag
/// whose value *selects what the command does*: `--source download` and
/// `--source compile` are two different operations behind one flag name, and
/// name-only matching let a scenario running the first be accepted as a
/// witness for the second.
///
/// Callers pair this with the clap tree to decide which flags are mode-like —
/// see the enum-valued check in the README contract steps — rather than
/// comparing every value and rejecting the `--image` case this exists to allow.
///
/// Handles both `--flag=value` and `--flag value`. A flag followed by another
/// flag, or ending the argv, binds to `None`.
#[must_use]
pub fn flag_bindings(argv: &[String]) -> std::collections::BTreeMap<String, Option<String>> {
    let mut out = std::collections::BTreeMap::new();
    let mut i = 0;
    while i < argv.len() {
        let token = &argv[i];
        if token == "--" {
            break;
        }
        if let Some(long) = token.strip_prefix("--") {
            if long.is_empty() {
                break;
            }
            match long.split_once('=') {
                Some((name, value)) => {
                    out.insert(format!("--{name}"), Some(value.to_string()));
                }
                None => {
                    let value = argv
                        .get(i + 1)
                        .filter(|next| !next.starts_with('-') && *next != "--")
                        .cloned();
                    out.insert(format!("--{long}"), value);
                }
            }
        } else if let Some(body) = token.strip_prefix('-')
            && !body.is_empty()
        {
            // A short cluster binds its value to the last flag in the cluster,
            // which is the only one clap would accept a value for.
            let chars: Vec<char> = body.chars().take_while(|c| *c != '=').collect();
            for (n, ch) in chars.iter().enumerate() {
                let value = if n + 1 == chars.len() {
                    argv.get(i + 1)
                        .filter(|next| !next.starts_with('-') && *next != "--")
                        .cloned()
                } else {
                    None
                };
                out.insert(format!("-{ch}"), value);
            }
        }
        i += 1;
    }
    out
}

/// The tier each documented command path is verified at.
///
/// Keyed by command path (`["machine", "run"]`), because the CLI surface is
/// finite and reviewable while the set of examples is neither. Totality is the
/// point: [`TierPolicy::tier_for`] returning `None` is a CI failure that names
/// the unclassified path, so a new verb cannot be documented without someone
/// deciding how it gets proven.
#[derive(Debug, Clone, Default)]
pub struct TierPolicy {
    tiers: BTreeMap<Vec<String>, Tier>,
}

impl TierPolicy {
    /// Build a policy from `(path, tier)` pairs.
    pub fn from_entries(entries: impl IntoIterator<Item = (Vec<String>, Tier)>) -> Self {
        Self {
            tiers: entries.into_iter().collect(),
        }
    }

    /// The tier for `path`, falling back to the longest registered prefix so a
    /// leaf inherits its group's tier unless it overrides it.
    pub fn tier_for(&self, path: &[String]) -> Option<Tier> {
        (0..=path.len())
            .rev()
            .find_map(|length| self.tiers.get(&path[..length]).copied())
    }

    /// Every registered path, for the manifest-coverage assertions.
    pub fn paths(&self) -> impl Iterator<Item = &Vec<String>> {
        self.tiers.keys()
    }
}

/// Walk the user-facing documentation set.
///
/// The website content root plus the Markdown the README links to as
/// documentation: the language-SDK READMEs, the example workloads, and the
/// contributor guide. A command is a promise wherever it is printed, so the
/// set is defined by "does a reader follow this", not by directory.
pub fn documentation_files(repo_root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for standalone in ["README.md", "AGENTS.md"] {
        let path = repo_root.join(standalone);
        if path.is_file() {
            files.push(path);
        }
    }
    for tree in ["public/src/content/docs", "crates/mvm-sdk/sdks", "examples"] {
        collect_markdown(&repo_root.join(tree), &mut files);
    }
    files.sort();
    files.dedup();
    files
}

fn collect_markdown(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "node_modules") {
                continue;
            }
            collect_markdown(&path, out);
        } else if path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| matches!(extension, "md" | "mdx"))
        {
            out.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    fn argv(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    /// Both spellings of a value bind identically, because a documented example
    /// and the scenario exercising it are free to differ in spelling.
    #[test]
    fn a_value_binds_whether_spelled_with_a_space_or_an_equals() {
        let spaced = flag_bindings(&argv("build kernel build --source download"));
        let equals = flag_bindings(&argv("build kernel build --source=download"));
        assert_eq!(spaced.get("--source"), Some(&Some("download".to_string())));
        assert_eq!(spaced, equals);
    }

    /// The distinction the whole function exists for: two invocations with an
    /// identical flag *set* that select different operations.
    #[test]
    fn two_modes_of_one_flag_are_distinguishable() {
        let download = flag_bindings(&argv(
            "build kernel build --which workload --source download",
        ));
        let compile = flag_bindings(&argv(
            "build kernel build --which workload --source compile",
        ));
        assert_ne!(download, compile);
        assert_eq!(
            download.keys().collect::<Vec<_>>(),
            compile.keys().collect::<Vec<_>>(),
            "the names are the same — only the values tell them apart, which is \
             why matching on names alone accepted one as a witness for the other"
        );
    }

    /// A flag with no value, and a flag followed by another flag, both bind to
    /// `None` rather than swallowing the next token.
    #[test]
    fn a_valueless_flag_does_not_swallow_the_next_flag() {
        let b = flag_bindings(&argv("machine run --detach --image alpine"));
        assert_eq!(b.get("--detach"), Some(&None));
        assert_eq!(b.get("--image"), Some(&Some("alpine".to_string())));
    }

    /// Everything after `--` is the guest's argv and says nothing about which
    /// mvm code path runs, so parsing stops there.
    #[test]
    fn the_guest_argv_after_the_separator_is_not_parsed() {
        let b = flag_bindings(&argv("machine run --image alpine -- sh --source compile"));
        assert!(b.contains_key("--image"));
        assert!(
            !b.contains_key("--source"),
            "a flag-looking token in the guest argv must not bind"
        );
    }

    /// A short cluster binds its value to the last flag, which is the only one
    /// clap would accept a value for.
    #[test]
    fn a_short_cluster_binds_its_value_to_the_last_flag() {
        let b = flag_bindings(&argv("machine run -it -c 2"));
        assert_eq!(b.get("-i"), Some(&None));
        assert_eq!(b.get("-t"), Some(&None));
        assert_eq!(b.get("-c"), Some(&Some("2".to_string())));
    }

    use super::*;

    fn examples(body: &str) -> Vec<DocExample> {
        doc_examples("doc.md", body)
    }

    #[test]
    fn extracts_a_plain_invocation_with_its_line() {
        let found = examples("intro\n\n```bash\nmvmctl doctor\n```\n");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].argv, vec!["doctor"]);
        assert_eq!(found[0].line, 4);
        assert_eq!(found[0].location(), "doc.md:4");
    }

    #[test]
    fn folds_backslash_continuations_into_one_command() {
        let found =
            examples("```bash\nmvmctl machine run \\\n  --image alpine \\\n  -- echo hi\n```\n");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].argv,
            vec!["machine", "run", "--image", "alpine", "--", "echo", "hi"]
        );
    }

    #[test]
    fn splits_compound_commands_on_shell_operators() {
        let found = examples("```bash\nmvmctl machine stop web && mvmctl machine rm web\n```\n");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].argv, vec!["machine", "stop", "web"]);
        assert_eq!(found[1].argv, vec!["machine", "rm", "web"]);
    }

    #[test]
    fn ignores_mvmctl_used_as_a_path_argument() {
        let found = examples("```bash\ncp target/release/mvmctl ~/.local/bin/\n```\n");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn ignores_the_binary_named_as_an_install_argument() {
        // `cargo install mvmctl` mentions the binary; it does not run it.
        assert!(examples("```bash\ncargo install mvmctl\n```\n").is_empty());
    }

    #[test]
    fn steps_over_leading_environment_assignments() {
        let found = examples("```bash\nMVM_PHASE_TIMING=1 mvmctl doctor\n```\n");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].argv, vec!["doctor"]);
    }

    #[test]
    fn steps_over_a_sudo_wrapper() {
        let found = examples("```bash\nsudo mvmctl doctor\n```\n");
        assert_eq!(found[0].argv, vec!["doctor"]);
    }

    #[test]
    fn ignores_a_segment_whose_command_word_is_another_program() {
        assert!(examples("```bash\nwhich mvmctl\n```\n").is_empty());
        assert!(examples("```bash\nls -l /usr/bin/mvmctl\n```\n").is_empty());
    }

    #[test]
    fn a_pipeline_only_yields_its_mvmctl_segments() {
        let found = examples("```bash\nmvmctl machine ls --json | jq .\n```\n");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].argv, vec!["machine", "ls", "--json"]);
    }

    #[test]
    fn ignores_commented_out_lines() {
        let found = examples("```bash\n# mvmctl doctor\nmvmctl bootstrap\n```\n");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].argv, vec!["bootstrap"]);
    }

    #[test]
    fn strips_a_trailing_inline_comment() {
        let found = examples("```bash\nmvmctl machine ls   # list them\n```\n");
        assert_eq!(found[0].argv, vec!["machine", "ls"]);
    }

    #[test]
    fn keeps_quoted_arguments_as_single_tokens() {
        let found =
            examples("```bash\nmvmctl machine run --image alpine -- sh -c \"echo a b\"\n```\n");
        assert_eq!(found[0].argv.last().unwrap(), "echo a b");
    }

    #[test]
    fn a_pipe_inside_quotes_does_not_split_the_command() {
        let found =
            examples("```bash\nmvmctl machine run --image alpine -- sh -c \"a | b\"\n```\n");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn extracts_a_command_from_an_inline_code_span() {
        let found = inline_code_examples("d.md", "| `mvmctl machine ls` | list them |\n");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].argv, vec!["machine", "ls"]);
        assert_eq!(found[0].line, 1);
    }

    #[test]
    fn inline_spans_inside_a_fence_are_left_to_the_fence_walker() {
        let doc = "```bash\nmvmctl doctor\n```\n";
        assert!(inline_code_examples("d.md", doc).is_empty());
    }

    #[test]
    fn an_inline_span_that_only_names_the_binary_is_not_a_command() {
        assert!(inline_code_examples("d.md", "install `mvmctl` first\n").is_empty());
    }

    #[test]
    fn an_inline_span_for_another_binary_is_ignored() {
        assert!(inline_code_examples("d.md", "run `mvmctld serve` now\n").is_empty());
    }

    #[test]
    fn ignores_non_shell_fences() {
        let found = examples("```python\nmvmctl = 1\n```\n");
        assert!(found.is_empty());
    }

    #[test]
    fn strips_a_shell_prompt() {
        let found = examples("```console\n$ mvmctl doctor\n```\n");
        assert_eq!(found[0].argv, vec!["doctor"]);
    }

    #[test]
    fn a_template_still_exposes_its_concrete_verb_prefix() {
        let found = examples("```bash\nmvmctl manifest pull <CHANNEL> <DIR>\n```\n");
        assert_eq!(
            found[0].concrete_prefix(),
            vec!["manifest".to_string(), "pull".to_string()]
        );
    }

    #[test]
    fn a_template_prefix_stops_at_the_first_flag() {
        let found = examples("```bash\nmvmctl machine run --image <REF>\n```\n");
        assert_eq!(
            found[0].concrete_prefix(),
            vec!["machine".to_string(), "run".to_string()]
        );
    }

    #[test]
    fn strips_a_separated_output_redirection() {
        let found = examples("```bash\nmvmctl doctor --json > doctor.json\n```\n");
        assert_eq!(found[0].argv, vec!["doctor", "--json"]);
    }

    #[test]
    fn strips_an_attached_fd_redirection() {
        let found = examples("```bash\nmvmctl machine logs vm -f 2>/dev/null\n```\n");
        assert_eq!(found[0].argv, vec!["machine", "logs", "vm", "-f"]);
    }

    #[test]
    fn strips_an_input_redirection() {
        let found = examples("```bash\nmvmctl machine fs write vm /a.py < /tmp/in.py\n```\n");
        assert_eq!(found[0].argv, vec!["machine", "fs", "write", "vm", "/a.py"]);
    }

    #[test]
    fn keeps_a_stderr_to_stdout_redirect_out_of_argv_without_splitting() {
        let found = examples("```bash\nmvmctl doctor 2>&1\n```\n");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].argv, vec!["doctor"]);
    }

    #[test]
    fn a_shell_redirect_is_not_a_placeholder() {
        let found =
            examples("```bash\nmvmctl machine fs write vm /work/main.py < /tmp/in.py\n```\n");
        assert_eq!(found.len(), 1);
        assert!(
            !found[0].is_template(),
            "a redirect made this look like a template: {:?}",
            found[0].argv
        );
    }

    #[test]
    fn slash_alternation_names_a_family_not_a_command() {
        let found = inline_code_examples("d.md", "see `mvmctl machine pause/resume`\n");
        assert!(found[0].is_template(), "{:?}", found[0].argv);
    }

    #[test]
    fn a_wildcard_names_a_family_not_a_command() {
        let found = inline_code_examples("d.md", "see `mvmctl manifest *`\n");
        assert!(found[0].is_template());
    }

    #[test]
    fn a_path_argument_is_not_alternation_notation() {
        let found = examples("```bash\nmvmctl machine run --mount /work/app:/w -- ls\n```\n");
        assert!(!found[0].is_template(), "{:?}", found[0].argv);
    }

    #[test]
    fn a_bracketed_optional_argument_is_a_placeholder() {
        let found = examples("```bash\nmvmctl manifest push [PATH]\n```\n");
        assert!(found[0].is_template());
    }

    #[test]
    fn a_placeholder_invocation_is_a_template() {
        let found = examples("```bash\nmvmctl <command> --help\n```\n");
        assert!(found[0].is_template());
    }

    #[test]
    fn code_blocks_ignore_the_info_string_beyond_the_language() {
        let blocks = code_blocks("doc.md", "```nix \"mkGuest\"\n{}\n```\n");
        assert_eq!(blocks[0].language, "nix");
    }

    #[test]
    fn a_command_stranded_outside_a_fence_is_reported() {
        // A fence closed one block early: the command below renders as prose
        // and disappears from extraction.
        let doc = "```bash\nmvmctl doctor\n```\n\nmvmctl machine run --flake .\n";
        let verbs = vec!["machine".to_string(), "doctor".to_string()];
        let stranded = mvmctl_lines_outside_fences(doc, &verbs);
        assert_eq!(stranded.len(), 1);
        assert_eq!(stranded[0].0, 5);
        assert!(stranded[0].1.starts_with("mvmctl machine run"));
    }

    #[test]
    fn a_command_inside_a_fence_is_not_stranded() {
        let verbs = vec!["doctor".to_string()];
        assert!(mvmctl_lines_outside_fences("```bash\nmvmctl doctor\n```\n", &verbs).is_empty());
    }

    #[test]
    fn prose_opening_with_the_binary_name_is_not_a_stranded_command() {
        let verbs = vec!["machine".to_string(), "build".to_string()];
        let doc = "mvmctl uses Nix flakes to produce reproducible images.\n";
        assert!(mvmctl_lines_outside_fences(doc, &verbs).is_empty());
    }

    #[test]
    fn an_unterminated_fence_is_detected() {
        assert!(has_unterminated_fence("```bash\nmvmctl doctor\n"));
        assert!(!has_unterminated_fence("```bash\nmvmctl doctor\n```\n"));
    }

    #[test]
    fn live_commands_come_only_from_live_tagged_scenarios() {
        let feature = concat!(
            "Feature: F\n",
            "  @live\n",
            "  Scenario: booted\n",
            "    When I run mvmctl with \"machine run --image alpine\"\n",
            "  Scenario: hermetic\n",
            "    When I run mvmctl with \"machine ls\"\n",
        );
        let found = live_scenario_commands(feature);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0][..2], ["machine".to_string(), "run".to_string()]);
    }

    #[test]
    fn a_feature_level_live_tag_covers_every_scenario() {
        let feature = concat!(
            "@live\n",
            "Feature: F\n",
            "  Scenario: one\n",
            "    When I run mvmctl with \"machine build --flake .\"\n",
        );
        assert_eq!(live_scenario_commands(feature).len(), 1);
    }

    #[test]
    fn mk_guest_parameters_come_from_the_argument_set() {
        let source = concat!(
            "# a comment\n",
            "{ name\n",
            ", entrypoint\n",
            ", packages       ? [ ]\n",
            ", vcpus          ? 1\n",
            "}:\n",
            "let unrelated = 1; in unrelated\n",
        );
        let names = mk_guest_parameters(source);
        assert!(names.contains("name"));
        assert!(names.contains("entrypoint"));
        assert!(names.contains("packages"));
        assert!(names.contains("vcpus"));
        assert!(
            !names.contains("unrelated"),
            "the walk ran past the argument set: {names:?}"
        );
    }

    #[test]
    fn mk_guest_call_attributes_collapse_dotted_paths() {
        let body = concat!(
            "packages.default = mvm.lib.mkGuest {\n",
            "  inherit pkgs;\n",
            "  name = \"my-app\";\n",
            "  entrypoint.command = [ \"/bin/x\" ];\n",
            "};\n",
        );
        let found: Vec<String> = mk_guest_call_attributes(body)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert!(found.contains(&"pkgs".to_string()), "{found:?}");
        assert!(found.contains(&"name".to_string()), "{found:?}");
        assert!(found.contains(&"entrypoint".to_string()), "{found:?}");
        assert!(
            !found.contains(&"command".to_string()),
            "a dotted path leaked its tail: {found:?}"
        );
    }

    #[test]
    fn mk_guest_call_attributes_ignore_words_in_comments_and_strings() {
        let body = concat!(
            "mvm.lib.mkGuest {\n",
            "  name = \"my-app\";\n",
            "  dev = true;   # explicit override; auto-infer is false here\n",
            "  entrypoint.command = [ \"/bin/sh\" \"-c\" \"per-service thing\" ];\n",
            "}\n",
        );
        let found: Vec<String> = mk_guest_call_attributes(body)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        for prose in ["auto", "per", "explicit", "service"] {
            assert!(
                !found.contains(&prose.to_string()),
                "read {prose:?} out of a comment or string: {found:?}"
            );
        }
        assert!(found.contains(&"dev".to_string()), "{found:?}");
    }

    #[test]
    fn mk_guest_call_attributes_ignore_nested_attribute_sets() {
        let body = concat!(
            "mvm.lib.mkGuest {\n",
            "  name = \"x\";\n",
            "  entrypoint.services.web = { exec = \"run\"; };\n",
            "}\n",
        );
        let found: Vec<String> = mk_guest_call_attributes(body)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert!(
            !found.contains(&"exec".to_string()),
            "a nested attribute leaked to the top level: {found:?}"
        );
    }

    #[test]
    fn an_ellipsis_line_marks_an_excerpt() {
        assert!(is_elided("fn a() {\n  ...\n}\n"));
        assert!(is_elided("let x = 1; // …\n"));
    }

    #[test]
    fn spread_and_rest_syntax_are_not_elisions() {
        assert!(
            !is_elided("const b = { ...a, c: 1 };\n"),
            "an object spread was read as an elision"
        );
        assert!(
            !is_elided("function f(...args: string[]) {}\n"),
            "a rest parameter was read as an elision"
        );
    }

    #[test]
    fn tier_lookup_falls_back_to_the_longest_registered_prefix() {
        let policy = TierPolicy::from_entries([
            (vec!["machine".to_string()], Tier::Parse),
            (vec!["machine".to_string(), "ls".to_string()], Tier::Exec),
        ]);
        let path = |parts: &[&str]| parts.iter().map(|p| p.to_string()).collect::<Vec<_>>();
        assert_eq!(policy.tier_for(&path(&["machine", "ls"])), Some(Tier::Exec));
        assert_eq!(
            policy.tier_for(&path(&["machine", "run"])),
            Some(Tier::Parse)
        );
        assert_eq!(policy.tier_for(&path(&["doctor"])), None);
    }

    #[test]
    fn tier_spellings_round_trip_and_reject_typos() {
        for tier in [Tier::Parse, Tier::Exec, Tier::Live] {
            assert_eq!(tier.as_str().parse(), Ok(tier));
        }
        assert!("execute".parse::<Tier>().is_err());
    }
}

#[cfg(test)]
mod corpus_tests {
    use super::*;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
    }

    /// The extractor must keep seeing the documentation set. A silent drop to
    /// zero (a moved content root, a fence-parsing regression) would make every
    /// downstream "all examples pass" assertion vacuously true.
    #[test]
    fn the_documentation_corpus_is_not_empty() {
        let files = documentation_files(&repo_root());
        assert!(files.len() > 50, "only found {} doc files", files.len());
        let total: usize = files
            .iter()
            .map(|path| {
                let body = std::fs::read_to_string(path).unwrap_or_default();
                doc_examples(&path.display().to_string(), &body).len()
            })
            .sum();
        assert!(total > 200, "only extracted {total} mvmctl examples");
    }

    #[test]
    fn dependency_markdown_is_not_part_of_the_documentation_corpus() {
        let root = tempfile::tempdir().expect("create documentation fixture");
        let sdk = root.path().join("crates/mvm-sdk/sdks/typescript");
        let dependency = sdk.join("node_modules/dependency");
        std::fs::create_dir_all(&dependency).expect("create dependency fixture");
        std::fs::write(sdk.join("README.md"), "# SDK\n").expect("write SDK documentation");
        std::fs::write(dependency.join("README.md"), "# Dependency\n")
            .expect("write dependency documentation");

        let files = documentation_files(root.path());

        assert_eq!(files, vec![sdk.join("README.md")]);
    }

    #[test]
    fn dump_corpus() {
        if std::env::var_os("MVM_DUMP_CORPUS").is_none() {
            return;
        }
        let root = repo_root();
        for path in documentation_files(&root) {
            let rel = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .display()
                .to_string();
            let body = std::fs::read_to_string(&path).unwrap_or_default();
            if has_unterminated_fence(&body) {
                println!("UNTERMINATED-FENCE {rel}");
            }
            for example in doc_examples(&rel, &body) {
                println!("{}\t{}", example.location(), example.argv.join(" "));
            }
        }
    }
}

/// Whether a code block is abbreviated rather than complete.
///
/// Docs elide the uninteresting middle of an example, with a `…` or a line
/// holding nothing but `...`. Such a block is a excerpt, not a program: it
/// cannot compile or typecheck, and demanding that it does would push authors
/// toward opting out entirely.
///
/// Only a line that is *solely* dots counts. `...` is legal syntax — a spread
/// or a rest parameter — so a blanket substring test would silently drop real
/// examples from checking.
pub fn is_elided(body: &str) -> bool {
    body.contains('…')
        || body
            .lines()
            .any(|line| !line.trim().is_empty() && line.trim().chars().all(|c| c == '.'))
}

/// The attribute names `mkGuest` accepts, read from its Nix argument set.
///
/// The docs teach `mkGuest` as the Nix authoring surface, so a renamed or
/// removed attribute is drift of exactly the kind the Rust compiler and the
/// SDK checkers catch elsewhere. Evaluating Nix would need a `nix` binary the
/// hermetic lane does not have; the argument set is a flat `{ a, b ? x, ... }`
/// header, which is readable without one.
pub fn mk_guest_parameters(source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut started = false;

    for line in source.lines() {
        let trimmed = line.trim_start();
        // The header opens with `{ name` and closes with `}:`.
        if !started {
            if trimmed.starts_with("{ name") {
                started = true;
            } else {
                continue;
            }
        } else if trimmed.starts_with("}:") {
            break;
        }
        let candidate = trimmed.trim_start_matches(['{', ',']).trim_start();
        let name: String = candidate
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            names.insert(name);
        }
    }

    names
}

/// The top-level attributes a documented `mkGuest { … }` call passes, with the
/// line offset of each within the block.
///
/// Dotted paths collapse to their head (`entrypoint.command` is `entrypoint`),
/// and `inherit` brings names in without an `=`, so both are handled.
pub fn mk_guest_call_attributes(body: &str) -> Vec<(String, usize)> {
    let Some(start) = body.find("mkGuest") else {
        return Vec::new();
    };
    let Some(open) = body[start..].find('{').map(|offset| start + offset) else {
        return Vec::new();
    };

    let mut attributes = Vec::new();
    let mut depth = 0usize;
    let mut line = body[..open].lines().count();
    let mut at_item_start = false;

    let bytes = body.as_bytes();
    let mut index = open;
    while index < body.len() {
        let character = bytes[index] as char;
        // A `#` comment runs to end of line, and a string can hold anything;
        // words inside either are prose, not attributes.
        if character == '#' {
            let end = body[index..]
                .find('\n')
                .map_or(body.len(), |offset| index + offset);
            index = end;
            continue;
        }
        if character == '"' {
            let mut cursor = index + 1;
            while cursor < body.len() {
                let inner = bytes[cursor] as char;
                if inner == '\\' {
                    cursor += 2;
                    continue;
                }
                if inner == '"' {
                    break;
                }
                if inner == '\n' {
                    line += 1;
                }
                cursor += 1;
            }
            index = cursor + 1;
            at_item_start = false;
            continue;
        }
        match character {
            '\n' => {
                line += 1;
                at_item_start = true;
            }
            '{' => {
                depth += 1;
                at_item_start = true;
            }
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
                at_item_start = true;
            }
            ';' => at_item_start = true,
            c if c.is_whitespace() => {}
            _ => {
                if depth == 1 && at_item_start {
                    let rest = &body[index..];
                    let word: String = rest
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    if !word.is_empty() {
                        // `inherit pkgs;` names come in without an `=`.
                        if word == "inherit" {
                            for inherited in rest[..rest.find(';').unwrap_or(rest.len())]
                                .split_whitespace()
                                .skip(1)
                            {
                                let clean: String = inherited
                                    .chars()
                                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                                    .collect();
                                if !clean.is_empty() {
                                    attributes.push((clean, line));
                                }
                            }
                        } else {
                            attributes.push((word.clone(), line));
                        }
                        index += word.len();
                        at_item_start = false;
                        continue;
                    }
                }
                at_item_start = false;
            }
        }
        index += 1;
    }

    attributes
}
