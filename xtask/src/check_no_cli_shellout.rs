//! `xtask check-no-cli-shellout`
//!
//! The SDKs drive machines in-process, through `libmvm_hostlib`. They never
//! run `mvmctl`: not once per call, not through a long-lived helper, and not
//! as a fallback when the library is missing. A CLI shell-out is a second
//! entrypoint to every verb, it cannot stream, and it costs a process per
//! call, and it was the design for long enough that it will come back the
//! moment something is inconvenient. Prose does not hold that line; this does.
//!
//! The rule is broader than "do not name `mvmctl`": SDK source may not reach
//! for any process API at all, and may not resolve the CLI in order to run
//! it. Banning only the literal would be beaten by the first `which`-then-run
//! helper. Concretely, outside comments:
//!
//! - Python (`crates/mvm-sdk/sdks/python/mvm`): `subprocess`, the `os`
//!   process calls (`system`, `popen`, `spawn*`, `exec*`, `posix_spawn*`,
//!   `fork*`), `Popen`, `asyncio`'s `create_subprocess_*`, `pty`, and
//!   `multiprocessing`.
//! - TypeScript (`crates/mvm-sdk/sdks/typescript/src`): `child_process`,
//!   `spawn`/`spawnSync`, `exec*Sync`/`execFile`, `fork`, and the `Bun`/`Deno`
//!   process APIs.
//! - Rust (`crates/mvm-sdk/src`, `crates/mvm-hostlib/src`): `process::Command`
//!   and the `libc` spawn and exec calls. The host library's own runtime
//!   spawns per-VM helpers from inside `mvm-client`, which is not scanned
//!   here; the library itself declares the process a library embedder, so
//!   any runtime path that would spawn `mvmctl` refuses.
//! - Every surface: the CLI-location overrides `MVM_CLI_BIN` and
//!   `MVM_MVM_BIN`, and the `resolve_cli_bin`/`resolveCliBin` helpers that
//!   located the CLI to execute it.
//!
//! Locating the installed bundle directory to load the library from is not
//! execution and is not flagged: the loaders look beside `mvmctl` on `PATH`
//! for `libmvm_hostlib`, and never run the binary they find.
//!
//! Comments are stripped before matching so an explanation of the rule can
//! name what it forbids. Strings are not: `require("child_process")` is a
//! use. There is no exemption marker; a root that is missing or holds no
//! source fails the gate rather than passing an empty scan.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use regex::Regex;

/// How a surface writes comments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lang {
    /// `#` line comments; `'`, `"` and triple-quoted strings.
    Python,
    /// `//` and `/* */` comments; `'`, `"` and backtick strings.
    Script,
    /// `//` and nested `/* */` comments; `"` strings.
    Rust,
}

/// One scanned tree: a root, the file extensions that are source there, and
/// how those files write comments.
struct Surface {
    root: &'static str,
    extensions: &'static [&'static str],
    lang: Lang,
}

/// Every tree the rule holds for.
const SURFACES: &[Surface] = &[
    Surface {
        root: "crates/mvm-sdk/sdks/python/mvm",
        extensions: &["py"],
        lang: Lang::Python,
    },
    Surface {
        root: "crates/mvm-sdk/sdks/typescript/src",
        extensions: &["ts", "mts", "cts", "js", "mjs", "cjs"],
        lang: Lang::Script,
    },
    Surface {
        root: "crates/mvm-sdk/src",
        extensions: &["rs"],
        lang: Lang::Rust,
    },
    Surface {
        root: "crates/mvm-hostlib/src",
        extensions: &["rs"],
        lang: Lang::Rust,
    },
];

/// Build output and dependency trees are never ours to police.
const SKIP_DIRS: &[&str] = &["node_modules", "dist", "target", "__pycache__", ".venv"];

/// A forbidden construct: the pattern, and what to tell the author.
struct Needle {
    pattern: &'static str,
    why: &'static str,
}

const EVERY_SURFACE: &[Needle] = &[
    Needle {
        pattern: r"\bMVM_CLI_BIN\b",
        why: "names the CLI binary to execute",
    },
    Needle {
        pattern: r"\bMVM_MVM_BIN\b",
        why: "names the CLI binary to execute",
    },
    Needle {
        pattern: r"\bresolve_cli_bin\b|\bresolveCliBin\b",
        why: "resolves the CLI in order to run it",
    },
];

const PYTHON: &[Needle] = &[
    Needle {
        pattern: r"\bimport\s+subprocess\b|\bfrom\s+subprocess\s+import\b|\bsubprocess\s*\.",
        why: "spawns a process",
    },
    Needle {
        pattern: r"\bos\s*\.\s*(system|popen|spawn\w*|exec\w*|posix_spawn\w*|fork\w*)\s*\(",
        why: "spawns a process",
    },
    Needle {
        pattern: r"\bfrom\s+os\s+import\s+[^\n]*\b(system|popen|spawn\w*|exec\w*|posix_spawn\w*|fork\w*)\b",
        why: "imports an os process call",
    },
    Needle {
        pattern: r"\bPopen\b",
        why: "spawns a process",
    },
    Needle {
        pattern: r"\bcreate_subprocess_(exec|shell)\b",
        why: "spawns a process",
    },
    Needle {
        pattern: r"\bimport\s+pty\b|\bfrom\s+pty\s+import\b|\bpty\s*\.\s*spawn\b",
        why: "spawns a process on a pseudo-terminal",
    },
    Needle {
        pattern: r"\bimport\s+multiprocessing\b|\bfrom\s+multiprocessing\b",
        why: "spawns interpreter processes",
    },
];

const SCRIPT: &[Needle] = &[
    Needle {
        pattern: r"child_process",
        why: "loads Node's process API",
    },
    Needle {
        pattern: r"\bspawnSync\b|\bspawn\s*\(",
        why: "spawns a process",
    },
    Needle {
        pattern: r"\bexecFile(Sync)?\b|\bexecSync\b",
        why: "spawns a process",
    },
    Needle {
        pattern: r"\bfork\s*\(",
        why: "spawns a process",
    },
    Needle {
        pattern: r"\bBun\s*\.\s*spawn(Sync)?\b|\bDeno\s*\.\s*(Command|run)\b",
        why: "spawns a process",
    },
];

const RUST: &[Needle] = &[
    Needle {
        pattern: r"\bprocess::Command\b|\bCommand::new\b",
        why: "spawns a process",
    },
    Needle {
        pattern: r"\blibc::(fork|vfork|execv\w*|execl\w*|posix_spawn\w*|system)\b",
        why: "spawns or replaces a process",
    },
];

fn needles_for(lang: Lang) -> &'static [Needle] {
    match lang {
        Lang::Python => PYTHON,
        Lang::Script => SCRIPT,
        Lang::Rust => RUST,
    }
}

/// The compiled patterns for `lang`, then the ones every surface shares.
fn compiled(lang: Lang) -> &'static [(Regex, &'static str)] {
    static PY: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    static TS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    static RS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    let cell = match lang {
        Lang::Python => &PY,
        Lang::Script => &TS,
        Lang::Rust => &RS,
    };
    cell.get_or_init(|| {
        needles_for(lang)
            .iter()
            .chain(EVERY_SURFACE)
            .map(|n| {
                (
                    Regex::new(n.pattern).expect("every needle is a valid pattern"),
                    n.why,
                )
            })
            .collect()
    })
}

/// One forbidden use.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Finding {
    path: PathBuf,
    line: usize,
    matched: String,
    why: &'static str,
}

pub fn run(workspace: &Path) -> Result<()> {
    let mut findings = Vec::new();
    for surface in SURFACES {
        findings.extend(scan_surface(workspace, surface)?);
    }
    if findings.is_empty() {
        println!(
            "check-no-cli-shellout: clean — no SDK source spawns a process or resolves the CLI"
        );
        return Ok(());
    }
    let listing = findings
        .iter()
        .map(|f| {
            format!(
                "  {}:{}: `{}` {}",
                f.path.strip_prefix(workspace).unwrap_or(&f.path).display(),
                f.line,
                f.matched,
                f.why
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    bail!(
        "check-no-cli-shellout: {} forbidden use(s) in SDK source:\n{listing}\n\n\
         The SDKs drive machines through libmvm_hostlib, in-process. Call the \
         host library (`_hostlib.call` / `call`) instead; if it lacks the \
         method, add the method to crates/mvm-hostlib. There is no exemption.",
        findings.len()
    )
}

/// Scan one surface, refusing a root that is missing or holds no source.
fn scan_surface(workspace: &Path, surface: &Surface) -> Result<Vec<Finding>> {
    let root = workspace.join(surface.root);
    if !root.is_dir() {
        bail!(
            "check-no-cli-shellout: {} does not exist; a gate that scans nothing passes forever",
            surface.root
        );
    }
    let mut files = Vec::new();
    collect(&root, surface.extensions, &mut files)?;
    if files.is_empty() {
        bail!(
            "check-no-cli-shellout: {} holds no {:?} source; a gate that scans nothing passes forever",
            surface.root,
            surface.extensions
        );
    }
    files.sort();
    let mut findings = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        findings.extend(scan_text(&path, &text, surface.lang));
    }
    Ok(findings)
}

fn collect(dir: &Path, extensions: &[&str], out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            let skipped = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| SKIP_DIRS.contains(&n));
            if !skipped {
                collect(&path, extensions, out)?;
            }
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| extensions.contains(&e))
        {
            out.push(path);
        }
    }
    Ok(())
}

/// Every forbidden use in `text`, with comments removed first.
fn scan_text(path: &Path, text: &str, lang: Lang) -> Vec<Finding> {
    let code = strip_comments(text, lang);
    let mut findings = Vec::new();
    for (index, line) in code.lines().enumerate() {
        for (pattern, why) in compiled(lang) {
            if let Some(m) = pattern.find(line) {
                findings.push(Finding {
                    path: path.to_path_buf(),
                    line: index + 1,
                    matched: m.as_str().to_string(),
                    why,
                });
            }
        }
    }
    findings
}

/// `text` with every comment replaced by nothing, keeping line breaks so
/// findings report the original line numbers. Strings are kept verbatim.
fn strip_comments(text: &str, lang: Lang) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut block_depth = 0_usize;
    let mut quote: Option<Quote> = None;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if block_depth > 0 {
            if c == '*' && next == Some('/') {
                block_depth -= 1;
                i += 2;
            } else if lang == Lang::Rust && c == '/' && next == Some('*') {
                block_depth += 1;
                i += 2;
            } else {
                if c == '\n' {
                    out.push('\n');
                }
                i += 1;
            }
            continue;
        }
        if let Some(q) = quote {
            if c == '\\' {
                out.push(c);
                if let Some(n) = next {
                    out.push(n);
                }
                i += 2;
                continue;
            }
            if q.closes_at(&chars, i) {
                for _ in 0..q.width {
                    out.push(q.delim);
                }
                i += q.width;
                quote = None;
                continue;
            }
            out.push(c);
            i += 1;
            continue;
        }
        match lang {
            Lang::Python if c == '#' => {
                i = skip_to_line_end(&chars, i);
                continue;
            }
            Lang::Script | Lang::Rust if c == '/' && next == Some('/') => {
                i = skip_to_line_end(&chars, i);
                continue;
            }
            Lang::Script | Lang::Rust if c == '/' && next == Some('*') => {
                block_depth = 1;
                i += 2;
                continue;
            }
            _ => {}
        }
        if let Some(q) = Quote::opening(&chars, i, lang) {
            for _ in 0..q.width {
                out.push(q.delim);
            }
            i += q.width;
            quote = Some(q);
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

fn skip_to_line_end(chars: &[char], mut i: usize) -> usize {
    while i < chars.len() && chars[i] != '\n' {
        i += 1;
    }
    i
}

/// An open string literal: its delimiter and how many of them open and close
/// it (three for a Python triple-quoted string).
#[derive(Debug, Clone, Copy)]
struct Quote {
    delim: char,
    width: usize,
}

impl Quote {
    fn opening(chars: &[char], i: usize, lang: Lang) -> Option<Self> {
        let c = chars[i];
        let delims: &[char] = match lang {
            Lang::Python => &['"', '\''],
            Lang::Script => &['"', '\'', '`'],
            // A Rust `'` is a char literal or a lifetime; only `"` opens a
            // string that could hold a comment marker.
            Lang::Rust => &['"'],
        };
        if !delims.contains(&c) {
            return None;
        }
        let triple =
            lang == Lang::Python && chars.get(i + 1) == Some(&c) && chars.get(i + 2) == Some(&c);
        Some(Self {
            delim: c,
            width: if triple { 3 } else { 1 },
        })
    }

    fn closes_at(self, chars: &[char], i: usize) -> bool {
        (0..self.width).all(|k| chars.get(i + k) == Some(&self.delim))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A workspace holding one clean file per surface, so a test changes only
    /// the file it is about.
    fn clean_workspace() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let files = [
            (
                "crates/mvm-sdk/sdks/python/mvm/_sandbox.py",
                "from mvm import _hostlib\n\ndef run():\n    return _hostlib.call(\"machine.run\", {})\n",
            ),
            (
                "crates/mvm-sdk/sdks/typescript/src/_sandbox.ts",
                "import { call } from \"./_hostlib.js\";\nexport const run = () => call(\"machine.run\", {});\n",
            ),
            ("crates/mvm-sdk/src/lib.rs", "pub fn f() {}\n"),
            ("crates/mvm-hostlib/src/lib.rs", "pub fn g() {}\n"),
        ];
        for (path, body) in files {
            write(tmp.path(), path, body);
        }
        tmp
    }

    fn write(root: &Path, path: &str, body: &str) {
        let full = root.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, body).unwrap();
    }

    fn failure(root: &Path) -> String {
        format!("{:#}", run(root).expect_err("the gate must fail"))
    }

    #[test]
    fn a_workspace_that_only_calls_the_library_passes() {
        let tmp = clean_workspace();
        run(tmp.path()).expect("clean");
    }

    #[test]
    fn python_subprocess_running_mvmctl_is_flagged() {
        let tmp = clean_workspace();
        write(
            tmp.path(),
            "crates/mvm-sdk/sdks/python/mvm/_machine.py",
            "import subprocess\n\ndef ls():\n    subprocess.run([\"mvmctl\", \"machine\", \"ls\"])\n",
        );
        let message = failure(tmp.path());
        assert!(message.contains("_machine.py:1"), "{message}");
        assert!(message.contains("_machine.py:4"), "{message}");
    }

    #[test]
    fn every_python_process_api_is_flagged() {
        for body in [
            "import os\nos.system('mvmctl machine ls')\n",
            "import os\nos.execvp('mvmctl', ['mvmctl'])\n",
            "from os import posix_spawn\n",
            "from subprocess import Popen\n",
            "p = Popen(['mvmctl'])\n",
            "import asyncio\nasyncio.create_subprocess_exec('mvmctl')\n",
            "import pty\n",
            "import multiprocessing\n",
        ] {
            let tmp = clean_workspace();
            write(tmp.path(), "crates/mvm-sdk/sdks/python/mvm/_bad.py", body);
            assert!(run(tmp.path()).is_err(), "not flagged: {body}");
        }
    }

    #[test]
    fn node_child_process_is_flagged_as_import_and_as_require() {
        for body in [
            "import * as child from \"node:child_process\";\n",
            "const cp = require('child_process');\n",
            "const r = spawnSync(bin, argv);\n",
            "execFile(bin, argv, () => {});\n",
            "const out = execSync(\"mvmctl machine ls\");\n",
            "fork(\"./worker.js\");\n",
            "Bun.spawn([\"mvmctl\"]);\n",
            "new Deno.Command(\"mvmctl\");\n",
        ] {
            let tmp = clean_workspace();
            write(
                tmp.path(),
                "crates/mvm-sdk/sdks/typescript/src/_bad.ts",
                body,
            );
            assert!(run(tmp.path()).is_err(), "not flagged: {body}");
        }
    }

    #[test]
    fn resolving_the_cli_to_run_it_is_flagged_on_every_surface() {
        for (path, body) in [
            (
                "crates/mvm-sdk/sdks/python/mvm/_cli.py",
                "bin = os.environ.get(\"MVM_CLI_BIN\")\n",
            ),
            (
                "crates/mvm-sdk/sdks/python/mvm/_cli.py",
                "bin = resolve_cli_bin(purpose=\"x\")\n",
            ),
            (
                "crates/mvm-sdk/sdks/typescript/src/_cli.ts",
                "const bin = resolveCliBin(\"x\");\n",
            ),
            (
                "crates/mvm-sdk/src/facade.rs",
                "const ENV: &str = \"MVM_CLI_BIN\";\n",
            ),
        ] {
            let tmp = clean_workspace();
            write(tmp.path(), path, body);
            assert!(run(tmp.path()).is_err(), "not flagged: {path}: {body}");
        }
    }

    #[test]
    fn rust_process_spawning_is_flagged_in_the_sdk_and_the_library() {
        for path in [
            "crates/mvm-sdk/src/machine.rs",
            "crates/mvm-hostlib/src/x.rs",
        ] {
            let tmp = clean_workspace();
            write(
                tmp.path(),
                path,
                "use std::process::Command;\nfn f() { Command::new(\"mvmctl\"); }\n",
            );
            assert!(run(tmp.path()).is_err(), "not flagged: {path}");
        }
        let tmp = clean_workspace();
        write(
            tmp.path(),
            "crates/mvm-hostlib/src/x.rs",
            "fn f() { unsafe { libc::fork(); } }\n",
        );
        assert!(run(tmp.path()).is_err());
    }

    /// A comment may explain the rule; only code is held to it.
    #[test]
    fn comments_naming_the_forbidden_apis_pass() {
        let tmp = clean_workspace();
        write(
            tmp.path(),
            "crates/mvm-sdk/sdks/python/mvm/_notes.py",
            "# the old transport used subprocess.run and MVM_CLI_BIN\nx = 1  # never Popen\n",
        );
        write(
            tmp.path(),
            "crates/mvm-sdk/sdks/typescript/src/_notes.ts",
            "// no child_process here\n/* spawnSync( and\n   execFile( were the old way */\nexport const x = 1;\n",
        );
        write(
            tmp.path(),
            "crates/mvm-hostlib/src/notes.rs",
            "//! Never `std::process::Command::new(\"mvmctl\")`.\n/* nested /* Command::new */ still a comment */\npub fn h() {}\n",
        );
        run(tmp.path()).expect("comments are not code");
    }

    /// Strings are code: a forbidden module named in a string is a use, and a
    /// comment marker inside a string does not hide what follows it.
    #[test]
    fn strings_are_scanned_and_do_not_open_comments() {
        let tmp = clean_workspace();
        write(
            tmp.path(),
            "crates/mvm-sdk/sdks/typescript/src/_bad.ts",
            "const url = \"http://example\"; const cp = require(\"child_process\");\n",
        );
        assert!(run(tmp.path()).is_err());

        let tmp = clean_workspace();
        write(
            tmp.path(),
            "crates/mvm-sdk/sdks/python/mvm/_bad.py",
            "tag = \"#not-a-comment\"; import subprocess\n",
        );
        assert!(run(tmp.path()).is_err());
    }

    /// The Python docstring is not a comment: a forbidden call spelled in one
    /// is flagged, so prose has to describe the rule without the call.
    #[test]
    fn a_python_docstring_is_not_a_comment() {
        let tmp = clean_workspace();
        write(
            tmp.path(),
            "crates/mvm-sdk/sdks/python/mvm/_doc.py",
            "def f():\n    \"\"\"Runs subprocess.run for you.\"\"\"\n",
        );
        assert!(run(tmp.path()).is_err());
    }

    #[test]
    fn locating_the_bundle_directory_is_not_execution() {
        let tmp = clean_workspace();
        write(
            tmp.path(),
            "crates/mvm-sdk/sdks/python/mvm/_hostlib.py",
            "import shutil\nfound = shutil.which(\"mvmctl\")\n",
        );
        write(
            tmp.path(),
            "crates/mvm-sdk/sdks/typescript/src/_hostlib.ts",
            "const found = which(\"mvmctl\");\n",
        );
        run(tmp.path()).expect("finding the library's directory runs nothing");
    }

    #[test]
    fn node_modules_and_build_output_are_not_scanned() {
        let tmp = clean_workspace();
        write(
            tmp.path(),
            "crates/mvm-sdk/sdks/typescript/src/node_modules/dep/index.js",
            "require('child_process');\n",
        );
        write(
            tmp.path(),
            "crates/mvm-sdk/sdks/typescript/src/dist/x.js",
            "require('child_process');\n",
        );
        run(tmp.path()).expect("vendored and built trees are not ours");
    }

    #[test]
    fn a_missing_root_fails_closed() {
        let tmp = clean_workspace();
        std::fs::remove_dir_all(tmp.path().join("crates/mvm-hostlib")).unwrap();
        assert!(failure(tmp.path()).contains("does not exist"));
    }

    #[test]
    fn an_empty_root_fails_closed() {
        let tmp = clean_workspace();
        std::fs::remove_file(
            tmp.path()
                .join("crates/mvm-sdk/sdks/python/mvm/_sandbox.py"),
        )
        .unwrap();
        assert!(failure(tmp.path()).contains("holds no"));
    }

    #[test]
    fn findings_report_the_original_line_after_a_block_comment() {
        let text = "/* one\n two\n three */\nconst c = require('child_process');\n";
        let findings = scan_text(Path::new("x.ts"), text, Lang::Script);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 4);
    }

    /// The live tree holds the rule, so the gate is green on the branch that
    /// introduces it and red the moment a shell-out returns.
    #[test]
    fn the_workspace_itself_is_clean() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask sits in the workspace root");
        run(root).expect("the SDK sources call the host library only");
    }
}
