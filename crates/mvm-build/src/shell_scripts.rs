//! Scripts the dev and pool build paths hand to a `ShellEnvironment`.
//!
//! Every path and value is data: it goes through
//! `q`, so one containing a
//! space, quote, `$(...)`, backtick, newline or `;` stays a single inert word.
//! A revision name read back from a symlink or a hash read from tool output is
//! as untrusted as a flake path here.

/// POSIX single-quote form. `mvm-vmm`'s quoter is a unix-only dependency and
/// these scripts are built on every host, so the one-line idiom lives here.
pub(crate) fn q(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', r"'\''"))
}

pub(crate) fn mkdir_p(path: &str) -> String {
    format!("mkdir -p {}", q(path))
}

pub(crate) fn rm_rf(path: &str) -> String {
    format!("rm -rf {}", q(path))
}

pub(crate) fn cat(path: &str) -> String {
    format!("cat {}", q(path))
}

pub(crate) fn cat_or_echo(path: &str, fallback: &str) -> String {
    format!("cat {} 2>/dev/null || echo {}", q(path), q(fallback))
}

pub(crate) fn cat_quiet(path: &str) -> String {
    format!("cat {} 2>/dev/null", q(path))
}

pub(crate) fn tail_quiet(path: &str, lines: u32) -> String {
    format!("tail -{lines} {} 2>/dev/null || true", q(path))
}

pub(crate) fn test_link(path: &str) -> String {
    format!("test -L {} && echo yes || echo no", q(path))
}

pub(crate) fn test_file(path: &str) -> String {
    format!("test -f {} && echo yes || echo no", q(path))
}

pub(crate) fn readlink(path: &str) -> String {
    format!("readlink {}", q(path))
}

pub(crate) fn copy_tree(src: &str, dst: &str) -> String {
    format!("cp -a {} {}", q(src), q(dst))
}

pub(crate) fn relink(target: &str, link: &str) -> String {
    format!("ln -snf {} {}", q(target), q(link))
}

pub(crate) fn sha256_of(path: &str) -> String {
    format!("sha256sum {} 2>/dev/null | cut -d' ' -f1", q(path))
}

pub(crate) fn nix_hash_of_lock(flake: &str) -> String {
    let lock = q(&format!("{flake}/flake.lock"));
    format!(r#"if [ -f {lock} ]; then nix hash path {lock}; else echo ""; fi"#)
}

pub(crate) fn write_value(dir: &str, path: &str, value: &str) -> String {
    format!(
        "mkdir -p {} && printf '%s\\n' {} > {}",
        q(dir),
        q(value),
        q(path)
    )
}

pub(crate) fn record_history(path: &str, entry: &str) -> String {
    let (path, tmp, entry) = (q(path), q(&format!("{path}.tmp")), q(entry));
    format!(
        r#"
        if [ -f {path} ]; then
            EXISTING=$(cat {path})
            echo "$EXISTING" | head -49 > {tmp}
            printf '%s\n' {entry} >> {tmp}
            mv {tmp} {path}
        else
            printf '%s\n' {entry} > {path}
        fi
        "#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTILE: [&str; 7] = [
        "/p/PWN a b",
        "/p/PWN'; touch /tmp/PWN; '",
        "/p/PWN$(touch /tmp/PWN)",
        "/p/PWN`touch /tmp/PWN`",
        "/p/PWN\ntouch /tmp/PWN",
        "/p/PWN;rm -rf /",
        "/p/PWN\"x|y&z>w",
    ];

    /// `script` contains each of `quoted` and, with those removed, no trace of PWN.
    fn inert(script: &str, quoted: &[String]) {
        let mut rest = script.to_string();
        for part in quoted {
            assert!(rest.contains(part.as_str()), "{part} missing from {script}");
            rest = rest.replace(part.as_str(), "Q");
        }
        assert!(!rest.contains("PWN"), "leaks outside quotes: {rest}");
    }

    #[test]
    fn a_hostile_value_stays_one_inert_word_in_every_script() {
        for v in HOSTILE {
            let qv = vec![q(v)];
            for script in [
                mkdir_p(v),
                rm_rf(v),
                cat(v),
                cat_quiet(v),
                tail_quiet(v, 50),
                test_link(v),
                test_file(v),
                readlink(v),
                sha256_of(v),
                cat_or_echo(v, "x"),
            ] {
                inert(&script, &qv);
            }
            inert(&cat_or_echo("/ok", v), &[q(v)]);
            inert(&copy_tree(v, "/ok"), &qv);
            inert(&copy_tree("/ok", v), &qv);
            inert(&relink(v, "/ok"), &qv);
            inert(&relink("/ok", v), &qv);
            inert(&write_value(v, "/ok", "x"), &qv);
            inert(&write_value("/ok", "/ok2", v), &qv);
            inert(&nix_hash_of_lock(v), &[q(&format!("{v}/flake.lock"))]);
            inert(&record_history(v, "{}"), &[q(v), q(&format!("{v}.tmp"))]);
            inert(&record_history("/ok", v), &qv);
        }
    }

    #[test]
    fn ordinary_scripts_keep_their_shape() {
        assert_eq!(mkdir_p("/a/b"), "mkdir -p '/a/b'");
        assert_eq!(cat_or_echo("/a", ""), "cat '/a' 2>/dev/null || echo ''");
        assert_eq!(
            relink("revisions/r1", "/p/current"),
            "ln -snf 'revisions/r1' '/p/current'"
        );
    }
}
