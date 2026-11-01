#!/usr/bin/env python3
"""Regenerate the generated blocks in specs/contracts/cleanup-inventory.md.

    python3 scripts/gen-cli-surface-inventory.py --bin target/debug/mvmctl            # rewrite
    python3 scripts/gen-cli-surface-inventory.py --bin target/debug/mvmctl --check    # fail on drift
    python3 scripts/gen-cli-surface-inventory.py --env-only [--check]                 # no binary needed

Two blocks:
  cli-tree: the verb/flag tree from recursive `--help` of a built mvmctl.
  env:      every MVM_* string literal in Rust, classified by where it is read.

The env classification is a line heuristic (no parser): code after the first
`#[cfg(test)]` in a file, files under tests/, and tests.rs count as test code;
a line with `.env(` / `.envs(` / `set_var` / `env_remove` counts as a write.
"""
import collections, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "specs/contracts/cleanup-inventory.md")
LIT = re.compile(r'"(MVM_[A-Z0-9_]+)"')
NAME = re.compile(r'\bMVM_[A-Z][A-Z0-9_]*[A-Z0-9]\b')
WRITE = re.compile(r'\.envs?\(|set_var|env_remove|env_clear')
REMOVED = re.compile(r'removed|retired|no longer|gone|deprecated|never existed|does not exist', re.I)
SKIP = {"target", ".git", "node_modules", ".agent-memory", "specs", "third_party"}


def walk(exts, under):
    for base in under:
        if os.path.isfile(os.path.join(ROOT, base)):
            yield os.path.join(ROOT, base)
            continue
        for d, ds, fs in os.walk(os.path.join(ROOT, base)):
            ds[:] = [x for x in ds if x not in SKIP]
            for f in fs:
                if f.endswith(exts):
                    yield os.path.join(d, f)


def rel(p):
    return os.path.relpath(p, ROOT)


def is_test_file(p):
    r = rel(p)
    return "/tests/" in r or r.endswith("/tests.rs") or r.startswith("tests/")


def rust_sites():
    """name -> list of (relpath, line, kind) with kind in prod-read/prod-write/test."""
    out = collections.defaultdict(list)
    for p in sorted(walk((".rs",), ["crates", "src"])):
        test_file = is_test_file(p)
        in_test = False
        for n, line in enumerate(open(p, errors="replace"), 1):
            if line.strip() == "#[cfg(test)]":
                in_test = True
            for m in LIT.finditer(line):
                if test_file or in_test:
                    kind = "test"
                else:
                    kind = "prod-write" if WRITE.search(line) else "prod-read"
                out[m.group(1)].append((rel(p), n, kind))
    return out


def text_mentions(under, exts):
    """name -> first (relpath, line, text) over non-Rust files."""
    out = {}
    for p in sorted(walk(exts, under)):
        for n, line in enumerate(open(p, errors="replace"), 1):
            for m in NAME.finditer(line):
                out.setdefault(m.group(0), []).append((rel(p), n, line.strip()))
    return out


def env_block():
    sites = rust_sites()
    docs = text_mentions(["public/src/content/docs"], (".md", ".mdx"))
    ext = text_mentions(["scripts", "nix", "features", "tests", "crates", ".github", "xtask", "just", "bin", "model",
                         "install.sh", "uninstall.sh", "Justfile", "flake.nix"],
                        (".sh", ".py", ".nix", ".ts", ".toml", ".yml", ".yaml", ".feature", ".js", ".just", ".sh"))
    ext_root = {k: v for k, v in ext.items() if not k.endswith("_")}
    rows, cls = [], collections.Counter()
    for name in sorted(sites):
        s = sites[name]
        prod = [x for x in s if x[2] == "prod-read"]
        wr = [x for x in s if x[2] == "prod-write"]
        if prod:
            c, ref = "live-read", prod[0]
        elif wr:
            c, ref = "set-only", wr[0]
        else:
            c, ref = "test-only", s[0]
        cls[c] += 1
        doc = "yes" if name in docs else "NO"
        x = "yes" if name in ext_root else "-"
        rows.append(f"| `{name}` | {c} | `{ref[0]}:{ref[1]}` | {len(prod)} | {doc} | {x} |")
    lit_names = set(sites)
    nonrs = set(ext_root)
    gone = []
    for name in sorted(set(docs) - lit_names - nonrs):
        d = docs[name]
        why = next((t for t in d if REMOVED.search(t[2])), None)
        gone.append(f"| `{name}` | `{d[0][0]}:{d[0][1]}` | {'says removed/retired' if why else 'no removal statement'} |")
    undoc_live = sum(1 for n in sites if n not in docs and any(x[2] == "prod-read" for x in sites[n]))
    head = [
        f"Distinct `MVM_*` literals in Rust (`crates`, `src`, tests included): **{len(sites)}**; "
        f"live-read **{cls['live-read']}**, set-only **{cls['set-only']}**, test-only **{cls['test-only']}**; "
        f"live-read and absent from `public/src/content/docs`: **{undoc_live}**; "
        f"names in `public/src/content/docs` that no Rust literal or script/nix/feature/test file uses: **{len(gone)}**.",
        "",
        "Columns: class (`live-read` = a literal on a non-test, non-write line; `set-only` = only written to a child process, "
        "so the reader is outside Rust or in another process; `test-only` = test code only), first reader `file:line`, "
        "count of live-read sites, documented in `public/src/content/docs`, referenced by a script/nix/feature/test file.",
        "",
        "| Literal | Class | First site | Live sites | Documented | Non-Rust ref |",
        "|---|---|---|---|---|---|",
    ] + rows + [
        "",
        "Documented names with no reader anywhere (docs-only):",
        "",
        "| Name | First doc site | Removal statement |",
        "|---|---|---|",
    ] + gone
    return "\n".join(head)


def run_help(binp, path):
    r = subprocess.run([binp, *path, "--help"], capture_output=True, text=True,
                       env={**os.environ, "NO_COLOR": "1", "COLUMNS": "200"}, timeout=60)
    return r.stdout


def parse_help(text):
    """-> (subcommands [(name, desc)], flags [str]) from clap help output."""
    subs, flags, sect = [], [], None
    for line in text.splitlines():
        if re.match(r'^[A-Za-z ]+:$', line):
            sect = line.rstrip(":")
            continue
        if sect == "Commands" and re.match(r'^  \S', line):
            name = line.split()[0]
            if name != "help":
                subs.append((name, line[2 + len(name):].strip()))
        elif sect in ("Options", "Arguments") and re.match(r'^\s+(-|<)', line):
            flags.append(line.strip())
        elif sect in ("Options", "Arguments") and re.match(r'^\s+\S', line) and flags and line.startswith(" " * 8):
            flags[-1] += " " + line.strip()
    return subs, flags


def flag_cells(flags):
    out = []
    for f in flags:
        head = re.split(r'\s{2,}', f, maxsplit=1)
        names = head[0]
        if names.startswith("-h,") or names.startswith("-V,"):
            continue
        d = re.search(r'\[default: ([^\]]*)\]', f)
        env = re.search(r'\[env: ([^\]]*)\]', f)
        s = names
        if d:
            s += f" = {d.group(1)}"
        if env:
            s += f" (env {env.group(1)})"
        out.append(s)
    return out


def cli_block(binp):
    rows, counts = [], collections.Counter()
    root_flags = set()

    def visit(path):
        subs, flags = parse_help(run_help(binp, path))
        cells = flag_cells(flags)
        if not path:
            root_flags.update(c.split()[0] for c in cells)
        else:
            cells = [c for c in cells if c.split()[0] not in root_flags]
        counts["verbs"] += 1
        counts["flags"] += len(cells)
        rows.append((" ".join(path) or "(root)", cells))
        for name, _ in subs:
            visit(path + [name])

    visit([])
    # Hidden verbs: names the source declares hidden that help does not list.
    out = [
        f"Verb paths walked: **{counts['verbs']}** (every `Commands` listed by `--help`, recursively); "
        f"flag and positional entries in their `Options`/`Arguments` sections, excluding `-h`/`-V`: **{counts['flags']}**. "
        "Root flags (propagated to every verb by clap) are listed once, under `(root)`. "
        "`--help` here is width-constrained (`constrain_help_output`, `crates/mvm-cli/src/commands/mod.rs`), so descriptions, defaults and deprecation markers are cut off and not recorded. "
        "Hidden verbs do not appear in `--help` and are not in this table; see the hidden-verb list in §3.2.",
        "",
        "| Verb path | Flags and arguments (`= default`, `(env X)`) |",
        "|---|---|",
    ]
    for path, cells in rows:
        cell = "<br>".join(f"`{c}`" for c in cells) if cells else "-"
        out.append(f"| `{path}` | {cell} |")
    return "\n".join(out)


def splice(doc, tag, body):
    b, e = f"<!-- {tag}:begin -->", f"<!-- {tag}:end -->"
    i, j = doc.index(b) + len(b), doc.index(e)
    return doc[:i] + "\n" + body + "\n" + doc[j:]


def main():
    a = sys.argv[1:]
    check = "--check" in a
    doc = open(DOC).read()
    new = splice(doc, "env", env_block())
    if "--env-only" not in a:
        binp = a[a.index("--bin") + 1]
        new = splice(new, "cli-tree", cli_block(binp))
    if check:
        if new != doc:
            sys.exit("cleanup-inventory.md generated blocks are stale; rerun without --check")
        print("ok")
    else:
        open(DOC, "w").write(new)


if __name__ == "__main__":
    main()
