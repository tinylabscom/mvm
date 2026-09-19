//! `xtask check-image-reproducibility`
//!
//! Every filesystem the Nix image recipes write must be a function of its
//! input tree alone. The tools that write them draw randomness unless told
//! not to: `mke2fs` picks a filesystem UUID and a directory hash seed,
//! `veritysetup format` a superblock UUID, and `cpio -o` copies the build
//! host's inode and device numbers into every header. Any of them makes two
//! builds of one derivation differ in a few metadata bytes, which is enough
//! that two producers of an image cannot be compared by digest and a
//! published root hash cannot be re-derived from source.
//!
//! This gate reads the recipes under `nix/` and refuses:
//!
//! - a `mkfs.ext*` / `mke2fs` call without `-U`, without a `hash_seed=`, or
//!   with more than one `-E`. `mke2fs` keeps only the last `-E`, so a seed
//!   passed in one of two is silently dropped;
//! - a `veritysetup format` call without `--uuid`;
//! - a `cpio` create (`-o`) without `--reproducible`;
//! - a `make-ext4-fs.nix` call that does not pass its own `e2fsprogs`. That
//!   builder pins the UUID but not the hash seed and takes no extra `mkfs`
//!   arguments, so the pinned seed has to arrive through the `e2fsprogs` it is
//!   handed.
//!
//! It is a static check. The merge-queue image job rebuilds the default image
//! and runtime overlay with `nix build --rebuild`, which is the byte-level
//! witness; this gate is what fails on a pull request.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

const NIX_ROOT: &str = "nix";
const MAKE_EXT4_FS: &str = "make-ext4-fs.nix";

pub fn run(workspace: &Path) -> Result<()> {
    let mut files = Vec::new();
    collect_nix_files(&workspace.join(NIX_ROOT), &mut files)?;
    files.sort();

    let mut report = Report::default();
    for file in &files {
        let text =
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
        let rel = file
            .strip_prefix(workspace)
            .unwrap_or(file)
            .display()
            .to_string();
        report.scan(&rel, &text);
    }

    if !report.problems.is_empty() {
        bail!(
            "check-image-reproducibility: {} image recipe call(s) would write random bytes:\n  - {}",
            report.problems.len(),
            report.problems.join("\n  - ")
        );
    }
    eprintln!(
        "check-image-reproducibility: clean ({} mkfs, {} veritysetup, {} cpio, {} make-ext4-fs \
         call(s) pinned)",
        report.mkfs, report.verity, report.cpio, report.make_ext4_fs
    );
    Ok(())
}

fn collect_nix_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_nix_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "nix") {
            out.push(path);
        }
    }
    Ok(())
}

/// What one scan found: the calls it checked, and every refusal.
#[derive(Debug, Default)]
struct Report {
    mkfs: usize,
    verity: usize,
    cpio: usize,
    make_ext4_fs: usize,
    problems: Vec<String>,
}

impl Report {
    fn scan(&mut self, file: &str, text: &str) {
        for (line, command) in logical_commands(text) {
            for segment in command.split('|') {
                let words: Vec<&str> = segment.split_whitespace().collect();
                let Some(program) = program_of(&words) else {
                    continue;
                };
                let args = &words[program + 1..];
                let at = format!("{file}:{line}");
                match words[program] {
                    "mkfs.ext2" | "mkfs.ext3" | "mkfs.ext4" | "mke2fs" => {
                        self.mkfs += 1;
                        self.problems
                            .extend(mkfs_problems(args).map(|p| format!("{at}: {p}")));
                    }
                    "veritysetup" if args.first() == Some(&"format") => {
                        self.verity += 1;
                        if !args.iter().any(|a| a.starts_with("--uuid")) {
                            self.problems.push(format!(
                                "{at}: `veritysetup format` without `--uuid` writes a random \
                                 UUID into the hash device"
                            ));
                        }
                    }
                    "cpio" if is_cpio_create(args) => {
                        self.cpio += 1;
                        if !args.contains(&"--reproducible") {
                            self.problems.push(format!(
                                "{at}: `cpio -o` without `--reproducible` copies the build \
                                 host's inode numbers into the archive"
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
        for (line, block) in make_ext4_fs_calls(text) {
            self.make_ext4_fs += 1;
            if !block
                .lines()
                .any(|l| l.trim_start().starts_with("e2fsprogs ="))
            {
                self.problems.push(format!(
                    "{file}:{line}: `{MAKE_EXT4_FS}` is called without its own `e2fsprogs`, so \
                     `mkfs.ext4` draws a random directory hash seed"
                ));
            }
        }
    }
}

/// Why an `mke2fs` argument list leaves randomness in the filesystem.
fn mkfs_problems<'a>(args: &'a [&'a str]) -> impl Iterator<Item = String> + 'a {
    let extended: Vec<&str> = args
        .iter()
        .enumerate()
        .filter(|(_, a)| **a == "-E")
        .filter_map(|(i, _)| args.get(i + 1).copied())
        .collect();
    let mut problems = Vec::new();
    if !args.contains(&"-U") {
        problems.push("mkfs without `-U` draws a random filesystem UUID".to_string());
    }
    if extended.len() > 1 {
        problems.push(format!(
            "mkfs with {} `-E` flags keeps only the last; merge them into one \
             comma-separated `-E`",
            extended.len()
        ));
    }
    if !extended.last().is_some_and(|e| e.contains("hash_seed=")) {
        problems.push(
            "mkfs without an effective `-E hash_seed=` draws a random directory hash seed"
                .to_string(),
        );
    }
    problems.into_iter()
}

/// Whether a `cpio` argument list creates an archive.
fn is_cpio_create(args: &[&str]) -> bool {
    args.iter().any(|a| {
        *a == "--create" || (a.starts_with('-') && !a.starts_with("--") && a[1..].contains('o'))
    })
}

/// Index of the program word, past any leading `NAME=value` assignments and
/// a `(` or `&&` that opens a subshell or chains a command.
fn program_of(words: &[&str]) -> Option<usize> {
    words.iter().position(|w| {
        !matches!(*w, "(" | "&&" | "||" | "exec")
            && !w.split_once('=').is_some_and(|(name, _)| is_env_name(name))
    })
}

fn is_env_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Shell commands with backslash continuations joined, comment lines
/// dropped, each tagged with the line it starts on. Commands chained with
/// `&&` on one line are split so each is checked on its own.
fn logical_commands(text: &str) -> Vec<(usize, String)> {
    let mut commands = Vec::new();
    let mut current: Option<(usize, String)> = None;
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        let (body, continues) = match line.strip_suffix('\\') {
            Some(body) => (body, true),
            None => (line, false),
        };
        let entry = current.get_or_insert_with(|| (index + 1, String::new()));
        entry.1.push(' ');
        entry.1.push_str(body);
        if !continues && let Some((start, command)) = current.take() {
            for part in command.split("&&") {
                commands.push((start, part.to_string()));
            }
        }
    }
    if let Some(entry) = current {
        commands.push(entry);
    }
    commands
}

/// Each `make-ext4-fs.nix` call's argument set, with the line it is on.
fn make_ext4_fs_calls(text: &str) -> Vec<(usize, &str)> {
    let mut calls = Vec::new();
    let mut search = 0;
    while let Some(found) = text[search..].find(MAKE_EXT4_FS) {
        let at = search + found;
        search = at + MAKE_EXT4_FS.len();
        let line_start = text[..at].rfind('\n').map_or(0, |i| i + 1);
        if text[line_start..at].trim_start().starts_with('#') {
            continue;
        }
        let line = text[..at].matches('\n').count() + 1;
        if let Some(block) = balanced_braces(&text[search..]) {
            calls.push((line, block));
        }
    }
    calls
}

/// The text from the first `{` to its matching `}`.
fn balanced_braces(text: &str) -> Option<&str> {
    let open = text.find('{')?;
    let mut depth = 0usize;
    for (offset, c) in text[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[open..=open + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(text: &str) -> Report {
        let mut report = Report::default();
        report.scan("recipe.nix", text);
        report
    }

    #[test]
    fn a_pinned_mkfs_with_one_extended_flag_passes() {
        let r = scan(
            "SOURCE_DATE_EPOCH=0 \\\n  mkfs.ext4 -F \\\n    -U 00000000-0000-0000-0000-000000000001 \\\n    -E hash_seed=00000000-0000-0000-0000-000000000002,no_copy_xattrs \\\n    -d \"$staging\" $out/x.ext4\n",
        );
        assert_eq!(r.mkfs, 1);
        assert!(r.problems.is_empty(), "{:?}", r.problems);
    }

    /// The shape the runtime overlay and SDK sidecar shipped: the seed is in
    /// the first of two `-E` flags, and `mke2fs` keeps only the second.
    #[test]
    fn a_seed_in_the_first_of_two_extended_flags_is_refused() {
        let r = scan(
            "mkfs.ext4 -F \\\n  -U ${uuid} \\\n  -E hash_seed=${seed} \\\n  -E no_copy_xattrs \\\n  $out/overlay.ext4\n",
        );
        assert_eq!(r.problems.len(), 2, "{:?}", r.problems);
        assert!(r.problems[0].contains("2 `-E` flags"), "{:?}", r.problems);
        assert!(r.problems[1].contains("hash_seed"), "{:?}", r.problems);
        assert!(
            r.problems[0].starts_with("recipe.nix:1:"),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn an_unpinned_mkfs_is_refused_for_uuid_and_seed() {
        let r = scan("      mkfs.ext2 -d rootfs -F -q $out\n");
        assert_eq!(r.problems.len(), 2, "{:?}", r.problems);
        assert!(r.problems[0].contains("-U"));
        assert!(r.problems[1].contains("hash_seed"));
    }

    #[test]
    fn veritysetup_format_needs_a_uuid() {
        let unpinned = scan(
            "veritysetup_out=$(\n  veritysetup format \\\n    --salt=${salt} \\\n    $out/rootfs.ext4 \\\n    $out/rootfs.verity\n)\n",
        );
        assert_eq!(unpinned.verity, 1);
        assert_eq!(unpinned.problems.len(), 1, "{:?}", unpinned.problems);
        assert!(unpinned.problems[0].starts_with("recipe.nix:2:"));

        let pinned = scan("veritysetup format --uuid=${uuid} $out/a $out/b\n");
        assert_eq!(pinned.verity, 1);
        assert!(pinned.problems.is_empty(), "{:?}", pinned.problems);
    }

    #[test]
    fn a_cpio_create_in_a_pipeline_needs_reproducible() {
        let unpinned = scan(
            "( cd \"$staging\" \\\n  && find . -print0 | sort -z | cpio --null -o -H newc --owner=0:0 \\\n) > out.cpio\n",
        );
        assert_eq!(unpinned.cpio, 1);
        assert_eq!(unpinned.problems.len(), 1, "{:?}", unpinned.problems);

        let pinned = scan("find . | cpio -o -H newc --reproducible > out.cpio\n");
        assert!(pinned.problems.is_empty(), "{:?}", pinned.problems);
    }

    #[test]
    fn cpio_extraction_and_mentions_are_not_creates() {
        let r = scan(
            "cpio -idm < archive.cpio\nnativeBuildInputs = [ pkgs.cpio ];\n# cpio -o in a comment\n",
        );
        assert_eq!(r.cpio, 0);
        assert!(r.problems.is_empty(), "{:?}", r.problems);
    }

    #[test]
    fn make_ext4_fs_must_be_handed_its_e2fsprogs() {
        let bare = scan(
            "img = pkgs.callPackage \"${nixpkgs}/nixos/lib/make-ext4-fs.nix\" {\n  storePaths = [ tree ];\n  populateImageCommands = ''\n    cp -a ${tree}/. ./files/\n  '';\n};\n",
        );
        assert_eq!(bare.make_ext4_fs, 1);
        assert_eq!(bare.problems.len(), 1, "{:?}", bare.problems);
        assert!(bare.problems[0].starts_with("recipe.nix:1:"));

        let pinned = scan(
            "img = pkgs.callPackage \"${nixpkgs}/nixos/lib/make-ext4-fs.nix\" {\n  e2fsprogs = pinned;\n  storePaths = [ tree ];\n};\n",
        );
        assert!(pinned.problems.is_empty(), "{:?}", pinned.problems);
    }

    #[test]
    fn wrappers_and_comments_naming_mkfs_are_not_calls() {
        let r = scan(
            "# `mkfs.ext4 -d` + `veritysetup format` are pinned below.\nmakeWrapper ${e2fsprogs}/bin/mkfs.ext4 \"$out/bin/mkfs.ext4\" \\\n  --add-flags \"-E hash_seed=${seed}\"\n",
        );
        assert_eq!((r.mkfs, r.verity), (0, 0));
        assert!(r.problems.is_empty(), "{:?}", r.problems);
    }

    /// The real recipes: clean, and the scan reaches every kind of call, so a
    /// parser change that stops seeing them cannot pass vacuously.
    #[test]
    fn the_checked_in_recipes_are_clean_and_each_kind_is_seen() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask sits under the workspace root");
        let mut files = Vec::new();
        collect_nix_files(&workspace.join(NIX_ROOT), &mut files).expect("walk nix/");
        let mut report = Report::default();
        for file in &files {
            let text = std::fs::read_to_string(file).expect("read recipe");
            report.scan(&file.display().to_string(), &text);
        }
        assert!(report.problems.is_empty(), "{:?}", report.problems);
        assert!(report.mkfs >= 3, "mkfs calls seen: {}", report.mkfs);
        assert!(
            report.verity >= 2,
            "veritysetup calls seen: {}",
            report.verity
        );
        assert!(report.cpio >= 1, "cpio creates seen: {}", report.cpio);
        assert!(
            report.make_ext4_fs >= 1,
            "make-ext4-fs calls seen: {}",
            report.make_ext4_fs
        );
    }
}
