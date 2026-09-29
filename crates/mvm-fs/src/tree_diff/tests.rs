use super::tree::MemTree;
use super::*;

fn diff(old: &MemTree, new: &MemTree) -> TreeDiff {
    diff_trees(old, new, DiffLimits::default()).expect("diff")
}

fn only(diff: &TreeDiff) -> &FileDiff {
    assert_eq!(diff.files.len(), 1, "{diff:#?}");
    &diff.files[0]
}

#[test]
fn identical_trees_have_no_changes() {
    let tree = MemTree::default()
        .dir("src")
        .file("src/a.rs", b"fn a() {}\n");
    let d = diff(&tree, &tree);
    assert!(d.files.is_empty());
    assert_eq!(d.stats.changed(), 0);
    assert!(d.truncated.is_none());
}

#[test]
fn a_modified_text_file_carries_its_hunks() {
    let old = MemTree::default().file("a.txt", b"one\ntwo\nthree\n");
    let new = MemTree::default().file("a.txt", b"one\n2\nthree\n");
    let d = diff(&old, &new);
    let file = only(&d);
    assert_eq!(file.change, ChangeKind::Modified);
    let DiffContent::Text {
        hunks,
        lines_added,
        lines_removed,
    } = &file.content
    else {
        panic!("{:?}", file.content)
    };
    assert_eq!((*lines_added, *lines_removed), (1, 1));
    let texts: Vec<(LineKind, &str)> = hunks[0]
        .lines
        .iter()
        .map(|l| (l.kind, l.text.as_str()))
        .collect();
    assert_eq!(
        texts,
        [
            (LineKind::Context, "one"),
            (LineKind::Removed, "two"),
            (LineKind::Added, "2"),
            (LineKind::Context, "three"),
        ]
    );
    assert_eq!(d.stats.modified, 1);
}

#[test]
fn added_and_removed_files_diff_against_nothing() {
    let old = MemTree::default().file("gone.txt", b"bye\n");
    let new = MemTree::default().file("new.txt", b"hi\n");
    let d = diff(&old, &new);
    assert_eq!(d.files.len(), 2);
    assert_eq!(d.files[0].path, "gone.txt");
    assert_eq!(d.files[0].change, ChangeKind::Removed);
    assert!(d.files[0].new.is_none());
    assert_eq!(d.files[1].change, ChangeKind::Added);
    assert!(matches!(
        d.files[1].content,
        DiffContent::Text {
            lines_added: 1,
            lines_removed: 0,
            ..
        }
    ));
    assert_eq!((d.stats.added, d.stats.removed), (1, 1));
}

#[test]
fn a_binary_file_is_summarised_by_digest() {
    let old = MemTree::default().file("img.bin", b"\x00\x01\x02");
    let new = MemTree::default().file("img.bin", b"\x00\x01\x03");
    let d = diff(&old, &new);
    let DiffContent::Binary {
        old_sha256,
        new_sha256,
    } = &only(&d).content
    else {
        panic!()
    };
    assert_ne!(old_sha256, new_sha256);
    assert_eq!(old_sha256.as_ref().unwrap().len(), 64);
}

#[test]
fn invalid_utf8_is_binary_too() {
    let old = MemTree::default();
    let new = MemTree::default().file("latin1.txt", b"caf\xe9\n");
    let d = diff(&old, &new);
    assert!(matches!(only(&d).content, DiffContent::Binary { .. }));
}

#[test]
fn a_file_over_the_size_limit_is_compared_by_digest_and_not_shown() {
    let big_old = vec![b'a'; 2048];
    let mut big_new = big_old.clone();
    big_new[1000] = b'b';
    let old = MemTree::default().file("big.txt", &big_old);
    let new = MemTree::default().file("big.txt", &big_new);
    let limits = DiffLimits::default().with_max_file_bytes(1024);
    let d = diff_trees(&old, &new, limits).unwrap();
    let DiffContent::TooLarge {
        limit_bytes,
        old_sha256,
        new_sha256,
    } = &only(&d).content
    else {
        panic!()
    };
    assert_eq!(*limit_bytes, 1024);
    assert_ne!(old_sha256, new_sha256);

    // Same size and same bytes over the limit: unchanged, found by digest.
    let same = MemTree::default().file("big.txt", &big_old);
    assert!(diff_trees(&old, &same, limits).unwrap().files.is_empty());
}

#[test]
fn past_the_output_budget_later_files_are_listed_without_text() {
    let old = MemTree::default()
        .file("a.txt", b"a\n")
        .file("b.txt", b"b\n");
    let new = MemTree::default()
        .file("a.txt", b"A\n")
        .file("b.txt", b"B\n");
    let limits = DiffLimits::default().with_max_output_bytes(4);
    let d = diff_trees(&old, &new, limits).unwrap();
    assert!(matches!(d.files[0].content, DiffContent::Text { .. }));
    assert_eq!(d.files[1].content, DiffContent::Omitted);
    let truncated = d.truncated.expect("truncated");
    assert_eq!(truncated.reason, TruncationReason::OutputLimit);
    assert_eq!(truncated.omitted_content, 1);
    assert_eq!(truncated.omitted_files, 0);
    assert_eq!(d.stats.modified, 2, "stats count what the text left out");
}

#[test]
fn past_the_file_limit_changes_are_counted_not_listed() {
    let old = MemTree::default();
    let new = MemTree::default()
        .file("1", b"x")
        .file("2", b"x")
        .file("3", b"x");
    let d = diff_trees(&old, &new, DiffLimits::default().with_max_files(2)).unwrap();
    assert_eq!(d.files.len(), 2);
    assert_eq!(d.stats.added, 3);
    let truncated = d.truncated.unwrap();
    assert_eq!(truncated.reason, TruncationReason::FileLimit);
    assert_eq!(truncated.omitted_files, 1);
}

#[test]
fn a_tree_over_the_entry_limit_is_refused() {
    let old = MemTree::default().file("a", b"").file("b", b"");
    let err = diff_trees(&old, &old, DiffLimits::default().with_max_entries(1)).unwrap_err();
    assert!(matches!(
        err,
        TreeDiffError::TooManyEntries { max_entries: 1 }
    ));
}

#[test]
fn a_mode_change_alone_is_reported_as_such() {
    let old = MemTree::default().file("run.sh", b"echo\n");
    let new = MemTree::default()
        .file("run.sh", b"echo\n")
        .mode("run.sh", 0o755);
    let d = diff(&old, &new);
    assert_eq!(only(&d).content, DiffContent::ModeOnly);
    assert_eq!(only(&d).new.as_ref().unwrap().mode, 0o755);
}

#[test]
fn a_symlink_is_diffed_by_its_target_text() {
    let old = MemTree::default().link("current", "v1");
    let new = MemTree::default().link("current", "/etc/passwd");
    let d = diff(&old, &new);
    assert_eq!(
        only(&d).content,
        DiffContent::Symlink {
            old_target: Some("v1".into()),
            new_target: Some("/etc/passwd".into()),
        }
    );
}

#[test]
fn a_file_turned_directory_is_a_type_change() {
    let old = MemTree::default().file("x", b"file\n");
    let new = MemTree::default().dir("x");
    let d = diff(&old, &new);
    assert_eq!(only(&d).change, ChangeKind::TypeChanged);
    assert_eq!(only(&d).content, DiffContent::Entry);
}

/// The ext4 side end to end: two images built from two directories, read back
/// by the reader the diff uses in production.
mod images {
    use super::*;
    use std::path::Path;

    fn image(dir: &Path, out: &Path) {
        let options = crate::rootfs::MaterializeOptions::default();
        crate::rootfs::materialize_ext4_pure(dir, out, &options).expect("materialize");
    }

    #[test]
    fn two_images_diff_as_their_trees_do() {
        let root = tempfile::tempdir().unwrap();
        let before = root.path().join("before");
        let after = root.path().join("after");
        for dir in [&before, &after] {
            std::fs::create_dir_all(dir.join("src")).unwrap();
            std::fs::write(dir.join("README"), "unchanged\n").unwrap();
        }
        std::fs::write(before.join("src/lib.rs"), "fn a() {}\n").unwrap();
        std::fs::write(after.join("src/lib.rs"), "fn a() {}\nfn b() {}\n").unwrap();
        std::fs::write(before.join("old.txt"), "old\n").unwrap();
        std::fs::write(after.join("new.bin"), [0u8, 1, 2]).unwrap();
        std::os::unix::fs::symlink("src/lib.rs", after.join("link")).unwrap();

        let old_image = root.path().join("before.ext4");
        let new_image = root.path().join("after.ext4");
        image(&before, &old_image);
        image(&after, &new_image);

        let d = diff_images(&old_image, &new_image, DiffLimits::default()).unwrap();
        let summary: Vec<(&str, ChangeKind)> = d
            .files
            .iter()
            .map(|f| (f.path.as_str(), f.change))
            .collect();
        assert_eq!(
            summary,
            [
                ("link", ChangeKind::Added),
                ("new.bin", ChangeKind::Added),
                ("old.txt", ChangeKind::Removed),
                ("src/lib.rs", ChangeKind::Modified),
            ],
            "lost+found and unchanged entries are not reported"
        );
        assert!(matches!(d.files[1].content, DiffContent::Binary { .. }));
        assert!(matches!(
            d.files[3].content,
            DiffContent::Text {
                lines_added: 1,
                lines_removed: 0,
                ..
            }
        ));
        assert_eq!(
            d.files[0].content,
            DiffContent::Symlink {
                old_target: None,
                new_target: Some("src/lib.rs".into())
            }
        );
    }

    #[test]
    fn a_file_that_is_not_an_image_is_unreadable_not_empty() {
        let root = tempfile::tempdir().unwrap();
        let junk = root.path().join("junk.ext4");
        std::fs::write(&junk, b"not an image").unwrap();
        let err = diff_images(&junk, &junk, DiffLimits::default()).unwrap_err();
        assert!(matches!(err, TreeDiffError::Unreadable { .. }), "{err}");
    }
}
