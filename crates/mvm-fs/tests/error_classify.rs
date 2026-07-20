//! `Ext4Error::is_capacity_limit` classifies build failures for the run path's
//! materialize dispatch: a *capacity limit* (the pure writer structurally can't
//! emit this image) is retryable via the builder VM, whereas a *malformed tree*
//! is a genuine error to surface. A real OCI-unpacked FS tree only ever produces
//! capacity limits — the malformed variants require a synthetic node list.

use mvm_fs::ext4::Ext4Error;

#[test]
fn capacity_limits_are_classified_for_fallback() {
    let capacity = [
        Ext4Error::TooLarge { blocks: 1 << 40 },
        Ext4Error::FileTooFragmented {
            ino: 12,
            extents: 9,
        },
        Ext4Error::XattrTooLarge { ino: 7 },
    ];
    for e in capacity {
        assert!(e.is_capacity_limit(), "{e:?} should be a capacity limit");
    }
}

#[test]
fn malformed_tree_errors_are_not_capacity_limits() {
    let malformed = [
        Ext4Error::MissingParent("/a/b".into()),
        Ext4Error::BadPath("//a".into()),
        Ext4Error::NotADirectory("/a/b".into()),
        Ext4Error::DuplicatePath("/dup".into()),
    ];
    for e in malformed {
        assert!(
            !e.is_capacity_limit(),
            "{e:?} is a malformed-tree error, not a capacity limit"
        );
    }
}
