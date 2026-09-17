//! Collections against real ext4 images: formatted by the same in-process
//! `mkfs` the run path uses, then populated through an independent ext4
//! driver so a fixture can hold what a hostile guest could write — links,
//! device nodes, FIFOs, sockets — and, where no driver will write it, a
//! directory entry patched byte for byte.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use fs_ext4::block_io::FileDevice;
use fs_ext4::fs::Filesystem;

use super::*;
use crate::output::PathRule;

const IMAGE_BYTES: u64 = 16 << 20;
const S_IFCHR: u16 = 0o020000;
const S_IFIFO: u16 = 0o010000;
const S_IFSOCK: u16 = 0o140000;

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    image: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        // The collector refuses a destination whose parent resolves elsewhere,
        // and a temp directory on macOS sits behind a `/var` symlink.
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let image = root.join("output.img");
        let mut file = std::fs::File::create(&image).unwrap();
        file.set_len(IMAGE_BYTES).unwrap();
        crate::ext4::mkfs::format_empty_ext4(&mut file, IMAGE_BYTES).unwrap();
        Self {
            _dir: dir,
            root,
            image,
        }
    }

    /// Mutate the image through an independent ext4 driver.
    fn write(&self, populate: impl FnOnce(&Filesystem)) {
        let device = FileDevice::open_rw(self.image.to_str().unwrap()).unwrap();
        let fs = Filesystem::mount(Arc::new(device)).unwrap();
        populate(&fs);
    }

    fn file(&self, path: &str, body: &[u8]) {
        self.write(|fs| {
            fs.apply_create(path, 0o644).unwrap();
            fs.apply_pwrite(path, 0, body).unwrap();
        });
    }

    /// Rewrite the bytes of one directory entry. `name` must be unique in the
    /// image and as long as `new_name`; `file_type` replaces the entry's type
    /// byte when given. The mkfs this image came from writes no checksums, so
    /// the patched entry is exactly what a guest could have left behind.
    fn patch_entry(&self, name: &[u8], new_name: &[u8], file_type: Option<u8>) {
        assert_eq!(name.len(), new_name.len());
        let mut bytes = std::fs::read(&self.image).unwrap();
        let needle: Vec<u8> = std::iter::once(name.len() as u8)
            .chain(std::iter::once(0))
            .chain(name.iter().copied())
            .collect();
        let hits: Vec<usize> = (0..bytes.len() - needle.len())
            .filter(|&i| bytes[i] == needle[0] && bytes[i + 2..i + needle.len()] == needle[2..])
            .collect();
        assert_eq!(hits.len(), 1, "fixture name must appear once in the image");
        let at = hits[0];
        if let Some(file_type) = file_type {
            bytes[at + 1] = file_type;
        }
        bytes[at + 2..at + 2 + new_name.len()].copy_from_slice(new_name);
        std::fs::write(&self.image, bytes).unwrap();
    }

    fn destination(&self) -> PathBuf {
        self.root.join("results")
    }

    fn collect(&self, bounds: OutputBounds) -> Result<CollectedOutputs, OutputRefusal> {
        collect_from_ext4(&OutputCollection {
            image: &self.image,
            destination: &self.destination(),
            bounds,
        })
    }
}

fn generous() -> OutputBounds {
    OutputBounds {
        max_bytes: 1 << 20,
        max_entries: 1000,
    }
}

/// A refused collection leaves nothing: no destination, no manifest.
fn assert_nothing_left(fixture: &Fixture) {
    let destination = fixture.destination();
    assert!(
        !destination.exists(),
        "a refused collection must not leave {}",
        destination.display()
    );
    assert!(!manifest_path_for(&destination).exists());
}

fn sha(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

#[test]
fn regular_files_and_directories_are_collected_with_their_manifest() {
    let fixture = Fixture::new();
    fixture.write(|fs| {
        fs.apply_mkdir("/logs", 0o755).unwrap();
        fs.apply_mkdir("/empty", 0o700).unwrap();
    });
    fixture.file("/result.json", b"{\"ok\":true}");
    fixture.file("/logs/run.txt", b"done\n");

    let collected = fixture.collect(generous()).expect("a plain tree collects");

    let destination = fixture.destination();
    assert_eq!(
        std::fs::read(destination.join("result.json")).unwrap(),
        b"{\"ok\":true}"
    );
    assert_eq!(
        std::fs::read(destination.join("logs/run.txt")).unwrap(),
        b"done\n"
    );
    assert!(destination.join("empty").is_dir());

    let expected = OutputManifest::from_entries(vec![
        OutputEntry {
            path: "empty".into(),
            kind: OutputEntryKind::Directory,
        },
        OutputEntry {
            path: "logs".into(),
            kind: OutputEntryKind::Directory,
        },
        OutputEntry {
            path: "logs/run.txt".into(),
            kind: OutputEntryKind::File {
                size: 5,
                sha256: sha(b"done\n"),
            },
        },
        OutputEntry {
            path: "result.json".into(),
            kind: OutputEntryKind::File {
                size: 11,
                sha256: sha(b"{\"ok\":true}"),
            },
        },
    ])
    .unwrap();
    assert_eq!(collected.manifest, expected);
    assert_eq!(collected.manifest_path, manifest_path_for(&destination));
    let written: OutputManifest =
        serde_json::from_slice(&std::fs::read(&collected.manifest_path).unwrap()).unwrap();
    assert_eq!(written, expected);
}

#[test]
fn an_empty_existing_destination_is_filled() {
    let fixture = Fixture::new();
    fixture.file("/a", b"1");
    std::fs::create_dir(fixture.destination()).unwrap();
    fixture
        .collect(generous())
        .expect("an empty directory is usable");
    assert_eq!(
        std::fs::read(fixture.destination().join("a")).unwrap(),
        b"1"
    );
}

#[test]
fn a_symlink_is_refused_and_never_followed() {
    let fixture = Fixture::new();
    let outside = fixture.root.join("outside");
    std::fs::create_dir(&outside).unwrap();
    fixture.write(|fs| {
        fs.apply_symlink(outside.to_str().unwrap(), "/escape")
            .unwrap();
    });
    fixture.file("/escape-target-name", b"x");

    let refusal = fixture.collect(generous()).unwrap_err();
    assert!(
        matches!(
            refusal,
            OutputRefusal::EntryType {
                kind: "symlink",
                ..
            }
        ),
        "{refusal}"
    );
    assert_eq!(refusal.audit_tag(), "symlink");
    assert_nothing_left(&fixture);
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
}

#[test]
fn device_nodes_fifos_and_sockets_are_refused() {
    for (mode, kind) in [
        (S_IFCHR | 0o644, "character_device"),
        (S_IFIFO | 0o644, "fifo"),
        (S_IFSOCK | 0o644, "socket"),
    ] {
        let fixture = Fixture::new();
        fixture.file("/fine", b"ok");
        fixture.write(|fs| {
            fs.apply_mknod("/special", mode, 1, 3).unwrap();
        });
        let refusal = fixture.collect(generous()).unwrap_err();
        match &refusal {
            OutputRefusal::EntryType { kind: got, path } => {
                assert_eq!(*got, kind);
                assert_eq!(path, "special");
            }
            other => panic!("expected {kind} refusal, got {other}"),
        }
        assert_nothing_left(&fixture);
    }
}

#[test]
fn a_planted_dot_dot_entry_is_refused() {
    let fixture = Fixture::new();
    fixture.file("/zq", b"escape");
    fixture.patch_entry(b"zq", b"..", None);
    let refusal = fixture.collect(generous()).unwrap_err();
    assert!(
        matches!(
            refusal,
            OutputRefusal::Path {
                rule: PathRule::Traversal,
                ..
            }
        ),
        "{refusal}"
    );
    assert_nothing_left(&fixture);
}

#[test]
fn a_name_carrying_a_separator_refuses_the_whole_image() {
    let fixture = Fixture::new();
    fixture.file("/zq", b"escape");
    fixture.patch_entry(b"zq", b"a/", None);
    let refusal = fixture.collect(generous()).unwrap_err();
    // The reader rejects the entry as corrupt before a name reaches the rules;
    // either way the collection is refused rather than partly taken.
    assert!(
        matches!(
            refusal,
            OutputRefusal::Unreadable { .. }
                | OutputRefusal::Path {
                    rule: PathRule::Separator,
                    ..
                }
        ),
        "{refusal}"
    );
    assert_nothing_left(&fixture);
}

#[test]
fn a_directory_entry_that_disagrees_with_its_inode_is_refused() {
    // The listing says regular file; the inode is a symlink. Trusting the
    // listing alone would copy a link's target path out as file content.
    let fixture = Fixture::new();
    fixture.write(|fs| {
        fs.apply_symlink("/etc/shadow", "/zq").unwrap();
    });
    fixture.patch_entry(b"zq", b"zq", Some(1));
    let refusal = fixture.collect(generous()).unwrap_err();
    assert!(
        matches!(refusal, OutputRefusal::TypeMismatch { .. }),
        "{refusal}"
    );
    assert_nothing_left(&fixture);
}

#[test]
fn exceeding_the_byte_bound_refuses_everything() {
    let fixture = Fixture::new();
    fixture.file("/small", b"12345");
    fixture.file("/large", &[7u8; 2000]);
    let refusal = fixture
        .collect(OutputBounds {
            max_bytes: 2004,
            max_entries: 1000,
        })
        .unwrap_err();
    assert!(
        matches!(refusal, OutputRefusal::ByteBound { max_bytes: 2004 }),
        "{refusal}"
    );
    assert!(refusal.to_string().contains("2004-byte bound"), "{refusal}");
    assert_nothing_left(&fixture);
}

#[test]
fn exceeding_the_entry_bound_refuses_everything() {
    let fixture = Fixture::new();
    fixture.write(|fs| fs.apply_mkdir("/d", 0o755).map(|_| ()).unwrap());
    for name in ["/d/1", "/d/2", "/d/3", "/d/4"] {
        fixture.file(name, b"x");
    }
    let refusal = fixture
        .collect(OutputBounds {
            max_bytes: 1 << 20,
            max_entries: 4,
        })
        .unwrap_err();
    assert!(
        matches!(refusal, OutputRefusal::EntryBound { max_entries: 4 }),
        "{refusal}"
    );
    assert!(refusal.to_string().contains("4-entry bound"), "{refusal}");
    assert_nothing_left(&fixture);

    // Exactly at the bound is admitted.
    fixture
        .collect(OutputBounds {
            max_bytes: 1 << 20,
            max_entries: 5,
        })
        .expect("five entries fit a five-entry bound");
}

#[test]
fn a_file_linked_under_two_names_is_charged_twice() {
    let fixture = Fixture::new();
    fixture.file("/original", &[1u8; 600]);
    fixture.write(|fs| fs.apply_link("/original", "/alias").unwrap());
    let refusal = fixture
        .collect(OutputBounds {
            max_bytes: 1000,
            max_entries: 10,
        })
        .unwrap_err();
    assert!(
        matches!(refusal, OutputRefusal::ByteBound { .. }),
        "{refusal}"
    );
    assert_nothing_left(&fixture);

    let collected = fixture.collect(generous()).expect("within bounds");
    assert_eq!(collected.manifest.total_bytes, 1200);
    let original = fixture.destination().join("original");
    let alias = fixture.destination().join("alias");
    use std::os::unix::fs::MetadataExt as _;
    assert_ne!(
        std::fs::metadata(&original).unwrap().ino(),
        std::fs::metadata(&alias).unwrap().ino(),
        "the host must receive two files, never an alias"
    );
}

#[test]
fn a_populated_destination_is_refused_and_left_untouched() {
    let fixture = Fixture::new();
    fixture.file("/a", b"new");
    std::fs::create_dir(fixture.destination()).unwrap();
    std::fs::write(fixture.destination().join("keep"), b"mine").unwrap();
    let refusal = fixture.collect(generous()).unwrap_err();
    assert!(
        matches!(refusal, OutputRefusal::DestinationNotEmpty { .. }),
        "{refusal}"
    );
    assert_eq!(
        std::fs::read(fixture.destination().join("keep")).unwrap(),
        b"mine"
    );
    assert!(!fixture.destination().join("a").exists());
}

#[test]
fn an_existing_manifest_is_refused_before_anything_is_written() {
    let fixture = Fixture::new();
    fixture.file("/a", b"new");
    let manifest = manifest_path_for(&fixture.destination());
    std::fs::write(&manifest, b"previous").unwrap();
    let refusal = fixture.collect(generous()).unwrap_err();
    assert!(
        matches!(refusal, OutputRefusal::ManifestExists { .. }),
        "{refusal}"
    );
    assert_eq!(std::fs::read(&manifest).unwrap(), b"previous");
    assert!(!fixture.destination().exists());
}

#[test]
fn a_symlinked_destination_is_refused_not_followed() {
    let fixture = Fixture::new();
    fixture.file("/a", b"new");
    let elsewhere = fixture.root.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, fixture.destination()).unwrap();
    let refusal = fixture.collect(generous()).unwrap_err();
    assert!(
        matches!(refusal, OutputRefusal::DestinationNotDirectory { .. }),
        "{refusal}"
    );
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
}

#[test]
fn a_destination_behind_a_linked_parent_is_refused() {
    let fixture = Fixture::new();
    fixture.file("/a", b"new");
    let real = fixture.root.join("real");
    std::fs::create_dir(&real).unwrap();
    let link = fixture.root.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let refusal = collect_from_ext4(&OutputCollection {
        image: &fixture.image,
        destination: &link.join("results"),
        bounds: generous(),
    })
    .unwrap_err();
    assert!(
        matches!(refusal, OutputRefusal::DestinationMoved { .. }),
        "{refusal}"
    );
    assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0);
}

#[test]
fn a_bytes_that_are_not_an_ext4_image_refuse_as_unreadable() {
    let fixture = Fixture::new();
    std::fs::write(&fixture.image, vec![0u8; 8192]).unwrap();
    let refusal = fixture.collect(generous()).unwrap_err();
    assert!(
        matches!(refusal, OutputRefusal::Unreadable { .. }),
        "{refusal}"
    );
    assert_nothing_left(&fixture);
}

#[test]
fn availability_check_accepts_absent_and_empty_and_refuses_the_rest() {
    let fixture = Fixture::new();
    let destination = fixture.destination();
    check_destination_available(&destination).expect("absent is available");
    std::fs::create_dir(&destination).unwrap();
    check_destination_available(&destination).expect("empty is available");
    std::fs::write(destination.join("x"), b"").unwrap();
    assert!(matches!(
        check_destination_available(&destination),
        Err(OutputRefusal::DestinationNotEmpty { .. })
    ));
    let file = fixture.root.join("plain-file");
    std::fs::write(&file, b"").unwrap();
    assert!(matches!(
        check_destination_available(&file),
        Err(OutputRefusal::DestinationNotDirectory { .. })
    ));
    assert!(matches!(
        check_destination_available(Path::new("/")),
        Err(OutputRefusal::DestinationNotDirectory { .. })
    ));
}
