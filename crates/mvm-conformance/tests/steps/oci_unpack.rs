//! Step definitions for OCI image layer materialization scenarios.
//!
//! These steps exercise `mvm_fs::oci::unpack_layer_with_prior_paths` directly
//! so multi-layer semantics stay covered without requiring a live registry or
//! a full microVM boot for every scenario.

use std::io::Cursor;

use cucumber::{given, then, when};

use crate::world::CliWorld;

/// Build an in-memory tar archive from a Gherkin data table.
///
/// Columns: `path`, `kind`, `content`. Supported kinds:
/// - `file` — a regular file whose contents come from the `content` cell.
/// - `directory` — a directory entry; `content` is ignored.
/// - `whiteout` — a whiteout marker file; the path itself (e.g. `.wh.foo.txt`)
///   triggers the unpacker's whiteout logic.
fn build_layer_tar(table: &cucumber::gherkin::Table) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut buf);
        let rows = &table.rows;
        assert!(
            rows.len() > 1,
            "layer table must have a header and at least one data row"
        );
        let header = &rows[0];
        let col = |name: &str| {
            header
                .iter()
                .position(|h| h.eq_ignore_ascii_case(name))
                .unwrap_or_else(|| panic!("layer table missing {name:?} column"))
        };
        let path_idx = col("path");
        let kind_idx = col("kind");

        for row in rows.iter().skip(1) {
            let path = &row[path_idx];
            let kind = row[kind_idx].to_ascii_lowercase();
            let content = row.get(col("content")).map(String::as_str).unwrap_or("");

            match kind.as_str() {
                "file" | "whiteout" => {
                    let data = if kind == "whiteout" {
                        &[][..]
                    } else {
                        content.as_bytes()
                    };
                    let mut header = tar::Header::new_gnu();
                    header.set_size(data.len() as u64);
                    header.set_mode(0o644);
                    header.set_entry_type(tar::EntryType::Regular);
                    builder
                        .append_data(&mut header, path, data)
                        .expect("append tar entry");
                }
                "directory" => {
                    let mut header = tar::Header::new_gnu();
                    header.set_size(0);
                    header.set_mode(0o755);
                    header.set_entry_type(tar::EntryType::Directory);
                    builder
                        .append_data(&mut header, path, std::io::empty())
                        .expect("append tar directory");
                }
                other => panic!("unknown layer entry kind {other:?}"),
            }
        }
        builder.finish().expect("finish tar archive");
    }
    buf
}

#[given(expr = "an empty OCI unpack root")]
fn empty_unpack_root(world: &mut CliWorld) {
    world.unpack_root = Some(tempfile::tempdir().expect("create unpack root"));
    world.prior_layer_paths.clear();
    world.last_unpack_report = None;
}

#[when(expr = "I unpack a layer containing:")]
fn unpack_layer(world: &mut CliWorld, step: &cucumber::gherkin::Step) {
    let root = world
        .unpack_root
        .as_ref()
        .expect("unpack root must be created first")
        .path();
    let table = step
        .table()
        .expect("layer entries must be given as a data table");
    let tar_bytes = build_layer_tar(table);

    let report = mvm_fs::oci::unpack_layer_with_prior_paths(
        Cursor::new(tar_bytes),
        root,
        &mvm_fs::oci::UnpackOptions::default(),
        &world.prior_layer_paths,
    )
    .expect("layer unpack should succeed");

    world.prior_layer_paths.extend(report.paths_written.clone());
    world.last_unpack_report = Some(report);
}

#[then(expr = "the path {string} exists as a file")]
fn path_exists_as_file(world: &mut CliWorld, rel: String) {
    let root = world
        .unpack_root
        .as_ref()
        .expect("unpack root must be created first")
        .path();
    let path = root.join(&rel);
    assert!(
        path.is_file(),
        "expected {rel:?} to be a file under {root:?}"
    );
}

#[then(expr = "the path {string} exists as a directory")]
fn path_exists_as_directory(world: &mut CliWorld, rel: String) {
    let root = world
        .unpack_root
        .as_ref()
        .expect("unpack root must be created first")
        .path();
    let path = root.join(&rel);
    assert!(
        path.is_dir(),
        "expected {rel:?} to be a directory under {root:?}"
    );
}

#[then(expr = "the path {string} does not exist")]
fn path_does_not_exist(world: &mut CliWorld, rel: String) {
    let root = world
        .unpack_root
        .as_ref()
        .expect("unpack root must be created first")
        .path();
    let path = root.join(&rel);
    assert!(
        !path.exists(),
        "expected {rel:?} to not exist under {root:?}"
    );
}

#[then(expr = "the path {string} contains {string}")]
fn path_contains(world: &mut CliWorld, rel: String, expected: String) {
    let root = world
        .unpack_root
        .as_ref()
        .expect("unpack root must be created first")
        .path();
    let path = root.join(&rel);
    let contents = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel:?}: {e}"));
    assert!(
        contents == expected,
        "expected {rel:?} to contain {expected:?}, got {contents:?}"
    );
}

#[then(expr = "the unpack report has {int} refused entries")]
fn unpack_report_refused_count(world: &mut CliWorld, count: i64) {
    let report = world
        .last_unpack_report
        .as_ref()
        .expect("an unpack step must have run first");
    assert_eq!(
        report.refused.len(),
        count as usize,
        "unexpected refused entry count: {:?}",
        report.refused
    );
}
