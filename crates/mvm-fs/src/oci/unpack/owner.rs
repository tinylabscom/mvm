//! Reading the owner a tar entry declares.
//!
//! The ustar header carries uid and gid in octal (or base-256) fields; a pax
//! `uid` / `gid` record, when present, supersedes them — that is how producers
//! spell an id too large for the header. The host unpack cannot apply the owner
//! (it runs unprivileged), so the value is only recorded, for the image writer.

use std::io::Read;

use crate::ext4::Owner;

use super::RefusalReason;

/// The owner `entry` declares. An id that does not fit the 32 bits ext4 stores,
/// or a pax record that is not a decimal number, refuses the entry as
/// malformed rather than being truncated into someone else's id.
pub(super) fn entry_owner<R: Read>(entry: &mut tar::Entry<R>) -> Result<Owner, RefusalReason> {
    let header = entry.header();
    let mut uid = header.uid().map_err(|_| RefusalReason::MalformedHeader)?;
    let mut gid = header.gid().map_err(|_| RefusalReason::MalformedHeader)?;

    if let Some(extensions) = entry
        .pax_extensions()
        .map_err(|_| RefusalReason::MalformedHeader)?
    {
        for extension in extensions {
            let extension = extension.map_err(|_| RefusalReason::MalformedHeader)?;
            match extension.key_bytes() {
                b"uid" => uid = parse_pax_id(extension.value_bytes())?,
                b"gid" => gid = parse_pax_id(extension.value_bytes())?,
                _ => {}
            }
        }
    }

    Ok(Owner::new(narrow_id(uid)?, narrow_id(gid)?))
}

fn parse_pax_id(value: &[u8]) -> Result<u64, RefusalReason> {
    std::str::from_utf8(value)
        .ok()
        .filter(|text| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|text| text.parse::<u64>().ok())
        .ok_or(RefusalReason::MalformedHeader)
}

fn narrow_id(id: u64) -> Result<u32, RefusalReason> {
    u32::try_from(id).map_err(|_| RefusalReason::MalformedHeader)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::io::Cursor;
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::super::test_support::build_tar;
    use super::super::{
        RefusalReason, UnpackOptions, UnpackReport, unpack_layer, unpack_layer_with_prior_paths,
    };
    use crate::ext4::Owner;
    use crate::ownership::OwnerTable;

    fn header(path: &str, kind: tar::EntryType, uid: u64, gid: u64) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).unwrap();
        header.set_size(0);
        header.set_mode(if kind == tar::EntryType::Directory {
            0o755
        } else {
            0o644
        });
        header.set_entry_type(kind);
        header.set_uid(uid);
        header.set_gid(gid);
        header
    }

    fn add_owned(
        builder: &mut tar::Builder<Cursor<Vec<u8>>>,
        path: &str,
        kind: tar::EntryType,
        uid: u64,
        gid: u64,
    ) {
        let mut header = header(path, kind, uid, gid);
        header.set_cksum();
        builder.append(&header, std::io::empty()).unwrap();
    }

    fn add_link_owned(
        builder: &mut tar::Builder<Cursor<Vec<u8>>>,
        path: &str,
        kind: tar::EntryType,
        target: &str,
        owner: (u64, u64),
    ) {
        let mut header = header(path, kind, owner.0, owner.1);
        header.set_link_name(target).unwrap();
        header.set_cksum();
        builder.append(&header, std::io::empty()).unwrap();
    }

    fn unpack(tar: Vec<u8>, root: &TempDir) -> UnpackReport {
        let report =
            unpack_layer(Cursor::new(tar), root.path(), &UnpackOptions::default()).expect("unpack");
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        report
    }

    fn table_after(layers: Vec<Vec<u8>>) -> OwnerTable {
        let root = TempDir::new().unwrap();
        let mut prior: HashSet<PathBuf> = HashSet::new();
        let mut table = OwnerTable::new();
        for layer in layers {
            let report = unpack_layer_with_prior_paths(
                Cursor::new(layer),
                root.path(),
                &UnpackOptions::default(),
                &prior,
            )
            .expect("unpack");
            assert!(report.refused.is_empty(), "{:?}", report.refused);
            prior.extend(report.paths_written.iter().cloned());
            table.absorb(&report.ownership);
        }
        table
    }

    #[test]
    fn header_owners_are_recorded_for_every_materialized_kind() {
        let root = TempDir::new().unwrap();
        let report = unpack(
            build_tar(|b| {
                add_owned(b, "var/lib/svc/", tar::EntryType::Directory, 999, 999);
                add_owned(b, "var/lib/svc/state", tar::EntryType::Regular, 999, 998);
                add_link_owned(
                    b,
                    "var/lib/svc/current",
                    tar::EntryType::Symlink,
                    "state",
                    (997, 996),
                );
            }),
            &root,
        );
        let mut table = OwnerTable::new();
        table.absorb(&report.ownership);
        assert_eq!(table.owner_of("/var/lib/svc"), Owner::new(999, 999));
        assert_eq!(table.owner_of("/var/lib/svc/state"), Owner::new(999, 998));
        assert_eq!(table.owner_of("/var/lib/svc/current"), Owner::new(997, 996));
        assert_eq!(
            table.owner_of("/var/lib"),
            Owner::ROOT,
            "a parent the stream only implied stays root-owned"
        );
    }

    #[test]
    fn a_pax_owner_supersedes_the_header() {
        let root = TempDir::new().unwrap();
        let report = unpack(
            build_tar(|b| {
                b.append_pax_extensions([("uid", b"3000000".as_slice()), ("gid", b"4000000")])
                    .unwrap();
                add_owned(b, "big", tar::EntryType::Regular, 1, 1);
            }),
            &root,
        );
        let mut table = OwnerTable::new();
        table.absorb(&report.ownership);
        assert_eq!(table.owner_of("/big"), Owner::new(3_000_000, 4_000_000));
    }

    #[test]
    fn an_id_past_32_bits_refuses_the_entry() {
        let root = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(build_tar(|b| {
                b.append_pax_extensions([("uid", b"4294967296".as_slice())])
                    .unwrap();
                add_owned(b, "wide", tar::EntryType::Regular, 0, 0);
            })),
            root.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack");
        assert_eq!(report.refused.len(), 1);
        assert_eq!(report.refused[0].reason, RefusalReason::MalformedHeader);
        assert!(!root.path().join("wide").exists());
    }

    #[test]
    fn a_non_numeric_pax_owner_refuses_the_entry() {
        let root = TempDir::new().unwrap();
        let report = unpack_layer(
            Cursor::new(build_tar(|b| {
                b.append_pax_extensions([("gid", b"-1".as_slice())])
                    .unwrap();
                add_owned(b, "odd", tar::EntryType::Regular, 0, 0);
            })),
            root.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack");
        assert_eq!(report.refused.len(), 1);
        assert_eq!(report.refused[0].reason, RefusalReason::MalformedHeader);
    }

    #[test]
    fn a_hardlink_shares_its_owner_with_the_target() {
        let table = table_after(vec![build_tar(|b| {
            add_owned(b, "bin/", tar::EntryType::Directory, 0, 0);
            add_owned(b, "bin/tool", tar::EntryType::Regular, 0, 0);
            add_link_owned(b, "bin/alias", tar::EntryType::Link, "bin/tool", (999, 999));
        })]);
        assert_eq!(table.owner_of("/bin/alias"), Owner::new(999, 999));
        assert_eq!(table.owner_of("/bin/tool"), Owner::new(999, 999));
    }

    #[test]
    fn layer_whiteouts_and_overrides_reach_the_table() {
        let table = table_after(vec![
            build_tar(|b| {
                add_owned(b, "srv/", tar::EntryType::Directory, 999, 999);
                add_owned(b, "srv/old", tar::EntryType::Regular, 999, 999);
                add_owned(b, "srv/kept", tar::EntryType::Regular, 999, 999);
                add_owned(b, "opt/", tar::EntryType::Directory, 999, 999);
                add_owned(b, "opt/lower", tar::EntryType::Regular, 999, 999);
                add_owned(b, "etc/", tar::EntryType::Directory, 0, 0);
                add_owned(b, "etc/app.conf", tar::EntryType::Regular, 999, 999);
            }),
            build_tar(|b| {
                add_owned(b, "srv/.wh.old", tar::EntryType::Regular, 0, 0);
                add_owned(b, "opt/.wh..wh..opq", tar::EntryType::Regular, 0, 0);
                add_owned(b, "opt/upper", tar::EntryType::Regular, 1000, 1000);
                add_owned(b, "etc/app.conf", tar::EntryType::Regular, 0, 0);
            }),
        ]);
        assert_eq!(table.owner_of("/srv/old"), Owner::ROOT, "whited out");
        assert_eq!(table.owner_of("/srv/kept"), Owner::new(999, 999));
        assert_eq!(
            table.owner_of("/opt"),
            Owner::new(999, 999),
            "opaque keeps the dir"
        );
        assert_eq!(
            table.owner_of("/opt/lower"),
            Owner::ROOT,
            "opaque clears lower"
        );
        assert_eq!(table.owner_of("/opt/upper"), Owner::new(1000, 1000));
        assert_eq!(
            table.owner_of("/etc/app.conf"),
            Owner::ROOT,
            "last writer wins"
        );
    }
}
