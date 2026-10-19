// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// In-memory tests of the apple-codesign adaptation. See ../PROVENANCE.md.

use super::*;
use sha1::Digest as _;
use sha2::Digest as _;

pub(super) fn fixture(little: bool, wide: bool, minimum: u32) -> Vec<u8> {
    let header = if wide { 32 } else { 28 };
    let segment = if wide { 72 } else { 56 };
    let section = if wide { 80 } else { 68 };
    let mut bytes = vec![0; 4098];
    let word = |bytes: &mut [u8], at: usize, value: u32| {
        let value = if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        };
        bytes[at..at + 4].copy_from_slice(&value);
    };
    let wide_word = |bytes: &mut [u8], at: usize, value: u64| {
        if wide {
            let value = if little {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            };
            bytes[at..at + 8].copy_from_slice(&value);
        } else {
            word(bytes, at, value as u32);
        }
    };
    for (at, value) in [
        (0, if wide { 0xfeed_facf } else { 0xfeed_face }),
        (4, if wide { 0x0100_0007 } else { 7 }),
        (8, 3),
        (12, 2),
        (16, 3),
        (20, (2 * segment + section + 24) as u32),
    ] {
        word(&mut bytes, at, value);
    }
    for (at, name, offset, length, sections) in [
        (header, b"__TEXT".as_slice(), 0, 4096, 1),
        (
            header + segment + section,
            b"__LINKEDIT".as_slice(),
            4096,
            2,
            0,
        ),
    ] {
        word(&mut bytes, at, if wide { 0x19 } else { 1 });
        word(&mut bytes, at + 4, (segment + sections * section) as u32);
        bytes[at + 8..at + 8 + name.len()].copy_from_slice(name);
        let width = if wide { 8 } else { 4 };
        for (field, value) in [
            (24, 0x400000 + offset),
            (24 + width, length),
            (24 + 2 * width, offset),
            (24 + 3 * width, length),
        ] {
            wide_word(&mut bytes, at + field, value);
        }
        word(&mut bytes, at + 24 + 4 * width, 5);
        word(&mut bytes, at + 28 + 4 * width, 5);
        word(&mut bytes, at + 32 + 4 * width, sections as u32);
    }
    let at = header + segment;
    bytes[at..at + 12].copy_from_slice(b"__info_plist");
    bytes[at + 16..at + 22].copy_from_slice(b"__TEXT");
    wide_word(&mut bytes, at + 32, 0x400200);
    wide_word(&mut bytes, at + if wide { 40 } else { 36 }, 4);
    word(&mut bytes, at + if wide { 48 } else { 40 }, 512);
    bytes[512..516].copy_from_slice(b"info");
    let at = header + 2 * segment + section;
    for (field, value) in [(0, 0x32), (4, 24), (8, 1), (12, minimum), (16, 0x000e_0000)] {
        word(&mut bytes, at + field, value);
    }
    bytes
}
fn entitlements() -> plist::Value {
    let mut dict = plist::Dictionary::new();
    dict.insert(
        "com.apple.security.hypervisor".into(),
        plist::Value::Boolean(true),
    );
    plist::Value::Dictionary(dict)
}
pub(super) fn assert_hashes(slice: &Slice<'_>) {
    let blobs = slice.signature_blobs().unwrap();
    for (slot, cd) in &blobs {
        if *slot != 0 && *slot != 0x1000 {
            continue;
        }
        let hash = |data: &[u8]| -> Vec<u8> {
            if cd[37] == 1 {
                sha1::Sha1::digest(data).to_vec()
            } else {
                sha2::Sha256::digest(data).to_vec()
            }
        };
        let width = cd[36] as usize;
        let offset = be32(cd, 16).unwrap() as usize;
        let limit = be32(cd, 32).unwrap() as usize;
        assert_eq!(be32(cd, 28).unwrap() as usize, limit.div_ceil(4096));
        for (index, page) in slice.data[..limit].chunks(4096).enumerate() {
            assert_eq!(
                &cd[offset + index * width..offset + (index + 1) * width],
                hash(page)
            );
        }
        for slot in 1..=be32(cd, 24).unwrap() {
            let expected = if slot == 1 {
                hash(b"info")
            } else if let Some(blob) = blobs.get(&slot) {
                hash(blob)
            } else {
                vec![0; width]
            };
            let start = offset - slot as usize * width;
            assert_eq!(&cd[start..start + width], expected);
        }
    }
}
#[test]
fn thin_signed_unsigned_all_layouts_and_special_slot_digests() {
    for little in [true, false] {
        for wide in [true, false] {
            for minimum in [0x000a_0a00, 0x000e_0000] {
                let signed = sign(&fixture(little, wide, minimum), &entitlements()).unwrap();
                let parsed = slices(&signed).unwrap();
                assert_hashes(&parsed[0]);
                let blobs = parsed[0].signature_blobs().unwrap();
                assert_eq!(blobs.contains_key(&0x1000), minimum < 0x000a_0b04);
                assert_eq!(
                    plist::Value::from_reader_xml(&blobs[&5][8..]).unwrap(),
                    decode_entitlements_der(&blobs[&7][8..]).unwrap()
                );
                assert_eq!(signed, sign(&signed, &entitlements()).unwrap());
            }
        }
    }
}
#[test]
fn universal_legacy_compatibility_and_every_slice_rewrite() {
    let fat = universal_binary(&[
        fixture(true, true, 0x000a_0a00),
        fixture(false, false, 0x000e_0000),
    ])
    .unwrap();
    let signed = sign(&fat, &entitlements()).unwrap();
    assert_eq!(slices(&signed).unwrap().len(), 2);
    for slice in slices(&signed).unwrap() {
        assert_hashes(&slice);
        assert_eq!(slice.code_directory().unwrap().unwrap().digest_type, 1);
        assert!(slice.signature_blobs().unwrap().contains_key(&0x1000));
    }
}
#[test]
fn no_command_room_is_a_typed_refusal() {
    let mut bytes = fixture(true, true, 0x000e_0000);
    bytes[280] = 1;
    assert_eq!(
        sign(&bytes, &entitlements()).unwrap_err(),
        Error::NoSignatureCommandRoom
    );
}
#[test]
fn malformed_truncated_and_fat_alignment_inputs_refuse_without_panicking() {
    let original = fixture(true, true, 0x000e_0000);
    for end in [0, 1, 4, 28, 32, 100, 4096, 4097] {
        assert!(sign(&original[..end], &entitlements()).is_err());
    }
    let fat = universal_binary(&[original]).unwrap();
    for (at, value) in [(4, u32::MAX), (8, 99), (16, 8), (20, u32::MAX), (24, 63)] {
        let mut bad = fat.clone();
        put32(&mut bad, at, value);
        assert!(slices(&bad).is_err());
    }
}
#[test]
fn file_backed_sections_must_stay_within_their_segment() {
    for little in [true, false] {
        for wide in [true, false] {
            let original = fixture(little, wide, 0x000e_0000);
            assert!(slices(&original).is_ok());
            let header = if wide { 32 } else { 28 };
            let segment = if wide { 72 } else { 56 };
            let section = header + segment;
            let offset_field = section + if wide { 48 } else { 40 };
            let length_field = section + if wide { 40 } else { 36 };
            for (offset, length) in [(4096u32, 2u64), (4095, 3), (512, u64::MAX)] {
                let mut bad = original.clone();
                let offset = if little {
                    offset.to_le_bytes()
                } else {
                    offset.to_be_bytes()
                };
                bad[offset_field..offset_field + 4].copy_from_slice(&offset);
                let length = if little {
                    length.to_le_bytes()
                } else {
                    length.to_be_bytes()
                };
                if wide {
                    bad[length_field..length_field + 8].copy_from_slice(&length);
                } else {
                    let length = if little { &length[..4] } else { &length[4..] };
                    bad[length_field..length_field + 4].copy_from_slice(length);
                }
                assert!(
                    slices(&bad).is_err(),
                    "file-backed section escapes __TEXT: little={little}, wide={wide}"
                );
            }
        }
    }
}

#[test]
fn section_segment_boundaries_and_zero_fill_are_distinct() {
    for little in [true, false] {
        for wide in [true, false] {
            let original = fixture(little, wide, 0x000e_0000);
            let header = if wide { 32 } else { 28 };
            let segment = if wide { 72 } else { 56 };
            let section = header + segment;
            let write_word = |bytes: &mut [u8], at, value: u32| {
                let value = if little {
                    value.to_le_bytes()
                } else {
                    value.to_be_bytes()
                };
                bytes[at..at + 4].copy_from_slice(&value);
            };
            let mut bounded = original.clone();
            if wide {
                let encode = |value: u64| {
                    if little {
                        value.to_le_bytes()
                    } else {
                        value.to_be_bytes()
                    }
                };
                bounded[header + 40..header + 48].copy_from_slice(&encode(512));
                bounded[header + 48..header + 56].copy_from_slice(&encode(4));
            } else {
                write_word(&mut bounded, header + 32, 512);
                write_word(&mut bounded, header + 36, 4);
            }
            assert!(slices(&bounded).is_ok(), "exact segment boundary");
            write_word(&mut bounded, section + if wide { 48 } else { 40 }, 511);
            assert!(slices(&bounded).is_err(), "section begins before segment");
            for kind in [1, 0xc, 0x12] {
                let mut zero_fill = original.clone();
                write_word(
                    &mut zero_fill,
                    section + if wide { 48 } else { 40 },
                    u32::MAX,
                );
                write_word(&mut zero_fill, section + if wide { 64 } else { 56 }, kind);
                assert!(slices(&zero_fill).is_ok(), "zero-fill type {kind:#x}");
            }
        }
    }
}

#[test]
fn library_emits_matching_encodings_without_executable_flags() {
    let mut bytes = fixture(true, true, 0x000e_0000);
    bytes[12..16].copy_from_slice(&6u32.to_le_bytes());
    let signed = sign(&bytes, &entitlements()).unwrap();
    let parsed = slices(&signed).unwrap();
    let blobs = parsed[0].signature_blobs().unwrap();
    assert_eq!(&blobs[&0][80..88], &[0; 8]);
    assert_hashes(&parsed[0]);
}
#[test]
fn upstream_der_boolean_vectors_and_truncation() {
    for (boolean, byte) in [(false, 0), (true, 255)] {
        let mut dict = plist::Dictionary::new();
        dict.insert("key".into(), plist::Value::Boolean(boolean));
        let value = plist::Value::Dictionary(dict);
        let bytes = [
            112, 15, 2, 1, 1, 176, 10, 48, 8, 12, 3, 107, 101, 121, 1, 1, byte,
        ];
        assert_eq!(encode_entitlements_der(&value).unwrap(), bytes);
        assert_eq!(decode_entitlements_der(&bytes).unwrap(), value);
        for end in 0..bytes.len() {
            assert!(decode_entitlements_der(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(decode_entitlements_der(&trailing).is_err());
    }
}

#[test]
fn fat64_both_byte_orders_and_reserved_field_refusal() {
    let thin = fixture(true, true, 0x000e_0000);
    for little in [false, true] {
        let mut fat = vec![0; 16384];
        let word = |bytes: &mut [u8], at: usize, value: u32| {
            let value = if little {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            };
            bytes[at..at + 4].copy_from_slice(&value);
        };
        let wide = |bytes: &mut [u8], at: usize, value: u64| {
            let value = if little {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            };
            bytes[at..at + 8].copy_from_slice(&value);
        };
        for (at, value) in [
            (0, 0xcafe_babf),
            (4, 1),
            (8, 0x0100_0007),
            (12, 3),
            (32, 14),
        ] {
            word(&mut fat, at, value);
        }
        wide(&mut fat, 16, 16384);
        wide(&mut fat, 24, thin.len() as u64);
        fat.extend_from_slice(&thin);
        let signed = sign(&fat, &entitlements()).unwrap();
        let parsed = slices(&signed).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_ne!(parsed[0].offset, 0);
        assert_hashes(&parsed[0]);
        word(&mut fat, 36, 1);
        assert!(slices(&fat).is_err());
    }
}

#[test]
fn malformed_code_directory_and_superblob_tables_refuse() {
    let signed = sign(&fixture(true, true, 0x000e_0000), &entitlements()).unwrap();
    let parsed = slices(&signed).unwrap();
    let blobs = parsed[0].signature_blobs().unwrap();
    let cd = blobs[&0];
    for (at, value) in [
        (20, 8),
        (20, u32::MAX),
        (24, u32::MAX),
        (28, u32::MAX),
        (16, 0),
        (8, 0x20600),
    ] {
        let mut bad = cd.to_vec();
        put32(&mut bad, at, value);
        assert!(CodeDirectory::parse(&bad).is_err());
    }
    let mut bad = cd.to_vec();
    bad[36] = 1;
    assert!(CodeDirectory::parse(&bad).is_err());
    let mut table = vec![0; 44];
    for (at, value) in [
        (0, 0xfade_0cc0),
        (4, 44),
        (8, 2),
        (12, 5),
        (16, 28),
        (20, 7),
        (24, 36),
        (28, 0xfade_7171),
        (32, 8),
        (36, 0xfade_7172),
        (40, 8),
    ] {
        put32(&mut table, at, value);
    }
    assert!(signature_blobs(&table).is_ok());
    for (at, value) in [(20, 5), (24, 28), (16, 12), (40, 9), (32, 7), (8, u32::MAX)] {
        let mut bad = table.clone();
        put32(&mut bad, at, value);
        assert!(signature_blobs(&bad).is_err());
    }
}

#[test]
fn malformed_der_boolean_integer_lengths_and_duplicate_keys_refuse() {
    let cases: &[&[u8]] = &[
        &[0x70, 0x80, 0, 0],
        &[0x70, 0x81, 5, 2, 1, 1, 0xb0, 0],
        &[0x70, 5, 2, 1, 2, 0xb0, 0],
        &[
            112, 15, 2, 1, 1, 176, 10, 48, 8, 12, 3, 107, 101, 121, 1, 1, 1,
        ],
        &[
            112, 16, 2, 1, 1, 176, 11, 48, 9, 12, 3, 107, 101, 121, 2, 2, 0, 1,
        ],
        &[
            112, 25, 2, 1, 1, 176, 20, 48, 8, 12, 3, 107, 101, 121, 1, 1, 255, 48, 8, 12, 3, 107,
            101, 121, 1, 1, 0,
        ],
    ];
    for bytes in cases {
        assert!(decode_entitlements_der(bytes).is_err(), "{bytes:?}");
    }
}
