//! Fixed-offset ELF header checks for the guest binaries.
//!
//! The guest executables are cross-compiled as `*-unknown-linux-musl` statics and
//! injected into a rootfs that has no dynamic loader. A dynamically linked or
//! wrong-architecture binary therefore does not fail here — it fails inside the
//! guest, after boot, as a silent PID 1 that never reaches the agent.
//!
//! These checks read the ELF *header* only: magic, class, data encoding and
//! machine at fixed offsets, then the program-header table for `PT_INTERP` and
//! the dynamic section for `DT_NEEDED`. Nothing walks the section table, and no
//! allocation is driven by a field read out of the file. The inputs are our own
//! build outputs under a mode-0700 cache, not registry or guest bytes, and this
//! deliberately stays too small to be a parser.
//!
//! Guest shared objects are the other kind of artifact: loaded by the guest's
//! own dynamic loader, so they must be dynamic, and must need nothing beyond
//! the libc they were built for. Their `DT_NEEDED` list is read with
//! [`mvm_fs::elf::needed_sonames`], the reader the SDK sidecar check uses.

use std::path::Path;

use mvm_contract::guest_libc::GuestLibc;
use mvm_core::arch::GuestArch;

const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

const EM_X86_64: u16 = 0x3E;
const EM_AARCH64: u16 = 0xB7;

const E_TYPE: usize = 16;
const ET_DYN: u16 = 3;

const PT_INTERP: u32 = 3;
const PT_DYNAMIC: u32 = 2;
const DT_NEEDED: u64 = 1;
const DT_NULL: u64 = 0;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GuestElfError {
    #[error("{path}: not an ELF file")]
    NotElf { path: String },
    #[error("{path}: must be a 64-bit little-endian ELF")]
    NotElf64Le { path: String },
    #[error("{path}: built for ELF machine {found:#x}, but this host's guest is {expected}")]
    WrongMachine {
        path: String,
        found: u16,
        expected: GuestArch,
    },
    #[error(
        "{path}: dynamically linked (has a {kind}), but the guest rootfs has no dynamic loader"
    )]
    Dynamic { path: String, kind: &'static str },
    #[error("{path}: ELF header is truncated")]
    Truncated { path: String },
    #[error("{path}: ELF type {found} is not a shared object (ET_DYN)")]
    NotSharedObject { path: String, found: u16 },
    #[error("{path}: has a PT_INTERP segment, so it is an executable, not a shared object")]
    ExecutableNotLibrary { path: String },
    #[error("{path}: no libc to check a shared object against")]
    UnknownLibc { path: String },
    #[error("{path}: dynamic section unreadable: {reason}")]
    DynamicUnreadable { path: String, reason: String },
    #[error("{path}: a {libc} shared object must need {soname}, but it needs {found:?}")]
    MissingLibc {
        path: String,
        libc: GuestLibc,
        soname: &'static str,
        found: Vec<String>,
    },
    #[error(
        "{path}: needs {soname}, which a {libc} guest is not guaranteed to provide \
         (allowed: {allowed:?})"
    )]
    UnexpectedNeeded {
        path: String,
        libc: GuestLibc,
        soname: String,
        allowed: Vec<&'static str>,
    },
}

fn expected_machine(arch: GuestArch) -> u16 {
    match arch {
        GuestArch::X86_64 => EM_X86_64,
        GuestArch::Aarch64 => EM_AARCH64,
    }
}

/// Read `N` bytes at `off`, or `None` if that range is not wholly inside `b`.
///
/// `off` comes out of the file, so the end offset is computed with
/// `checked_add`: a corrupt `e_phoff` of `u64::MAX` would otherwise overflow
/// the addition before the slice bounds were ever consulted.
fn bytes_at<const N: usize>(b: &[u8], off: usize) -> Option<[u8; N]> {
    let end = off.checked_add(N)?;
    b.get(off..end)?.try_into().ok()
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    bytes_at::<2>(b, off).map(u16::from_le_bytes)
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    bytes_at::<4>(b, off).map(u32::from_le_bytes)
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    bytes_at::<8>(b, off).map(u64::from_le_bytes)
}

/// The ELF64 little-endian identity and machine checks every guest artifact
/// shares: a non-ELF, a 32-bit or big-endian ELF, or the wrong machine is
/// refused before anything else is read.
fn check_guest_elf_header(bytes: &[u8], path: &Path, arch: GuestArch) -> Result<(), GuestElfError> {
    let p = || path.display().to_string();

    if bytes.len() < 4 || bytes[..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(GuestElfError::NotElf { path: p() });
    }
    if bytes.len() < 64 {
        return Err(GuestElfError::Truncated { path: p() });
    }
    if bytes[EI_CLASS] != ELFCLASS64 || bytes[EI_DATA] != ELFDATA2LSB {
        return Err(GuestElfError::NotElf64Le { path: p() });
    }

    let machine = u16_at(bytes, 18).ok_or_else(|| GuestElfError::Truncated { path: p() })?;
    let expected = expected_machine(arch);
    if machine != expected {
        return Err(GuestElfError::WrongMachine {
            path: p(),
            found: machine,
            expected: arch,
        });
    }
    Ok(())
}

/// Reject anything the guest could not execute: a non-ELF, a 32-bit or
/// big-endian ELF, the wrong machine, or a dynamically linked binary.
pub fn validate_static_guest_elf(
    bytes: &[u8],
    path: &Path,
    arch: GuestArch,
) -> Result<(), GuestElfError> {
    let p = || path.display().to_string();
    check_guest_elf_header(bytes, path, arch)?;

    // Program header table: e_phoff@32 (u64), e_phentsize@54, e_phnum@56.
    let phoff = u64_at(bytes, 32).ok_or_else(|| GuestElfError::Truncated { path: p() })? as usize;
    let phentsize =
        u16_at(bytes, 54).ok_or_else(|| GuestElfError::Truncated { path: p() })? as usize;
    let phnum = u16_at(bytes, 56).ok_or_else(|| GuestElfError::Truncated { path: p() })? as usize;

    // `phnum` is bounded by u16 and each entry is read through `get`, so a
    // corrupt count walks off the end and stops rather than allocating.
    for i in 0..phnum {
        let Some(base) = phoff.checked_add(i.saturating_mul(phentsize)) else {
            break;
        };
        let Some(p_type) = u32_at(bytes, base) else {
            break;
        };
        if p_type == PT_INTERP {
            return Err(GuestElfError::Dynamic {
                path: p(),
                kind: "PT_INTERP segment",
            });
        }
        if p_type == PT_DYNAMIC
            && let (Some(off), Some(size)) = (
                u64_at(bytes, base.saturating_add(8)),
                u64_at(bytes, base.saturating_add(32)),
            )
            && has_dt_needed(bytes, off as usize, size as usize)
        {
            return Err(GuestElfError::Dynamic {
                path: p(),
                kind: "DT_NEEDED entry",
            });
        }
    }

    Ok(())
}

/// The sonames a guest shared object built for `libc` may need on `arch`.
///
/// glibc's list is what a cross-compiled Rust cdylib links against plus the
/// arch's loader, which a native toolchain records instead of `libpthread`.
/// Each is part of every glibc install. musl folds threads and the loader into
/// `libc.so`, leaving only the unwinder beside it. Anything else is a library
/// the guest may not carry, discovered only when `dlopen` fails inside it.
pub fn allowed_shared_object_needs(arch: GuestArch, libc: GuestLibc) -> Vec<&'static str> {
    let glibc_loader = match arch {
        GuestArch::Aarch64 => "ld-linux-aarch64.so.1",
        GuestArch::X86_64 => "ld-linux-x86-64.so.2",
    };
    match libc {
        GuestLibc::Glibc => vec![
            "libc.so.6",
            "libpthread.so.0",
            "libgcc_s.so.1",
            glibc_loader,
        ],
        GuestLibc::Musl => vec!["libc.so", "libgcc_s.so.1"],
        GuestLibc::Unknown => Vec::new(),
    }
}

/// Reject anything a `libc` guest on `arch` could not `dlopen`: a non-ELF or
/// wrong-machine object, an executable, or one whose `DT_NEEDED` list does not
/// name `libc`'s soname or names a library outside
/// [`allowed_shared_object_needs`].
///
/// The libc soname is the one witness of which libc an object was really
/// linked against — a build that names a musl target can still link through a
/// glibc driver — so it is required, not merely allowed.
pub fn validate_guest_shared_object(
    bytes: &[u8],
    path: &Path,
    arch: GuestArch,
    libc: GuestLibc,
) -> Result<(), GuestElfError> {
    let p = || path.display().to_string();
    check_guest_elf_header(bytes, path, arch)?;
    let Some(libc_soname) = libc.libc_soname() else {
        return Err(GuestElfError::UnknownLibc { path: p() });
    };
    let e_type = u16_at(bytes, E_TYPE).ok_or_else(|| GuestElfError::Truncated { path: p() })?;
    if e_type != ET_DYN {
        return Err(GuestElfError::NotSharedObject {
            path: p(),
            found: e_type,
        });
    }
    if program_header_types(bytes).any(|p_type| p_type == PT_INTERP) {
        return Err(GuestElfError::ExecutableNotLibrary { path: p() });
    }
    let needed =
        mvm_fs::elf::needed_sonames(bytes).map_err(|e| GuestElfError::DynamicUnreadable {
            path: p(),
            reason: e.to_string(),
        })?;
    // Exact comparison: `libc.so` is a prefix of `libc.so.6`.
    if !needed.iter().any(|name| name == libc_soname) {
        return Err(GuestElfError::MissingLibc {
            path: p(),
            libc,
            soname: libc_soname,
            found: needed,
        });
    }
    let allowed = allowed_shared_object_needs(arch, libc);
    if let Some(unexpected) = needed
        .into_iter()
        .find(|name| !allowed.contains(&name.as_str()))
    {
        return Err(GuestElfError::UnexpectedNeeded {
            path: p(),
            libc,
            soname: unexpected,
            allowed,
        });
    }
    Ok(())
}

/// The `p_type` of each program header, stopping at the first one that does
/// not lie wholly inside `bytes`. Callers have checked the header first.
fn program_header_types(bytes: &[u8]) -> impl Iterator<Item = u32> + '_ {
    let phoff = u64_at(bytes, 32).map_or(usize::MAX, |v| v as usize);
    let phentsize = u16_at(bytes, 54).map_or(0, usize::from);
    let phnum = u16_at(bytes, 56).map_or(0, usize::from);
    (0..phnum).map_while(move |i| {
        let base = phoff.checked_add(i.saturating_mul(phentsize))?;
        u32_at(bytes, base)
    })
}

/// Whether the dynamic array at `off` carries a `DT_NEEDED` tag. Walks fixed
/// 16-byte entries and stops at `DT_NULL`, the end of the section, or the end
/// of the file — whichever comes first.
fn has_dt_needed(bytes: &[u8], off: usize, size: usize) -> bool {
    let end = off.saturating_add(size).min(bytes.len());
    let mut cursor = off;
    while cursor + 16 <= end {
        let Some(tag) = u64_at(bytes, cursor) else {
            return false;
        };
        if tag == DT_NULL {
            return false;
        }
        if tag == DT_NEEDED {
            return true;
        }
        cursor += 16;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal well-formed ELF64 LE header with `phnum` program headers
    /// appended immediately after it.
    fn elf(machine: u16, phdrs: &[(u32, u64, u64)]) -> Vec<u8> {
        const EHSIZE: usize = 64;
        const PHENTSIZE: usize = 56;
        let mut b = vec![0u8; EHSIZE + phdrs.len() * PHENTSIZE];
        b[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        b[EI_CLASS] = ELFCLASS64;
        b[EI_DATA] = ELFDATA2LSB;
        b[18..20].copy_from_slice(&machine.to_le_bytes());
        b[32..40].copy_from_slice(&(EHSIZE as u64).to_le_bytes()); // e_phoff
        b[54..56].copy_from_slice(&(PHENTSIZE as u16).to_le_bytes());
        b[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
        for (i, (p_type, p_offset, p_filesz)) in phdrs.iter().enumerate() {
            let base = EHSIZE + i * PHENTSIZE;
            b[base..base + 4].copy_from_slice(&p_type.to_le_bytes());
            b[base + 8..base + 16].copy_from_slice(&p_offset.to_le_bytes());
            b[base + 32..base + 40].copy_from_slice(&p_filesz.to_le_bytes());
        }
        b
    }

    fn host() -> GuestArch {
        GuestArch::host()
    }

    fn host_machine() -> u16 {
        expected_machine(host())
    }

    fn p() -> &'static Path {
        Path::new("/cache/mvm-guest-agent")
    }

    #[test]
    fn a_static_elf_for_this_host_is_accepted() {
        let bytes = elf(host_machine(), &[(1 /* PT_LOAD */, 0, 0)]);
        assert_eq!(validate_static_guest_elf(&bytes, p(), host()), Ok(()));
    }

    #[test]
    fn a_non_elf_is_rejected() {
        let err = validate_static_guest_elf(b"#!/bin/sh\n", p(), host()).unwrap_err();
        assert!(matches!(err, GuestElfError::NotElf { .. }), "{err}");
    }

    #[test]
    fn a_32_bit_or_big_endian_elf_is_rejected() {
        let mut bytes = elf(host_machine(), &[]);
        bytes[EI_CLASS] = 1; // ELFCLASS32
        assert!(matches!(
            validate_static_guest_elf(&bytes, p(), host()).unwrap_err(),
            GuestElfError::NotElf64Le { .. }
        ));

        let mut bytes = elf(host_machine(), &[]);
        bytes[EI_DATA] = 2; // ELFDATA2MSB
        assert!(matches!(
            validate_static_guest_elf(&bytes, p(), host()).unwrap_err(),
            GuestElfError::NotElf64Le { .. }
        ));
    }

    /// The cross-compile target is the thing most likely to be wrong on a
    /// contributor's host, and the guest symptom is a VM that never boots.
    #[test]
    fn the_wrong_architecture_is_rejected_and_named() {
        let other = if host_machine() == EM_X86_64 {
            EM_AARCH64
        } else {
            EM_X86_64
        };
        let bytes = elf(other, &[]);
        let err = validate_static_guest_elf(&bytes, p(), host()).unwrap_err();
        assert!(matches!(err, GuestElfError::WrongMachine { .. }), "{err}");
        assert!(
            err.to_string().contains("mvm-guest-agent"),
            "error should name the artifact: {err}"
        );
    }

    #[test]
    fn a_pt_interp_segment_is_rejected() {
        let bytes = elf(host_machine(), &[(PT_INTERP, 0, 0)]);
        let err = validate_static_guest_elf(&bytes, p(), host()).unwrap_err();
        assert!(
            matches!(
                err,
                GuestElfError::Dynamic {
                    kind: "PT_INTERP segment",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn a_dt_needed_entry_is_rejected() {
        // PT_DYNAMIC pointing at a dynamic array whose first tag is DT_NEEDED.
        let mut bytes = elf(host_machine(), &[(PT_DYNAMIC, 0, 0)]);
        let dyn_off = bytes.len() as u64;
        bytes.extend_from_slice(&DT_NEEDED.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&DT_NULL.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        let base = 64;
        bytes[base + 8..base + 16].copy_from_slice(&dyn_off.to_le_bytes());
        bytes[base + 32..base + 40].copy_from_slice(&32u64.to_le_bytes());

        let err = validate_static_guest_elf(&bytes, p(), host()).unwrap_err();
        assert!(
            matches!(
                err,
                GuestElfError::Dynamic {
                    kind: "DT_NEEDED entry",
                    ..
                }
            ),
            "{err}"
        );
    }

    /// A PT_DYNAMIC with no DT_NEEDED is a static-PIE, which the guest runs.
    #[test]
    fn a_static_pie_without_dt_needed_is_accepted() {
        let mut bytes = elf(host_machine(), &[(PT_DYNAMIC, 0, 0)]);
        let dyn_off = bytes.len() as u64;
        bytes.extend_from_slice(&DT_NULL.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        let base = 64;
        bytes[base + 8..base + 16].copy_from_slice(&dyn_off.to_le_bytes());
        bytes[base + 32..base + 40].copy_from_slice(&16u64.to_le_bytes());

        assert_eq!(validate_static_guest_elf(&bytes, p(), host()), Ok(()));
    }

    /// A corrupt header must not panic or allocate from a file-supplied count.
    #[test]
    fn a_truncated_or_corrupt_header_is_an_error_not_a_panic() {
        assert!(matches!(
            validate_static_guest_elf(&[0x7f, b'E', b'L', b'F'], p(), host()).unwrap_err(),
            GuestElfError::Truncated { .. }
        ));

        // Absurd phnum/phoff: the walk must run off the end and stop.
        let mut bytes = elf(host_machine(), &[]);
        bytes[56..58].copy_from_slice(&u16::MAX.to_le_bytes());
        bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(validate_static_guest_elf(&bytes, p(), host()), Ok(()));
    }

    /// A shared object for `machine` recording `needed`.
    fn shared_object(machine: u16, needed: &[&str]) -> Vec<u8> {
        let mut bytes = mvm_fs::elf::test_fixture::shared_object(needed);
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    fn so_path() -> &'static Path {
        Path::new("/cache/lib/libcuda.so.1")
    }

    #[test]
    fn a_shared_object_needing_only_its_libc_is_accepted() {
        let arch = host();
        let loader = allowed_shared_object_needs(arch, GuestLibc::Glibc)[3];
        for needed in [
            vec!["libpthread.so.0", "libc.so.6"],
            vec!["libgcc_s.so.1", "libc.so.6", loader],
        ] {
            let bytes = shared_object(host_machine(), &needed);
            assert_eq!(
                validate_guest_shared_object(&bytes, so_path(), arch, GuestLibc::Glibc),
                Ok(()),
                "{needed:?}"
            );
        }
        for needed in [vec!["libc.so"], vec!["libgcc_s.so.1", "libc.so"]] {
            let bytes = shared_object(host_machine(), &needed);
            assert_eq!(
                validate_guest_shared_object(&bytes, so_path(), arch, GuestLibc::Musl),
                Ok(()),
                "{needed:?}"
            );
        }
    }

    #[test]
    fn a_shared_object_for_the_wrong_arch_is_rejected() {
        let other = if host_machine() == EM_X86_64 {
            EM_AARCH64
        } else {
            EM_X86_64
        };
        let bytes = shared_object(other, &["libc.so"]);
        assert!(matches!(
            validate_guest_shared_object(&bytes, so_path(), host(), GuestLibc::Musl),
            Err(GuestElfError::WrongMachine { .. })
        ));
    }

    #[test]
    fn a_static_executable_offered_as_a_library_is_rejected() {
        let bytes = elf(host_machine(), &[(1, 0, 0)]);
        assert!(matches!(
            validate_guest_shared_object(&bytes, so_path(), host(), GuestLibc::Musl),
            Err(GuestElfError::NotSharedObject { found: 0, .. })
        ));
    }

    /// A dynamic executable is ET_DYN too; its interpreter gives it away.
    #[test]
    fn a_dynamic_executable_offered_as_a_library_is_rejected() {
        let mut bytes = shared_object(host_machine(), &["libc.so.6"]);
        // Turn the PT_LOAD header into PT_INTERP.
        bytes[64..68].copy_from_slice(&PT_INTERP.to_le_bytes());
        assert!(matches!(
            validate_guest_shared_object(&bytes, so_path(), host(), GuestLibc::Glibc),
            Err(GuestElfError::ExecutableNotLibrary { .. })
        ));
    }

    #[test]
    fn a_shared_object_without_its_libc_is_rejected() {
        let cases = [
            (vec![], GuestLibc::Musl),
            (vec!["libc.so.6"], GuestLibc::Musl),
            (vec!["libc.so"], GuestLibc::Glibc),
        ];
        for (needed, libc) in cases {
            let bytes = shared_object(host_machine(), &needed);
            assert!(
                matches!(
                    validate_guest_shared_object(&bytes, so_path(), host(), libc),
                    Err(GuestElfError::MissingLibc { .. })
                ),
                "{needed:?} as {libc}"
            );
        }
    }

    #[test]
    fn a_need_outside_the_allowlist_is_rejected_and_named() {
        let cases = [
            (
                vec!["libc.so.6", "libssl.so.3"],
                GuestLibc::Glibc,
                "libssl.so.3",
            ),
            (
                vec!["libc.so", "libpthread.so.0"],
                GuestLibc::Musl,
                "libpthread.so.0",
            ),
        ];
        for (needed, libc, unexpected) in cases {
            let bytes = shared_object(host_machine(), &needed);
            let err = validate_guest_shared_object(&bytes, so_path(), host(), libc).unwrap_err();
            assert!(
                matches!(&err, GuestElfError::UnexpectedNeeded { soname, .. } if soname == unexpected),
                "{err}"
            );
            assert!(err.to_string().contains("libcuda.so.1"), "{err}");
        }
    }

    #[test]
    fn the_glibc_allowlist_names_each_arch_its_own_loader() {
        assert!(
            allowed_shared_object_needs(GuestArch::Aarch64, GuestLibc::Glibc)
                .contains(&"ld-linux-aarch64.so.1")
        );
        assert!(
            allowed_shared_object_needs(GuestArch::X86_64, GuestLibc::Glibc)
                .contains(&"ld-linux-x86-64.so.2")
        );
        assert!(allowed_shared_object_needs(GuestArch::X86_64, GuestLibc::Unknown).is_empty());
    }

    #[test]
    fn an_unknown_libc_is_rejected() {
        let bytes = shared_object(host_machine(), &["libc.so"]);
        assert!(matches!(
            validate_guest_shared_object(&bytes, so_path(), host(), GuestLibc::Unknown),
            Err(GuestElfError::UnknownLibc { .. })
        ));
    }
}
