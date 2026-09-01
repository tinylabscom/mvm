//! Choosing the SDK-sidecar variant for a guest that has just been materialized.
//!
//! There is one sidecar artifact per guest libc, and a musl process cannot
//! `dlopen` a glibc-linked object. The choice therefore has to be made from the
//! guest's own libc — and the earliest point that value exists is *after* the
//! rootfs has been unpacked, which is why this is called from the middle of the
//! launch resolution rather than from the command layer that parsed the flag.
//!
//! Kept beside that resolution and separate from it so the two facts it weighs
//! — what the catalog declared and what the image recorded — are readable
//! together, and so their tests sit with them.

use anyhow::Result;
use mvm_contract::guest_libc::GuestLibc;
use mvm_contract::protocol::broker::ServiceId;

use crate::commands::vm::up::SdkSidecarAttachment;

/// Resolve the sidecar this boot will attach, or `None`.
///
/// The libc is read from the sidecar written beside the rootfs when its layers
/// were unpacked — the only thing the host can still read once the tree is an
/// ext4 blob, and a fact about *this* image rather than about whatever table
/// pinned a reference to it. Selecting on it is what lets an arbitrary
/// `--image` work: nothing declares a libc for an image a user names.
///
/// Not asked on a tier that attaches no ELF sidecar. Wasm has no dynamic loader
/// and never will, so "which libc" is the wrong question there; a wasm workload
/// binding an SDK host service is refused by the backend-compatibility gate,
/// which can say why. Asking here first would answer it with a libc complaint
/// about a loader that was never going to exist.
pub(super) fn select_for_launch(
    backend: mvm_core::vm_backend::BackendKind,
    rootfs: &std::path::Path,
    services: &[ServiceId],
    declared_libc: GuestLibc,
) -> Result<Option<SdkSidecarAttachment>> {
    if backend == mvm_core::vm_backend::BackendKind::Wasm {
        return Ok(None);
    }
    let recorded = mvm_build::guest_libc::recorded_image_libc(rootfs);
    refuse_declared_libc_disagreement(declared_libc, recorded)?;
    crate::commands::vm::up::resolve_sdk_sidecar_attachment_for_host(services, recorded)
}

/// Refuse a catalogued runtime whose declared libc is not what its image turned
/// out to record.
///
/// Two independent facts about the same guest: the catalog *declares* a libc
/// for the image reference it pins, and the unpacker *observes* one in the tree
/// that reference resolved to. They agree until the upstream tag moves — a
/// `:alpine` image rebuilt on a glibc base, say — at which point the
/// declaration is silently wrong about every guest booted from it.
///
/// Selection uses the observed value, so a disagreement is not itself a boot
/// hazard; it is a catalog entry that has drifted from reality, and it is
/// invisible from anywhere else. Refusing is the only way anyone finds out.
///
/// `Unknown` on either side is not a disagreement: an image the host has no
/// declaration for is the ordinary `--image` case, and an image that recorded
/// no libc is refused later, by the resolver, with a message about what to do.
fn refuse_declared_libc_disagreement(declared: GuestLibc, recorded: GuestLibc) -> Result<()> {
    if declared == GuestLibc::Unknown || recorded == GuestLibc::Unknown || declared == recorded {
        return Ok(());
    }
    anyhow::bail!(
        "refusing to launch: the runtime catalog declares this image is {declared}, but the \
         materialized rootfs records {recorded}. The catalog entry has drifted from the image \
         it pins — most likely the upstream tag was rebuilt on a different base. Report it; \
         naming the image directly with --image bypasses the declaration."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The catalog declares a libc and the unpacker observes one. While they
    /// agree there is nothing to say; the check exists for the day the upstream
    /// tag is rebuilt on a different base and the declaration becomes quietly
    /// wrong about every guest booted from it.
    #[test]
    fn a_declaration_matching_what_the_image_records_is_not_a_disagreement() {
        for libc in [GuestLibc::Glibc, GuestLibc::Musl] {
            assert!(refuse_declared_libc_disagreement(libc, libc).is_ok());
        }
    }

    #[test]
    fn a_declaration_the_image_contradicts_refuses_and_names_both() {
        let err = refuse_declared_libc_disagreement(GuestLibc::Musl, GuestLibc::Glibc)
            .expect_err("a drifted catalog entry must not boot silently");
        let msg = err.to_string();
        assert!(msg.contains("musl"), "must name the declaration: {msg}");
        assert!(msg.contains("glibc"), "must name what was recorded: {msg}");
    }

    /// `Unknown` on either side is not a disagreement. An image the host has no
    /// declaration for is the ordinary `--image` case — the one this selection
    /// exists to serve — and an image that recorded no libc is refused later by
    /// the resolver, with a message about what to do next. Treating either as a
    /// conflict here would refuse both instead.
    #[test]
    fn an_unknown_on_either_side_is_not_a_disagreement() {
        assert!(refuse_declared_libc_disagreement(GuestLibc::Unknown, GuestLibc::Musl).is_ok());
        assert!(refuse_declared_libc_disagreement(GuestLibc::Musl, GuestLibc::Unknown).is_ok());
        assert!(refuse_declared_libc_disagreement(GuestLibc::Unknown, GuestLibc::Unknown).is_ok());
    }

    /// The wasm tier attaches no ELF artifact, so it is never asked which libc
    /// it has — not even to be refused. A rootfs path that does not exist is
    /// enough to prove nothing was read.
    #[test]
    fn the_wasm_tier_is_not_asked_which_libc_it_has() {
        let services = [ServiceId::parse("host.kv.v1").expect("fixture service id")];
        assert_eq!(
            select_for_launch(
                mvm_core::vm_backend::BackendKind::Wasm,
                std::path::Path::new("/nonexistent/module.wasm"),
                &services,
                GuestLibc::Unknown,
            )
            .expect("wasm must not be refused for a libc it was never going to have"),
            None
        );
    }
}
