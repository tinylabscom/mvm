//! Tests for the `image boot` surface.
//!
//! Every test isolates `$HOME`/`MVM_HOME` through `TestEnv`, so the cache under
//! inspection is the one the test wrote and never the developer's real one.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

use mvm_core::util::test_env::TestEnv;
use sha2::{Digest, Sha256};

use super::cache;
use super::check::{CheckVerdict, verdict};
use super::update::{self, UpdateRequest};
use crate::commands::env::builder_vm::default_microvm::{
    DefaultMicrovmVariant, default_microvm_assets,
};

const ARCH: &str = if cfg!(target_arch = "aarch64") {
    "aarch64"
} else {
    "x86_64"
};

/// Write a complete prod cache entry whose every file holds `marker` bytes,
/// with a sidecar claiming `tag`.
fn seed_prod_entry(tag: &str, marker: &[u8]) -> PathBuf {
    let dir = cache::variant_dir(DefaultMicrovmVariant::Prod);
    std::fs::create_dir_all(&dir).expect("create prod cache dir");
    for name in DefaultMicrovmVariant::Prod.required_outputs() {
        std::fs::write(dir.join(name), marker).expect("seed cache file");
    }
    let sidecar = mvm_build::builder_vm::GuestSidecar::for_oci_run("seeded", true, false);
    let sidecar = mvm_build::builder_vm::GuestSidecar {
        image_tag: tag.to_string(),
        source: "fetched".to_string(),
        ..sidecar
    };
    sidecar.write_to_dir(&dir).expect("seed sidecar");
    dir
}

/// Lay out a `file://`-servable release directory for `tag`, with a checksum
/// manifest pinning `manifest_bytes` and assets actually holding
/// `served_bytes`. Passing two different slices is how the mismatch case is
/// built.
fn stage_release(root: &Path, tag: &str, manifest_bytes: &[u8], served_bytes: &[u8]) -> String {
    let release = root.join("tinylabscom/mvm/releases/download").join(tag);
    std::fs::create_dir_all(&release).expect("create release dir");
    let pinned = hex::encode(Sha256::digest(manifest_bytes));
    let mut manifest = String::new();
    for (name, _) in default_microvm_assets("unused", ARCH) {
        std::fs::write(release.join(&name), served_bytes).expect("write asset");
        manifest.push_str(&format!("{pinned}  {name}\n"));
    }
    std::fs::write(
        release.join(format!("default-microvm-{ARCH}-checksums-sha256.txt")),
        manifest,
    )
    .expect("write manifest");
    format!("file://{}", root.display())
}

/// Serve one canned JSON body on loopback for as long as the returned sender
/// is alive. `http::fetch_json` speaks real HTTP, so a `file://` stub cannot
/// stand in for the releases API the way it can for asset downloads.
fn serve_json(body: String) -> (String, mpsc::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("read loopback addr");
    listener
        .set_nonblocking(true)
        .expect("mark loopback nonblocking");
    let (tx, rx) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        loop {
            match rx.try_recv() {
                Ok(()) | Err(mpsc::TryRecvError::Disconnected) => return,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                    let mut buf = [0u8; 1024];
                    let mut seen = Vec::new();
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                seen.extend_from_slice(&buf[..n]);
                                if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
    });
    (format!("http://{addr}"), tx)
}

#[test]
fn check_reports_behind_when_the_published_tag_is_newer() {
    let home = tempfile::tempdir().expect("tempdir");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());

    seed_prod_entry("boot-image/v0.1.0", b"cached bytes");
    let (base_url, _stop) = serve_json(
        r#"[{"tag_name":"v0.18.0"},{"tag_name":"boot-image/v0.2.0"},
            {"tag_name":"boot-image/v0.1.0"}]"#
            .to_string(),
    );
    env.set("MVM_UPDATE_API_URL", &base_url);

    let latest = crate::update::fetch_latest_boot_image_tag()
        .expect("list releases")
        .expect("the stub publishes a boot image line");
    assert_eq!(
        latest, "boot-image/v0.2.0",
        "the binary train's v0.18.0 must not be mistaken for an image release"
    );

    let cached = super::check::cached_tag();
    assert_eq!(cached.as_deref(), Some("boot-image/v0.1.0"));
    assert_eq!(
        verdict(cached.as_deref(), Some(&latest)),
        CheckVerdict::Behind {
            cached: "boot-image/v0.1.0".to_string(),
            latest: "boot-image/v0.2.0".to_string(),
        }
    );

    let err = super::check::run(false).expect_err("behind must exit nonzero so a script can gate");
    assert!(
        err.to_string().contains("behind"),
        "the refusal must say why: {err}"
    );
}

#[test]
fn check_is_clean_when_the_image_line_has_published_nothing() {
    // No `boot-image/*` tag exists yet. That is a real state, and reporting it
    // as "behind" would fail every pipeline on a fresh install.
    let home = tempfile::tempdir().expect("tempdir");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());

    let (base_url, _stop) = serve_json(r#"[{"tag_name":"v0.18.0"}]"#.to_string());
    env.set("MVM_UPDATE_API_URL", &base_url);

    assert_eq!(
        crate::update::fetch_latest_boot_image_tag().expect("list releases"),
        None
    );
    super::check::run(false).expect("no published image line is not a failure");
}

#[test]
fn a_failed_update_leaves_the_previous_image_in_place() {
    let home = tempfile::tempdir().expect("tempdir");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    // The publisher rung has its own witnesses; this test is about what the
    // digest rung does to the cache when it refuses.
    env.set("MVM_SKIP_COSIGN_VERIFY", "1");
    env.remove("MVM_SKIP_HASH_VERIFY");

    let original = b"the image that already works";
    let dir = seed_prod_entry("boot-image/v0.1.0", original);

    let served = tempfile::tempdir().expect("release tempdir");
    let tag = "boot-image/v0.2.0";
    let base_url = stage_release(
        served.path(),
        tag,
        b"what the manifest pins",
        b"what the server actually sent",
    );
    env.set("MVM_UPDATE_DOWNLOAD_URL", &base_url);

    let err = update::run(&UpdateRequest {
        tag: Some(tag.to_string()),
        force: true,
    })
    .expect_err("an artifact that fails its digest must not be installed");
    assert!(
        err.to_string().contains("Integrity check failed"),
        "the refusal must name the digest mismatch: {err:#}"
    );

    for name in DefaultMicrovmVariant::Prod.required_outputs() {
        // The sidecar holds JSON rather than the marker; its survival is
        // asserted below by the tag it still records.
        if *name == mvm_build::builder_vm::SIDECAR_FILENAME {
            continue;
        }
        let bytes = std::fs::read(dir.join(name)).expect("previous image file must survive");
        assert_eq!(
            bytes, original,
            "{name} was replaced by a failed update; the cache must still hold the original bytes"
        );
    }
    let sidecar = mvm_build::builder_vm::GuestSidecar::read_from_dir(&dir)
        .expect("read sidecar")
        .expect("sidecar must survive");
    assert_eq!(
        sidecar.image_tag, "boot-image/v0.1.0",
        "a failed update must not advance the recorded tag"
    );
    assert!(
        !cache::cache_root()
            .read_dir()
            .expect("read cache root")
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains("staging")),
        "the staging directory must not be left behind"
    );
}

#[test]
fn update_refuses_in_a_source_checkout_without_force() {
    // The test binary is built from this checkout, so the in-repo builder-VM
    // flake resolves and the refusal is live.
    let home = tempfile::tempdir().expect("tempdir");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());

    let err = update::run(&UpdateRequest {
        tag: Some("boot-image/v0.2.0".to_string()),
        force: false,
    })
    .expect_err("a source checkout's local build is authoritative");
    assert!(
        err.to_string().contains("source checkout"),
        "the refusal must name the reason: {err}"
    );
}

#[test]
fn status_reports_an_unrecorded_field_rather_than_a_blank() {
    let home = tempfile::tempdir().expect("tempdir");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());

    let entries = cache::survey();
    assert_eq!(entries.len(), 2, "both variants are always reported");
    for entry in &entries {
        assert!(!entry.would_use(), "an empty cache is not usable");
        assert_eq!(entry.image_tag(), None);
        assert_eq!(entry.protocol_version(), None);
    }
    super::status::run(false).expect("status must render an empty cache");
    super::status::run(true).expect("status must render an empty cache as JSON");
}

#[test]
fn a_tag_that_cannot_be_ordered_is_not_reported_as_behind() {
    // Ordering tags as strings puts v0.10.0 before v0.9.0. Both of these
    // assertions fail under a string comparison.
    assert_eq!(
        verdict(Some("boot-image/v0.10.0"), Some("boot-image/v0.9.0")),
        CheckVerdict::Ahead {
            cached: "boot-image/v0.10.0".to_string(),
            latest: "boot-image/v0.9.0".to_string(),
        }
    );
    assert_eq!(
        verdict(Some("boot-image/v0.9.0"), Some("boot-image/v0.10.0")),
        CheckVerdict::Behind {
            cached: "boot-image/v0.9.0".to_string(),
            latest: "boot-image/v0.10.0".to_string(),
        }
    );
    assert!(matches!(
        verdict(Some("not-a-tag"), Some("boot-image/v0.1.0")),
        CheckVerdict::NoCachedTag { .. }
    ));
    assert_eq!(
        verdict(Some("boot-image/v0.1.0"), None),
        CheckVerdict::NoPublishedLine
    );
}

/// A fetched image must say so, even when it landed in a source checkout.
///
/// `MVM_BOOT_IMAGE=fetch` is the one case that weakens "a source checkout never
/// depends on a published artifact". The weakening is acceptable only because
/// the result is labelled: without this stamp a prebuilt sitting in a checkout
/// is indistinguishable from a build of the working tree, and the next person
/// to wonder why their flake edit had no effect has nothing to read.
#[test]
fn stamping_marks_an_acquired_image_as_fetched_without_losing_build_facts() {
    let _env = TestEnv::new();
    let dir = tempfile::tempdir().unwrap();

    // A sidecar as a producer would emit it: build facts present, acquisition
    // facts absent, because the build cannot know them.
    let produced = r#"{
        "name": "mvm-default-microvm",
        "accessible": false,
        "sealed": true,
        "entrypointKind": "command",
        "initSystem": "busybox",
        "expectedBootMs": 300,
        "agentBinary": "real",
        "rootlessEntrypoint": true,
        "hypervisor": "libkrun",
        "protocolVersion": 2,
        "generatorRev": "abc123",
        "source": "built-local"
    }"#;
    std::fs::write(
        dir.path().join(mvm_build::builder_vm::SIDECAR_FILENAME),
        produced,
    )
    .unwrap();

    super::cache::stamp_provenance(
        dir.path(),
        &super::cache::AcquiredProvenance::fetched("v0.18.0"),
    )
    .expect("stamping a well-formed sidecar must succeed");

    let after = mvm_build::builder_vm::GuestSidecar::read_from_dir(dir.path())
        .unwrap()
        .unwrap();
    assert_eq!(
        after.source, "fetched",
        "the acquisition arm must be recorded"
    );
    assert_eq!(after.image_tag, "v0.18.0");
    assert!(
        !after.built_at.is_empty(),
        "the host stamps a time the build could not"
    );
    // Build facts the producer recorded survive: stamping adds provenance, it
    // does not rewrite what the image is.
    assert_eq!(after.protocol_version, 2);
    assert_eq!(after.generator_rev, "abc123");
    assert_eq!(after.name, "mvm-default-microvm");
}
