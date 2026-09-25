#[path = "build_support.rs"]
mod build_support;
#[path = "src/workspace_graph.rs"]
mod workspace_graph;
// The pinned-toolchain resolution is shared with `mvm-build`. A build script
// cannot depend on a workspace crate, so it reads the same file off disk.
#[path = "../mvm-build/src/embed_toolchain.rs"]
mod embed_toolchain;
// What the payload holds, its content-store keys and the `cargo zigbuild` that
// produces it. `mvmctl` compiles the same file to build the payload at run time.
#[path = "src/host_binaries/payload_build.rs"]
mod payload_build;

use std::path::{Path, PathBuf};

use build_support::{EmbedDecision, EmbedRequest, embed_request};
use embed_toolchain::{Pin, workspace_root_from_manifest_dir};
use payload_build::{
    EmbedCache, EmbeddedSourceBinary, ZigbuildRequest, artifact_key_for, build_embed_cache,
    parse_embedded_manifest, run_cargo_zigbuild, zigbuild_output,
};

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = workspace_root_from_manifest_dir(&manifest_dir);
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    emit_pinned_toolchain_env(&workspace_root);
    println!("cargo:rerun-if-env-changed=MVM_EMBED");

    // A release build embeds unless told not to; a debug one — which is what
    // `cargo check`, clippy and nextest run — compiles nothing and only restores
    // a payload the content store can already prove belongs to this tree.
    match embed_decision(embed_request_from_env(), || {
        embed_toolchain::check_toolchain_ready(&read_pinned_toolchain(&workspace_root))
    }) {
        EmbedDecision::Compile => embed_host_binaries(&workspace_root, &out_dir),
        EmbedDecision::RestoreOnly { warning } => {
            write_unembedded_table(&workspace_root, &out_dir, warning.as_deref())
        }
    }
}

/// This build's embed request, from the environment cargo hands the script.
///
/// Cargo sets `CARGO_FEATURE_<NAME>` for each enabled feature of the package
/// being built, so this reads the `embed-host-bins` feature without the build
/// script needing to know how it was turned on.
fn embed_request_from_env() -> EmbedRequest {
    embed_request(
        std::env::var_os("CARGO_FEATURE_EMBED_HOST_BINS").is_some(),
        &std::env::var("PROFILE").unwrap_or_default(),
        std::env::var("MVM_EMBED").ok().as_deref(),
    )
}

/// Settle `request`, probing the toolchain only when the answer depends on it.
fn embed_decision(
    request: EmbedRequest,
    toolchain: impl FnOnce() -> Result<(), String>,
) -> EmbedDecision {
    let readiness = match request {
        EmbedRequest::ReleaseProfile => toolchain(),
        EmbedRequest::Feature | EmbedRequest::NotRequested => Ok(()),
    };
    build_support::embed_decision(request, readiness)
}

/// Export the pinned zig / rust / cargo-zigbuild versions `mvmctl doctor`
/// reports. Needed under both arms: doctor tells you what the embed toolchain
/// *would* be even when this build did not use it.
fn emit_pinned_toolchain_env(workspace_root: &Path) {
    let pin = read_pinned_toolchain(workspace_root);
    println!("cargo:rustc-env=MVM_PINNED_RUST={}", pin.rust);
    println!("cargo:rustc-env=MVM_PINNED_ZIG={}", pin.zig);
    println!(
        "cargo:rustc-env=MVM_PINNED_CARGO_ZIGBUILD={}",
        pin.cargo_zigbuild
    );
    println!("cargo:rustc-env=MVM_PINNED_TARGET={}", pin.target);
}

/// The unembedded arm. It never cross-compiles — but it does reuse a payload
/// the content store can prove belongs to this source tree.
///
/// Both feature variants write the same `target/<profile>/mvmctl`, so whichever
/// cargo invocation ran last decides whether the binary on `PATH` carries the
/// payload. A cached, zero-compile `cargo build` is enough to take it away,
/// which is why an unembedded `mvmctl` kept coming back after a `just embed`
/// that had genuinely worked. Restoring here closes that: the key covers each
/// binary's dependency closure, `Cargo.lock` and the pinned toolchain, so a hit
/// is exactly the bytes this tree produces — the same proof the embedding arm
/// relies on when it skips a rebuild.
///
/// A miss, an unreachable store, or `MVM_EMBED_NO_CACHE=1` writes the empty
/// table as before. This arm compiles nothing, so a payload it cannot prove is
/// one it does not ship.
///
/// At least one `rerun-if-*` line is mandatory. Emitting none does not mean
/// "never re-run" — it restores cargo's default, which re-runs the script on
/// *any* change to the package, i.e. every edit to `mvm-cli`'s 251 files.
fn write_unembedded_table(workspace_root: &Path, out_dir: &Path, warning: Option<&str>) {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support.rs");
    println!("cargo:rerun-if-changed=build_embed_cache.rs");
    println!("cargo:rerun-if-changed=src/host_binaries/payload_build.rs");
    println!("cargo:rerun-if-changed=src/workspace_graph.rs");
    println!("cargo:rerun-if-changed=src/host_binaries/manifest.rs");
    println!("cargo:rerun-if-changed=../mvm-build/src/embed_toolchain.rs");
    println!("cargo:rerun-if-env-changed=MVM_EMBED_NO_CACHE");
    println!("cargo:rerun-if-env-changed=MVM_EMBED_CACHE_DIR");
    // A release build lands here when the toolchain probe failed; pointing
    // these at a working toolchain has to be able to bring it back.
    println!("cargo:rerun-if-env-changed=MVM_EMBED_CARGO");
    println!("cargo:rerun-if-env-changed=MVM_EMBED_RUSTC");
    println!("cargo:rerun-if-env-changed=MVM_EMBED_ZIG");

    let entries = restore_embedded_from_store(workspace_root, out_dir);
    // Only when the restore came up empty: a store hit embeds after all, and
    // warning about a payload the binary carries would be noise.
    if let (true, Some(warning)) = (entries.is_empty(), warning) {
        println!("cargo:warning={warning}");
    }
    std::fs::write(out_dir.join("embedded.rs"), render_embedded_rs(&entries)).unwrap();
    println!(
        "cargo:rustc-env=MVM_EMBEDDED_BINS_REUSED={}",
        if entries.is_empty() { "0" } else { "1" }
    );
}

/// Restore the whole embedded set from the content store, or nothing.
///
/// All-or-nothing on purpose: extraction verifies the table as a unit, and a
/// builder VM missing one binary fails later and somewhere else, which reads as
/// a corrupted cache rather than as a partial restore.
fn restore_embedded_from_store(
    workspace_root: &Path,
    out_dir: &Path,
) -> Vec<(String, PathBuf, String)> {
    let mut cache = EmbedCache::discover(workspace_root);
    let Some(store_root) = cache.root.clone() else {
        return Vec::new();
    };
    // Watch the store itself, not just the sources. Publishing from a
    // `just embed` changes no file this unit already watches, so without this
    // the restore below would never re-run and the next plain build would keep
    // shipping the empty table it cached — the exact swap this arm exists to
    // stop. Created when absent so the watch is a stable directory rather than
    // a missing path, which cargo treats as permanently dirty.
    let _ = std::fs::create_dir_all(&store_root);
    println!("cargo:rerun-if-changed={}", store_root.display());

    let pin = read_pinned_toolchain(workspace_root);
    let bins_out = out_dir.join("mvm-host-bins");
    let mut entries = Vec::new();
    for binary in read_embedded_manifest(workspace_root) {
        let out_file = bins_out.join(&binary.name);
        let key = artifact_key_for(&mut cache, &binary, &pin);
        if !restore(&cache, key.as_deref(), &binary.name, &out_file) {
            // Watch the closure anyway: a later edit has to be able to bring
            // this unit back for another look once the store carries the
            // matching bytes.
            emit_rerun(&cache);
            return Vec::new();
        }
        let sha = sha256_hex(&out_file);
        entries.push((binary.name.clone(), out_file, sha));
    }
    // Editing any source the payload is built from must invalidate the restore,
    // or this arm would keep serving bytes that no longer match the tree.
    emit_rerun(&cache);
    eprintln!(
        "[build.rs] embedded host binaries restored from the content store \
         without `embed-host-bins` ({} binaries)",
        entries.len()
    );
    entries
}

fn embed_host_binaries(workspace_root: &Path, out_dir: &Path) {
    let workspace_root = workspace_root.to_path_buf();
    let out_dir = out_dir.to_path_buf();
    let bins_out = out_dir.join("mvm-host-bins");
    std::fs::create_dir_all(&bins_out).expect("create OUT_DIR/mvm-host-bins");

    // The nested `cargo {build,zigbuild}` that compiles the host-vm binaries
    // MUST use its own target dir. The outer `cargo build` (mvmctl) holds an
    // exclusive lock on the workspace `target/` for its whole run, including
    // while this build script executes; a nested cargo aimed at the same
    // `target/` blocks on that lock forever — the outer build waits on this
    // script, this script waits on the nested cargo, the nested cargo waits
    // on the outer's lock. That deadlock is why cold release builds hung
    // (warm builds slip through because the nested step does almost nothing).
    // A separate target dir under the profile's build directory has its own
    // lock → no contention. It is shared across mvm-cli feature fingerprints,
    // so identical embedded binaries are not rebuilt for each OUT_DIR.
    let nested_target_dir = build_support::shared_nested_target_dir(&out_dir);
    let host_target_dir = nested_target_dir.join("host-vm-target");

    let pin = read_pinned_toolchain(&workspace_root);
    println!("cargo:rerun-if-env-changed=MVM_EMBED_CARGO");
    println!("cargo:rerun-if-env-changed=MVM_EMBED_RUSTC");
    println!("cargo:rerun-if-env-changed=MVM_EMBED_ZIG");
    println!("cargo:rerun-if-env-changed=MVM_EMBED_NO_CACHE");

    let manifest = read_embedded_manifest(&workspace_root);
    let mut entries = Vec::new();

    // The host-vm bins are statically musl-linked and embedded for the host
    // arch (`pin.target`, picked from CARGO_CFG_TARGET_ARCH).
    //
    // The musl cross-compile is ~93% of this build script's wall time (measured:
    // 105s for one binary, ~163s for the set, against 13s for the whole native
    // aux-helper leg). Every one of these binaries links `mvm-build` ->
    // `mvm-core`, so any edit under `mvm-core/src` invalidates all six and a
    // one-line change costs ~176s before a single test runs.
    //
    // Reuse is decided by content, not by profile. The key covers each
    // binary's real dependency closure, `Cargo.lock` and the pinned
    // toolchain, so a hit proves the bytes are the ones this source tree
    // produces — which is what makes reuse safe under `--release` and
    // `release-witness` too, and safe to share across worktrees. The previous
    // rule (`PROFILE == "debug"` plus "the file exists") could prove neither,
    // so it had to refuse every other profile and still risked embedding a
    // stale binary within the one it allowed.
    //
    // A key *miss* is a different question from a key hit, and the answer
    // differs by profile. Rebuilding the musl set costs ~163s, which is why
    // the dev profile has always been allowed to boot a stale embedded binary
    // rather than pay that on every edit. That trade is kept below — but the
    // key now knows the artifact is stale, so the warning can say so instead
    // of describing a reuse that may or may not have been current.
    //
    // `MVM_EMBED_NO_CACHE=1` opts out of both the store and the stale
    // fallback, for release engineering that wants the bytes provably
    // compiled in this run.
    let force_rebuild = std::env::var_os("MVM_EMBED_NO_CACHE").is_some_and(|v| !v.is_empty());
    let dev_profile = std::env::var("PROFILE").unwrap_or_default() == "debug" && !force_rebuild;
    let mut cache = EmbedCache::discover(&workspace_root);
    let mut reused_any = false;
    let mut stale_any = false;

    for binary in &manifest {
        let out_file = bins_out.join(&binary.name);
        let prebuilt = zigbuild_output(&host_target_dir, &pin.target, &binary.name);
        let key = artifact_key_for(&mut cache, binary, &pin);

        if restore(&cache, key.as_deref(), &binary.name, &out_file) {
            eprintln!(
                "[build.rs] embedded {} restored from the content store \
                 (set MVM_EMBED_NO_CACHE=1 to rebuild)",
                binary.name
            );
            reused_any = true;
            // Seed the nested target dir the dev stale-fallback reads from.
            // A worktree whose binaries all came from the store has never
            // populated it, so without this the *first* source edit there
            // falls through to a full ~163s cross-compile — moving the cost
            // the store just removed rather than removing it.
            seed_prebuilt(&out_file, &prebuilt);
            let sha = sha256_hex(&out_file);
            entries.push((binary.name.clone(), out_file.clone(), sha));
            continue;
        }

        // Miss: the closure really did change. Under `--release` or
        // `release-witness` that always means a rebuild. Under dev, fall back
        // to whatever the nested target dir last produced, exactly as before
        // the store existed — the difference is that we now know it is stale
        // and can name the consequence.
        if dev_profile && prebuilt.is_file() {
            eprintln!(
                "[build.rs] embedded {} is STALE — this build's changes are \
                 NOT in it. Dev profile reuses it rather than pay a ~163s \
                 cross-compile per edit; run `just embed-refresh` or build \
                 with MVM_EMBED_NO_CACHE=1 before booting a VM that must \
                 carry the change.",
                binary.name
            );
            std::fs::copy(&prebuilt, &out_file).unwrap_or_else(|e| {
                panic!("copy {} -> {}: {e}", prebuilt.display(), out_file.display())
            });
            reused_any = true;
            stale_any = true;
            let sha = sha256_hex(&out_file);
            entries.push((binary.name.clone(), out_file.clone(), sha));
            continue;
        }

        run_cargo_zigbuild(
            ZigbuildRequest::default()
                .with_root(&workspace_root)
                .with_target_dir(&host_target_dir)
                .with_binary(binary)
                .with_pin(&pin)
                .with_output(&out_file)
                .build(),
        )
        .unwrap_or_else(|reason| panic!("{reason}"));
        cache.publish(key.as_deref(), &binary.name, &out_file);
        let sha = sha256_hex(&out_file);
        entries.push((binary.name.clone(), out_file.clone(), sha));
    }

    // Loud, not silent: the runtime can tell the user their embedded set was
    // reused rather than rebuilt, which is the difference between a confusing
    // "my edit did nothing" boot and an actionable message.
    println!(
        "cargo:rustc-env=MVM_EMBEDDED_BINS_REUSED={}",
        if reused_any { "1" } else { "0" }
    );
    // Reused-and-proven-fresh is not the same as reused-and-stale, and only
    // the second one can make a guest ignore your edit. Cargo captures build
    // script stderr unless you pass `-vv`, so the eprintln above is invisible
    // in a normal build; `cargo:warning=` is the one channel it does surface.
    // A developer whose edit will not reach the guest has to be told without
    // having to know to look.
    if stale_any {
        println!(
            "cargo:warning=embedded host binaries are STALE (this build's \
             changes to their sources are not in them). Dev builds reuse them \
             instead of a ~163s cross-compile. Run `just embed-refresh`, or \
             set MVM_EMBED_NO_CACHE=1, before booting a VM that must carry \
             the change."
        );
    }

    let embedded_rs = render_embedded_rs(&entries);
    std::fs::write(out_dir.join("embedded.rs"), embedded_rs).unwrap();
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("Cargo.toml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root
            .join("crates/mvm-cli/src/host_binaries/manifest.rs")
            .display()
    );
    // The embedded binaries' bytes are the authoritative builder-VM
    // fingerprint input, so they must rebuild when their real inputs change —
    // not just their `src/bin/` entrypoints. The lockfile covers a dep bump in
    // their closure.
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("Cargo.lock").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("rust-toolchain.toml").display()
    );
    // Every crate the embedded binaries actually link, taken from the manifest
    // graph rather than named here.
    emit_rerun(&cache);
    cache.prune();
}

fn read_pinned_toolchain(root: &Path) -> Pin {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH is set by cargo for build scripts");
    embed_toolchain::read_pinned_toolchain(root, &arch)
}

/// Every binary that gets cross-compiled and embedded, from `manifest.rs`.
fn read_embedded_manifest(workspace_root: &Path) -> Vec<EmbeddedSourceBinary> {
    let path = workspace_root.join("crates/mvm-cli/src/host_binaries/manifest.rs");
    let src =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    parse_embedded_manifest(&src).unwrap_or_else(|reason| panic!("{reason}"))
}

/// Copy a stored artifact into place, if the store has it.
fn restore(cache: &EmbedCache, key: Option<&str>, binary: &str, dest: &Path) -> bool {
    let (Some(root), Some(key)) = (cache.root.as_ref(), key) else {
        return false;
    };
    build_embed_cache::lookup(root, key, binary, dest)
}

/// Watch exactly the crates the cached binaries are built from.
///
/// The blanket walk this replaces covered every workspace crate including
/// `mvm-cli`'s own 251 files — which are downstream of these binaries and
/// cannot affect them, yet re-ran the whole script on every edit to the
/// crate under active development. Anything reachable is still watched,
/// because the set is taken from the manifest graph rather than named by
/// hand. Each crate's watched files are exactly the ones its key hashes, so
/// an edit that would move the key always re-runs the script. The watch is
/// per file because cargo does not reliably re-trigger a directory-level
/// `rerun-if-changed` on a content edit to a file already in it.
fn emit_rerun(cache: &EmbedCache) {
    for member in &cache.watched {
        let Some(dir) = cache.graph.dirs.get(member) else {
            continue;
        };
        for (path, _) in build_embed_cache::hash_member(&cache.workspace_root, dir) {
            println!(
                "cargo:rerun-if-changed={}",
                cache.workspace_root.join(path).display()
            );
        }
    }
}

/// Place a restored artifact where the dev stale-fallback expects to find it.
///
/// Best-effort: failing to seed costs a slower next build, never a wrong one.
fn seed_prebuilt(source: &Path, prebuilt: &Path) {
    if prebuilt.is_file() {
        return;
    }
    let Some(parent) = prebuilt.parent() else {
        return;
    };
    if std::fs::create_dir_all(parent).is_ok() {
        let _ = std::fs::copy(source, prebuilt);
    }
}

fn sha256_hex(p: &Path) -> String {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    let mut h = Sha256::new();
    h.update(&bytes);
    hex::encode(h.finalize())
}

fn render_embedded_rs(entries: &[(String, PathBuf, String)]) -> String {
    let mut s = String::new();
    s.push_str("// Generated by mvm-cli/build.rs. Do not edit.\n\n");
    s.push_str(
        "pub struct EmbeddedBinary { \
         pub name: &'static str, \
         pub bytes: &'static [u8], \
         pub sha256_hex: &'static str \
         }\n\n",
    );
    s.push_str("pub const EMBEDDED: &[EmbeddedBinary] = &[\n");
    for (name, path, sha) in entries {
        s.push_str(&format!(
            "    EmbeddedBinary {{ name: {name:?}, bytes: include_bytes!({path:?}), sha256_hex: {sha:?} }},\n"
        ));
    }
    s.push_str("];\n");
    s
}
