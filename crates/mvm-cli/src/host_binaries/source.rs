//! Where `mvmctl`'s Linux host payload comes from.
//!
//! A binary built with the payload carries it compiled in. One built without it
//! — a debug build, or a release built with `MVM_EMBED=0` or without the
//! cross-compile toolchain — produces the same set from the source checkout it
//! was built from, through the content store the build script restores from. So
//! reaching a builder VM takes one command and one `mvmctl` either way, and the
//! next plain `cargo build` embeds the bytes this produced without compiling
//! them again.
//!
//! Both sources report each binary's SHA-256, and everything downstream keys on
//! those — extraction, and the builder image's source fingerprint — so a
//! payload read from the store is indistinguishable from the same bytes
//! compiled in.

use std::borrow::Cow;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use mvm_vmm::host::aux_bin::{CliSpawn, HostProcess};

use super::embed_toolchain;
use super::embedded::EMBEDDED;
use super::payload_build::{
    self, EmbedCache, EmbeddedSourceBinary, ZigbuildRequest, artifact_key_for, build_embed_cache,
};
use build_embed_cache::Stored;

/// One binary of the payload.
pub struct PayloadBinary {
    pub name: String,
    pub sha256_hex: String,
    bytes: PayloadBytes,
}

enum PayloadBytes {
    CompiledIn(&'static [u8]),
    Stored(PathBuf),
}

impl PayloadBinary {
    /// The binary's bytes. A stored binary is read on each call; callers
    /// extract once and verify what they wrote.
    pub(crate) fn contents(&self) -> io::Result<Cow<'static, [u8]>> {
        match &self.bytes {
            PayloadBytes::CompiledIn(bytes) => Ok(Cow::Borrowed(bytes)),
            PayloadBytes::Stored(path) => std::fs::read(path).map(Cow::Owned),
        }
    }
}

/// Something that can hand over the whole payload.
pub(crate) trait PayloadSource {
    /// Every binary of the payload, in table order, or why there is none.
    fn load(&self) -> io::Result<Vec<PayloadBinary>>;
}

/// The payload `build.rs` compiled into this binary.
pub(crate) struct CompiledIn;

impl PayloadSource for CompiledIn {
    fn load(&self) -> io::Result<Vec<PayloadBinary>> {
        Ok(EMBEDDED
            .iter()
            .map(|bin| PayloadBinary {
                name: bin.name.to_string(),
                sha256_hex: bin.sha256_hex.to_string(),
                bytes: PayloadBytes::CompiledIn(bin.bytes),
            })
            .collect())
    }
}

/// Cross-compiles payload binaries. A trait so tests can stand in for a
/// multi-minute `cargo zigbuild`.
pub(crate) trait PayloadCompiler {
    /// Why this host cannot compile the payload, asked before a compile is
    /// announced so a missing toolchain fails in milliseconds.
    fn ready(&self, checkout: &Path) -> Result<(), String>;

    /// Cross-compile `binary` from `checkout` into `output`.
    fn compile(
        &self,
        checkout: &Path,
        binary: &EmbeddedSourceBinary,
        output: &Path,
    ) -> Result<(), String>;
}

/// The pinned `cargo zigbuild` the build script runs, run from `mvmctl`.
pub(crate) struct Zigbuild;

impl PayloadCompiler for Zigbuild {
    fn ready(&self, checkout: &Path) -> Result<(), String> {
        embed_toolchain::check_toolchain_ready(&pinned_toolchain(checkout)?)
    }

    fn compile(
        &self,
        checkout: &Path,
        binary: &EmbeddedSourceBinary,
        output: &Path,
    ) -> Result<(), String> {
        let pin = pinned_toolchain(checkout)?;
        let target_dir = payload_target_dir(checkout);
        payload_build::run_cargo_zigbuild(
            ZigbuildRequest::default()
                .with_root(checkout)
                .with_target_dir(&target_dir)
                .with_binary(binary)
                .with_pin(&pin)
                .with_output(output)
                .with_quiet(!mvm_runtime::ui::is_verbose())
                .build(),
        )
    }
}

fn pinned_toolchain(checkout: &Path) -> Result<embed_toolchain::Pin, String> {
    embed_toolchain::try_read_pinned_toolchain(checkout, std::env::consts::ARCH)
}

/// The nested Cargo target the runtime compile uses.
///
/// Its own directory, never the checkout's `target/<profile>`: a `cargo build`
/// running beside this one holds that directory's lock for its whole run. The
/// `host-vm-target` leaf is the name `just embed-refresh` clears.
fn payload_target_dir(checkout: &Path) -> PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .map(|dir| {
            if dir.is_absolute() {
                dir
            } else {
                checkout.join(dir)
            }
        })
        .unwrap_or_else(|| checkout.join("target"));
    target.join("mvm-host-payload").join("host-vm-target")
}

/// Where the status line announcing a compile goes.
pub(crate) trait PayloadNotice {
    fn announce(&self, line: &str);
}

/// Standard error, so a verb that writes JSON to stdout stays parseable.
pub(crate) struct StderrNotice;

impl PayloadNotice for StderrNotice {
    fn announce(&self, line: &str) {
        eprintln!("[mvm] {line}");
    }
}

/// The payload produced from a source checkout, through the content store.
pub(crate) struct ContentStore {
    checkout: PathBuf,
    store_root: PathBuf,
    host: HostProcess,
    compiler: Box<dyn PayloadCompiler>,
    notice: Box<dyn PayloadNotice>,
}

impl ContentStore {
    /// The store at `store_root`, filled from `checkout` with the pinned
    /// `cargo zigbuild`, on behalf of this process.
    pub(crate) fn new(checkout: impl Into<PathBuf>, store_root: impl Into<PathBuf>) -> Self {
        Self {
            checkout: checkout.into(),
            store_root: store_root.into(),
            host: HostProcess::current(),
            compiler: Box::new(Zigbuild),
            notice: Box::new(StderrNotice),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_host(mut self, host: HostProcess) -> Self {
        self.host = host;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_compiler(mut self, compiler: impl PayloadCompiler + 'static) -> Self {
        self.compiler = Box::new(compiler);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_notice(mut self, notice: impl PayloadNotice + 'static) -> Self {
        self.notice = Box::new(notice);
        self
    }

    /// Each binary's content-store key, in manifest order — the keys the build
    /// script computes, so either side finds what the other stored.
    fn keyed_manifest(&self) -> io::Result<Vec<(EmbeddedSourceBinary, String)>> {
        let manifest = payload_build::read_manifest(&self.checkout).map_err(io::Error::other)?;
        let pin = pinned_toolchain(&self.checkout).map_err(io::Error::other)?;
        let mut cache = EmbedCache::with_root(&self.checkout, Some(self.store_root.clone()));
        manifest
            .into_iter()
            .map(|binary| {
                let key = artifact_key_for(&mut cache, &binary, &pin)
                    .ok_or_else(|| io::Error::other("content store key unavailable"))?;
                Ok((binary, key))
            })
            .collect()
    }

    /// What the store holds for each binary: `None` where it holds nothing.
    /// A stored binary whose bytes changed since it was published is refused.
    fn inspect(
        &self,
        keyed: &[(EmbeddedSourceBinary, String)],
    ) -> io::Result<Vec<Option<PayloadBinary>>> {
        keyed
            .iter()
            .map(|(binary, key)| {
                match build_embed_cache::inspect(&self.store_root, key, &binary.name) {
                    Stored::Missing => Ok(None),
                    Stored::Verified { path, sha256 } => Ok(Some(PayloadBinary {
                        name: binary.name.clone(),
                        sha256_hex: sha256,
                        bytes: PayloadBytes::Stored(path),
                    })),
                    Stored::Corrupt {
                        path,
                        recorded,
                        actual,
                    } => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        corrupt_entry_message(&path, &recorded, &actual),
                    )),
                }
            })
            .collect()
    }

    /// Compile every binary in `missing` and publish it into the store.
    fn compile_missing(&self, missing: &[&(EmbeddedSourceBinary, String)]) -> io::Result<()> {
        let out_dir = payload_target_dir(&self.checkout).with_file_name("out");
        std::fs::create_dir_all(&out_dir)?;
        for (binary, key) in missing {
            // Another `mvmctl` may have published it while this one waited for
            // the lock.
            if let Stored::Verified { .. } =
                build_embed_cache::inspect(&self.store_root, key, &binary.name)
            {
                continue;
            }
            let output = out_dir.join(&binary.name);
            self.compiler
                .compile(&self.checkout, binary, &output)
                .map_err(io::Error::other)?;
            build_embed_cache::install(&self.store_root, key, &binary.name, &output);
        }
        build_embed_cache::prune(
            &self.store_root,
            build_embed_cache::max_bytes_from(std::env::var_os("MVM_EMBED_CACHE_MAX_BYTES")),
        );
        Ok(())
    }
}

impl PayloadSource for ContentStore {
    fn load(&self) -> io::Result<Vec<PayloadBinary>> {
        self.host
            .refuse_cli_spawn(CliSpawn::HostPayloadBuild)
            .map_err(io::Error::other)?;
        let keyed = self.keyed_manifest()?;
        let found = self.inspect(&keyed)?;
        let missing: Vec<_> = keyed
            .iter()
            .zip(&found)
            .filter_map(|(entry, stored)| stored.is_none().then_some(entry))
            .collect();
        if missing.is_empty() {
            return Ok(found.into_iter().flatten().collect());
        }

        self.compiler
            .ready(&self.checkout)
            .map_err(|reason| io::Error::other(toolchain_refusal(&reason)))?;
        self.notice
            .announce(&compile_notice(missing.len(), keyed.len()));
        std::fs::create_dir_all(&self.store_root)?;
        let _lock =
            mvm_core::util::atomic_io::FileLock::acquire(&self.store_root.join("payload-build"))
                .map_err(|e| io::Error::other(format!("{e:#}")))?;
        self.compile_missing(&missing)?;

        let found = self.inspect(&keyed)?;
        if found.iter().any(Option::is_none) {
            return Err(io::Error::other(format!(
                "the Linux host binaries were built but could not be stored in {}; \
                 check that the directory is writable",
                self.store_root.display()
            )));
        }
        Ok(found.into_iter().flatten().collect())
    }
}

/// The one line printed before a compile: what, why, and how long.
fn compile_notice(missing: usize, total: usize) -> String {
    let stream = if mvm_runtime::ui::is_verbose() {
        ""
    } else {
        " Pass -v to stream the compiler output."
    };
    format!(
        "Building the Linux host binaries this binary was compiled without ({missing} of \
         {total} not yet built for this source tree). A few minutes from cold, less when \
         only a few crates changed; the next `cargo build` embeds the result.{stream}"
    )
}

fn toolchain_refusal(reason: &str) -> String {
    format!(
        "this binary was compiled without the embedded Linux host binaries, and the \
         pinned cross-compile toolchain it needs to build them is unavailable: {reason} \
         Install it with `just toolchain-embed`, then retry."
    )
}

fn corrupt_entry_message(path: &Path, recorded: &str, actual: &str) -> String {
    format!(
        "{} in the embedded-binary content store no longer matches the SHA-256 recorded \
         when it was built (recorded {recorded}, now {actual}); refusing to use it. Delete \
         its directory, {}, and retry to rebuild it.",
        path.display(),
        path.parent().unwrap_or(path).display()
    )
}

/// Which source serves this process's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PayloadChoice {
    CompiledIn,
    FromSource {
        checkout: PathBuf,
        store_root: PathBuf,
    },
    Unavailable,
}

/// Pick the payload source.
///
/// A compiled-in payload always wins. Otherwise the checkout builds one, when
/// source builds are allowed and there is both a checkout and a store to build
/// into.
pub(crate) fn choose_payload(
    compiled_in: bool,
    source_builds: bool,
    checkout: Option<PathBuf>,
    store_root: Option<PathBuf>,
) -> PayloadChoice {
    match (compiled_in, source_builds, checkout, store_root) {
        (true, ..) => PayloadChoice::CompiledIn,
        (false, true, Some(checkout), Some(store_root)) => PayloadChoice::FromSource {
            checkout,
            store_root,
        },
        _ => PayloadChoice::Unavailable,
    }
}

/// Set once by `mvmctl` at startup.
///
/// Off by default, so a test binary or any other consumer of this crate gets
/// the refusal rather than a multi-minute compile it never asked for.
static SOURCE_BUILDS_ALLOWED: AtomicBool = AtomicBool::new(false);

/// Let this process build a missing payload from its source checkout.
pub fn allow_payload_from_source() {
    SOURCE_BUILDS_ALLOWED.store(true, Ordering::Relaxed);
}

/// The checkout this binary was compiled from, when it is still there.
fn compiled_checkout() -> Option<PathBuf> {
    let root =
        embed_toolchain::workspace_root_from_manifest_dir(Path::new(env!("CARGO_MANIFEST_DIR")));
    (root.join(payload_build::MANIFEST_PATH).is_file() && root.join("Cargo.lock").is_file())
        .then_some(root)
}

/// This process's payload source.
pub(crate) fn current_choice() -> PayloadChoice {
    let source_builds = SOURCE_BUILDS_ALLOWED.load(Ordering::Relaxed)
        && mvm_build::artifact_acquisition::compiled_channel().permits_automatic_builds();
    choose_payload(
        !EMBEDDED.is_empty(),
        source_builds,
        source_builds.then(compiled_checkout).flatten(),
        build_embed_cache::store_root(),
    )
}

/// Whether this process can supply a payload, without producing one.
pub fn payload_available() -> bool {
    current_choice() != PayloadChoice::Unavailable
}

/// The payload, produced at most once per process.
///
/// Only a success is kept: a failed attempt (a missing toolchain, say) is
/// retried by the next caller rather than remembered.
pub fn host_payload() -> io::Result<&'static [PayloadBinary]> {
    static PAYLOAD: OnceLock<Vec<PayloadBinary>> = OnceLock::new();
    if let Some(payload) = PAYLOAD.get() {
        return Ok(payload);
    }
    let loaded = match current_choice() {
        PayloadChoice::CompiledIn => CompiledIn.load()?,
        PayloadChoice::FromSource {
            checkout,
            store_root,
        } => ContentStore::new(checkout, store_root).load()?,
        PayloadChoice::Unavailable => {
            return Err(io::Error::other(super::extract::no_payload_message(cfg!(
                debug_assertions
            ))));
        }
    };
    Ok(PAYLOAD.get_or_init(|| loaded))
}

/// The payload, or an empty one when this process has no way to get it.
///
/// For identity folds, which treat a binary without a payload the way they
/// always treated an empty compiled-in table.
pub fn host_payload_if_any() -> io::Result<&'static [PayloadBinary]> {
    if current_choice() == PayloadChoice::Unavailable {
        return Ok(&[]);
    }
    host_payload()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    /// Records what happened, in order, across the compiler and the notice.
    #[derive(Clone, Default)]
    struct Journal(Arc<Mutex<Vec<String>>>);

    impl Journal {
        fn push(&self, event: String) {
            self.0.lock().unwrap().push(event);
        }

        fn events(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }

        fn compiles(&self) -> usize {
            self.events()
                .iter()
                .filter(|e| e.starts_with("compile "))
                .count()
        }
    }

    /// Writes deterministic bytes per binary instead of cross-compiling.
    struct FakeCompiler {
        journal: Journal,
        ready: Result<(), String>,
    }

    impl PayloadCompiler for FakeCompiler {
        fn ready(&self, _checkout: &Path) -> Result<(), String> {
            self.ready.clone()
        }

        fn compile(
            &self,
            _checkout: &Path,
            binary: &EmbeddedSourceBinary,
            output: &Path,
        ) -> Result<(), String> {
            self.journal.push(format!("compile {}", binary.name));
            std::fs::write(output, fake_bytes(&binary.name)).map_err(|e| e.to_string())
        }
    }

    struct JournalNotice(Journal);

    impl PayloadNotice for JournalNotice {
        fn announce(&self, line: &str) {
            self.0.push(format!("notice {line}"));
        }
    }

    fn fake_bytes(name: &str) -> Vec<u8> {
        format!("\x7fELF payload {name}").into_bytes()
    }

    fn checkout() -> PathBuf {
        compiled_checkout().expect("tests run from a source checkout")
    }

    /// A store under a scratch directory, and a compile target under another,
    /// so nothing here touches the developer's real cache or `target/`.
    struct Scratch {
        _dir: tempfile::TempDir,
        store: PathBuf,
    }

    impl Scratch {
        fn new() -> Self {
            let dir = tempfile::TempDir::new().unwrap();
            let store = dir.path().join("embed");
            Self { _dir: dir, store }
        }

        fn source(&self, journal: &Journal) -> ContentStore {
            ContentStore::new(checkout(), &self.store)
                .with_host(HostProcess::undeclared())
                .with_compiler(FakeCompiler {
                    journal: journal.clone(),
                    ready: Ok(()),
                })
                .with_notice(JournalNotice(journal.clone()))
        }

        /// Publish fake bytes for every binary under the keys the build script
        /// would compute, as a completed `cargo build --release` leaves them.
        fn publish_all(&self) {
            let journal = Journal::default();
            let source = self.source(&journal);
            let staged = self.store.with_file_name("staged");
            std::fs::create_dir_all(&staged).unwrap();
            for (binary, key) in source.keyed_manifest().unwrap() {
                let file = staged.join(&binary.name);
                std::fs::write(&file, fake_bytes(&binary.name)).unwrap();
                build_embed_cache::install(&self.store, &key, &binary.name, &file);
            }
        }
    }

    // The payload is produced in a nested target under the checkout; the fake
    // compiler never touches it, but `compile_missing` creates its `out/`.
    // Point it at scratch so a test run leaves `target/` as it found it.
    fn isolate_target(scratch: &Scratch) -> mvm_core::util::test_env::TestEnv {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("CARGO_TARGET_DIR", scratch.store.with_file_name("target"));
        env
    }

    #[test]
    fn a_store_hit_loads_without_compiling() {
        let scratch = Scratch::new();
        let _env = isolate_target(&scratch);
        scratch.publish_all();
        let journal = Journal::default();

        let payload = scratch.source(&journal).load().expect("store hit");

        assert_eq!(journal.events(), Vec::<String>::new());
        let names: Vec<_> = payload.iter().map(|bin| bin.name.clone()).collect();
        let manifest: Vec<_> = payload_build::read_manifest(&checkout())
            .unwrap()
            .into_iter()
            .map(|bin| bin.name)
            .collect();
        assert_eq!(names, manifest, "table order is part of the identity");
        for bin in payload {
            assert_eq!(bin.contents().unwrap().as_ref(), fake_bytes(&bin.name));
        }
    }

    #[test]
    fn a_store_miss_announces_then_compiles_every_binary_once() {
        let scratch = Scratch::new();
        let _env = isolate_target(&scratch);
        let journal = Journal::default();

        let payload = scratch.source(&journal).load().expect("built");

        let events = journal.events();
        assert!(
            events.first().is_some_and(|e| e.starts_with("notice ")),
            "the status line must come before the first compile: {events:?}"
        );
        assert_eq!(
            events.iter().filter(|e| e.starts_with("notice ")).count(),
            1,
            "one line, not one per binary: {events:?}"
        );
        assert_eq!(journal.compiles(), payload.len());

        // Published, so a second process finds it and compiles nothing.
        let again = Journal::default();
        scratch.source(&again).load().expect("store hit");
        assert_eq!(again.compiles(), 0);
    }

    #[test]
    fn a_missing_toolchain_refuses_before_announcing_anything() {
        let scratch = Scratch::new();
        let _env = isolate_target(&scratch);
        let journal = Journal::default();
        let source = scratch.source(&journal).with_compiler(FakeCompiler {
            journal: journal.clone(),
            ready: Err("zig 0.13.0 was not found.".to_string()),
        });

        let err = source.load().err().expect("refused").to_string();

        assert!(err.contains("zig 0.13.0 was not found."), "{err}");
        assert!(err.contains("just toolchain-embed"), "{err}");
        assert_eq!(journal.events(), Vec::<String>::new());
    }

    #[test]
    fn a_tampered_store_entry_is_refused() {
        let scratch = Scratch::new();
        let _env = isolate_target(&scratch);
        scratch.publish_all();
        let journal = Journal::default();
        let source = scratch.source(&journal);
        let (binary, key) = source.keyed_manifest().unwrap().remove(0);
        std::fs::write(
            build_embed_cache::artifact_path(&scratch.store, &key, &binary.name),
            b"tampered",
        )
        .unwrap();

        let err = source.load().err().expect("refused");

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("SHA-256"), "{err}");
        assert_eq!(journal.compiles(), 0, "a corrupt entry is not rebuilt over");
    }

    #[test]
    fn a_library_embedder_is_refused_before_touching_the_store() {
        let scratch = Scratch::new();
        let _env = isolate_target(&scratch);
        let journal = Journal::default();
        let source = scratch
            .source(&journal)
            .with_host(HostProcess::undeclared().as_library_embedder());

        let err = source.load().err().expect("refused").to_string();

        assert!(err.contains("mvmctl bootstrap"), "{err}");
        assert_eq!(journal.events(), Vec::<String>::new());
        assert!(!scratch.store.exists());
    }

    /// The builder image's fingerprint folds each binary's name and SHA-256.
    /// The same bytes must fold the same whether they were compiled in or read
    /// from the store, or switching sources would rebuild the builder image.
    #[test]
    fn stored_and_compiled_in_bytes_report_the_same_identity() {
        let scratch = Scratch::new();
        let _env = isolate_target(&scratch);
        scratch.publish_all();
        let stored = scratch.source(&Journal::default()).load().unwrap();

        for bin in &stored {
            let bytes: &'static [u8] = Box::leak(fake_bytes(&bin.name).into_boxed_slice());
            let compiled = PayloadBinary {
                name: bin.name.clone(),
                sha256_hex: hex::encode(<sha2::Sha256 as sha2::Digest>::digest(bytes)),
                bytes: PayloadBytes::CompiledIn(bytes),
            };
            assert_eq!(compiled.sha256_hex, bin.sha256_hex, "{}", bin.name);
            assert_eq!(
                compiled.contents().unwrap(),
                bin.contents().unwrap(),
                "{}",
                bin.name
            );
        }
    }

    #[test]
    fn a_compiled_in_payload_always_wins() {
        assert_eq!(
            choose_payload(true, true, Some("/src".into()), Some("/store".into())),
            PayloadChoice::CompiledIn
        );
    }

    #[test]
    fn an_empty_table_builds_from_its_checkout_when_allowed() {
        assert_eq!(
            choose_payload(false, true, Some("/src".into()), Some("/store".into())),
            PayloadChoice::FromSource {
                checkout: "/src".into(),
                store_root: "/store".into(),
            }
        );
    }

    /// Outside a checkout, or where source builds are not allowed, an empty
    /// table is refused as it always was.
    #[test]
    fn an_empty_table_without_a_checkout_or_permission_is_unavailable() {
        for (source_builds, checkout, store) in [
            (true, None, Some(PathBuf::from("/store"))),
            (
                false,
                Some(PathBuf::from("/src")),
                Some(PathBuf::from("/store")),
            ),
            (true, Some(PathBuf::from("/src")), None),
        ] {
            assert_eq!(
                choose_payload(false, source_builds, checkout, store),
                PayloadChoice::Unavailable
            );
        }
    }

    #[test]
    fn the_status_line_says_what_why_and_how_long() {
        let line = compile_notice(4, 6);
        assert!(line.contains("Linux host binaries"), "{line}");
        assert!(line.contains("compiled without"), "{line}");
        assert!(line.contains("4 of 6"), "{line}");
        assert!(line.contains("few minutes"), "{line}");
    }
}
