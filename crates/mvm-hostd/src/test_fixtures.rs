//! Fixtures shared by this crate's tests.
#![cfg(test)]

use std::path::Path;

use mvm_core::util::test_env::TestEnv;

/// Point `MVM_HOME` and `HOME` at a fresh scratch directory for as long as the
/// returned guard lives.
///
/// Any test whose code path resolves a path through `mvm_core::config` —
/// host config, the keys directory, VM or mock-VM state — needs this, even
/// when it never sets anything itself. `cargo test` runs a crate's tests as
/// threads of one process, so an unguarded test reads whichever home another
/// test has pointed the process at: one configured to refuse admission, or
/// one that is deleted halfway through. Holding the guard also serializes it
/// against every other test that changes the environment.
///
/// Bind both halves and keep them to the end of the test.
pub(crate) fn isolated_mvm_home() -> (TestEnv, tempfile::TempDir) {
    let home = tempfile::tempdir().expect("scratch mvm home");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    (env, home)
}

/// Install the runtime overlay a cold boot requires into `<mvm_home>/cache`.
///
/// The fixture goes through the shared overlay reader and cache installer, so
/// the resolver verifies the same ext4 payload, checksums, version, and
/// sidecars as production.
pub(crate) fn install_runtime_overlay(mvm_home: &Path) {
    let cache = mvm_home.join("cache");
    let workspace = mvm_build::image_source::guest_runtime_source_checkout()
        .expect("source-channel test checkout");
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let runtime = mvm_build::guest_runtime::test_support::write_source_cache_fixture(
        &cache, &workspace, version, arch,
    )
    .expect("complete source-runtime fixture");
    mvm_build::runtime_overlay::build_runtime_overlay_from_guest_runtime(
        &cache, version, arch, &runtime,
    )
    .expect("assemble fixture overlay");
    mvm_build::initramfs::build_initramfs_from_guest_runtime(
        &cache.join("initramfs"),
        version,
        arch,
        &runtime,
    )
    .expect("assemble fixture initramfs");
}

/// Run `f`, returning its value and every warning it logged on this thread.
///
/// A test that only asserts "admitted" cannot tell a warned admission from
/// a silent one, and the difference is the whole dev half of the rule.
///
/// One process-wide subscriber, installed on first use, writes each event to
/// a buffer owned by the emitting thread. A per-thread subscriber is not
/// enough under a single-process `cargo test`: callsite interest and the
/// maximum level are global, and another thread can leave a callsite cached
/// as uninteresting, so the capture saw nothing.
pub(crate) fn capturing_warnings<T>(f: impl FnOnce() -> T) -> (T, String) {
    use std::cell::RefCell;

    thread_local! {
        static SINK: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
    }

    struct ThreadSink;

    impl std::io::Write for ThreadSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            SINK.with_borrow_mut(|sink| {
                if let Some(sink) = sink {
                    sink.extend_from_slice(buf);
                }
            });
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(|| ThreadSink)
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("no other library test installs a global subscriber");
    });
    SINK.set(Some(Vec::new()));
    let value = f();
    let logged = SINK.with_borrow_mut(Option::take).unwrap_or_default();
    (
        value,
        String::from_utf8(logged).expect("log output is utf-8"),
    )
}
