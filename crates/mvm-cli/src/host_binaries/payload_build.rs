//! Producing the Linux host payload: the content-store key each binary is
//! filed under, and the `cargo zigbuild` that compiles one. What the payload
//! holds and the argument vector of that compile are the build plan in
//! `payload_build_plan`, shared with `xtask`'s compile-units report, which
//! includes that file directly rather than depending on this crate.
//!
//! Compiled twice. `build.rs` includes this file by path to embed the payload
//! at build time, and `mvmctl` compiles it as a module to produce the same
//! payload at run time when the binary was built without one. Both derive the
//! key here, so whichever of them fills the store first, the other finds the
//! bytes — and a store-backed payload is byte-for-byte the one a later build
//! bakes in.
//!
//! Each includer provides `super::embed_toolchain`, the pinned toolchain the
//! compile uses: the build script by path, `mvmctl` from `mvm-build`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../../build_embed_cache.rs"]
pub(crate) mod build_embed_cache;
#[path = "payload_build_plan.rs"]
pub(crate) mod payload_build_plan;

use super::embed_toolchain::{Pin, resolve_pinned_zig, strip_glibc, try_rustup_cargo_and_rustc};
pub(crate) use payload_build_plan::{EmbeddedSourceBinary, read_manifest};

/// What identifies one cacheable artifact.
struct KeyRequest<'a> {
    package: &'a str,
    binary: &'a str,
    features: &'a str,
    target: &'a str,
    toolchain: &'a str,
    flavor: &'a str,
}

/// One source snapshot per workspace member, shared by all payload keys.
pub(crate) struct EmbedCache {
    pub workspace_root: PathBuf,
    graph: build_embed_cache::WorkspaceGraph,
    lockfile: String,
    toolchain_file: String,
    workspace_manifest: Option<build_embed_cache::WorkspaceManifestDigest>,
    pub root: Option<PathBuf>,
    sources: BTreeMap<String, Vec<(String, String)>>,
}

impl EmbedCache {
    /// The store this process's environment names, over `workspace_root`.
    pub(crate) fn discover(workspace_root: &Path) -> Self {
        Self::with_root(workspace_root, build_embed_cache::cache_root())
    }

    /// The store at `root`, over `workspace_root`. `None` turns caching off.
    pub(crate) fn with_root(workspace_root: &Path, root: Option<PathBuf>) -> Self {
        Self {
            workspace_root: workspace_root.to_path_buf(),
            graph: build_embed_cache::read_workspace_graph(workspace_root),
            lockfile: build_embed_cache::hash_file(&workspace_root.join("Cargo.lock")),
            toolchain_file: build_embed_cache::hash_file(
                &workspace_root.join("rust-toolchain.toml"),
            ),
            // A failed snapshot disables reuse/publication, never supplies an
            // empty digest. Cache-off callers still build without a cache.
            workspace_manifest: build_embed_cache::WorkspaceManifestDigest::read(workspace_root)
                .ok(),
            root,
            sources: BTreeMap::new(),
        }
    }

    /// Source hashes for everything `package` can reach inside the workspace.
    fn closure_sources(&mut self, package: &str) -> Vec<(String, String)> {
        let mut hashes = Vec::new();
        for member in build_embed_cache::workspace_closure(&self.graph, &[package]) {
            let Some(dir) = self.graph.dirs.get(&member) else {
                continue;
            };
            let sources = self
                .sources
                .entry(member)
                .or_insert_with(|| build_embed_cache::hash_member(&self.workspace_root, dir));
            hashes.extend_from_slice(sources);
        }
        hashes.sort();
        hashes
    }

    /// Cargo watches the same inputs used in the keys, without rereading them.
    pub(crate) fn watched_paths(&self) -> impl Iterator<Item = &str> {
        self.sources
            .values()
            .flatten()
            .map(|(path, _)| path.as_str())
    }

    /// `None` when caching is off or unavailable — callers then build.
    fn key_for(&mut self, request: &KeyRequest<'_>) -> Option<String> {
        self.root.as_ref()?;
        let workspace_manifest = self.workspace_manifest.clone()?;
        let sources = self.closure_sources(request.package);
        Some(build_embed_cache::artifact_key(
            &build_embed_cache::KeyInputs {
                package: request.package.to_string(),
                binary: request.binary.to_string(),
                features: request.features.to_string(),
                target: request.target.to_string(),
                toolchain: format!("{} rust={}", request.toolchain, self.toolchain_file),
                flavor: request.flavor.to_string(),
                lockfile: self.lockfile.clone(),
                workspace_manifest,
                sources,
            },
        ))
    }

    /// File a freshly built artifact under `key`.
    pub(crate) fn publish(&self, key: Option<&str>, binary: &str, source: &Path) {
        let (Some(root), Some(key)) = (self.root.as_ref(), key) else {
            return;
        };
        build_embed_cache::install(root, key, binary, source);
    }

    /// Keep the store inside its ceiling. Run once after publishing a set, so
    /// several artifacts prune once rather than per binary.
    pub(crate) fn prune(&self) {
        let Some(root) = self.root.as_ref() else {
            return;
        };
        build_embed_cache::prune(
            root,
            build_embed_cache::max_bytes_from(std::env::var_os("MVM_EMBED_CACHE_MAX_BYTES")),
        );
    }
}

/// The content-store key for one embedded binary under the pinned toolchain.
pub(crate) fn artifact_key_for(
    cache: &mut EmbedCache,
    binary: &EmbeddedSourceBinary,
    pin: &Pin,
) -> Option<String> {
    cache.key_for(&KeyRequest {
        package: &binary.package,
        binary: &binary.name,
        features: &binary.features,
        target: &pin.target,
        toolchain: &format!(
            "rust={} zig={} zigbuild={}",
            pin.rust, pin.zig, pin.cargo_zigbuild
        ),
        flavor: "musl-static",
    })
}

/// Where a cross-compiled binary lands inside a nested target directory.
pub(crate) fn zigbuild_output(target_dir: &Path, target: &str, binary: &str) -> PathBuf {
    target_dir
        .join(strip_glibc(target))
        .join("release")
        .join(binary)
}

#[derive(Default)]
pub(crate) struct ZigbuildRequest<'a> {
    root: Option<&'a Path>,
    target_dir: Option<&'a Path>,
    binary: Option<&'a EmbeddedSourceBinary>,
    pin: Option<&'a Pin>,
    output: Option<&'a Path>,
    quiet: bool,
}

impl<'a> ZigbuildRequest<'a> {
    pub(crate) fn with_root(mut self, root: &'a Path) -> Self {
        self.root = Some(root);
        self
    }

    pub(crate) fn with_target_dir(mut self, target_dir: &'a Path) -> Self {
        self.target_dir = Some(target_dir);
        self
    }

    pub(crate) fn with_binary(mut self, binary: &'a EmbeddedSourceBinary) -> Self {
        self.binary = Some(binary);
        self
    }

    pub(crate) fn with_pin(mut self, pin: &'a Pin) -> Self {
        self.pin = Some(pin);
        self
    }

    pub(crate) fn with_output(mut self, output: &'a Path) -> Self {
        self.output = Some(output);
        self
    }

    /// Pass `--quiet`: compiler errors still print, progress does not.
    pub(crate) fn with_quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    pub(crate) fn build(self) -> ZigbuildSpec<'a> {
        ZigbuildSpec {
            root: self.root.expect("zigbuild request root"),
            target_dir: self.target_dir.expect("zigbuild request target dir"),
            binary: self.binary.expect("zigbuild request binary"),
            pin: self.pin.expect("zigbuild request toolchain pin"),
            output: self.output.expect("zigbuild request output"),
            quiet: self.quiet,
        }
    }
}

pub(crate) struct ZigbuildSpec<'a> {
    root: &'a Path,
    target_dir: &'a Path,
    binary: &'a EmbeddedSourceBinary,
    pin: &'a Pin,
    output: &'a Path,
    quiet: bool,
}

impl ZigbuildSpec<'_> {
    /// The `cargo` arguments, after the program name — the shared plan's, so
    /// every consumer of the plan reports this exact selection.
    fn args(&self) -> Vec<String> {
        payload_build_plan::zigbuild_args(self.binary, &self.pin.target, self.quiet)
    }
}

/// Cross-compile one payload binary and copy it to the spec's output.
///
/// Always `cargo-zigbuild`, even when host arch == target arch: `ring` (pulled
/// transitively) compiles C, so the musl target needs a musl *C*
/// cross-compiler. zig supplies it; a plain `cargo build --target <arch>-musl`
/// would instead demand a system `<arch>-linux-musl-gcc`, which neither CI nor
/// the documented contributor setup carries.
pub(crate) fn run_cargo_zigbuild(spec: ZigbuildSpec<'_>) -> Result<(), String> {
    let (package, binary, target) = (&spec.binary.package, &spec.binary.name, &spec.pin.target);
    // The rustup-managed cargo, not the Homebrew one. The Homebrew cargo sets
    // RUSTC=rustc which doesn't have the cross targets, and that value
    // propagates into the nested `cargo build` that cargo-zigbuild spawns.
    let (cargo, rustc) = try_rustup_cargo_and_rustc(strip_glibc(target), &spec.pin.rust)?;
    let rust_sysroot = rustc_sysroot(&rustc)?;
    let mut cmd = super::helper_command(&cargo);
    cmd.args(spec.args());
    apply_nested_rust_env(&mut cmd, &rustc, spec.target_dir, spec.root, &rust_sysroot);
    cmd.current_dir(spec.root);
    apply_zigbuild_env(&mut cmd, spec.target_dir)?;
    // Pin the zig binary cargo-zigbuild uses. Left to PATH, a Homebrew-upgraded
    // zig (newer than the pin) fails downstream with a cryptic `CacheCheckFailed`.
    if let Some(zig) = resolve_pinned_zig(&spec.pin.zig)? {
        cmd.env("CARGO_ZIGBUILD_ZIG_PATH", zig);
    }
    let status = cmd.status().map_err(|e| {
        format!(
            "spawn `cargo zigbuild` ({e}) — install it with \
             `cargo install cargo-zigbuild --version {}`",
            spec.pin.cargo_zigbuild
        )
    })?;
    if !status.success() {
        return Err(format!(
            "cargo zigbuild failed for package {package}, binary {binary} ({status})"
        ));
    }
    let built = zigbuild_output(spec.target_dir, target, binary);
    std::fs::copy(&built, spec.output)
        .map(|_| ())
        .map_err(|e| format!("copy {} → {}: {e}", built.display(), spec.output.display()))
}

pub(crate) fn apply_nested_rust_env(
    cmd: &mut Command,
    rustc: &str,
    target_dir: &Path,
    workspace_root: &Path,
    rust_sysroot: &Path,
) {
    cmd.env("RUSTC", rustc)
        // A dedicated target dir: the outer `cargo build` holds the workspace
        // `target/` lock while its build script runs, so a nested cargo aimed
        // at the same directory would wait on it forever.
        .env("CARGO_TARGET_DIR", target_dir)
        .env("RUSTC_WORKSPACE_WRAPPER", "")
        .env_remove("RUSTUP_TOOLCHAIN")
        // The outer nightly's frontend flags are incompatible with the pinned
        // stable compiler used for reproducible embedded binaries.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS");
    // Empty values normally prevent a global compiler wrapper from leaking
    // into the reproducible nested build. On macOS the pinned rust-objcopy
    // binary needs the sysroot loader wrapper after nested Cargo reconstructs
    // its dynamic-library environment.
    #[cfg(target_os = "macos")]
    {
        cmd.env(
            "RUSTC_WRAPPER",
            workspace_root.join("scripts/rustc-macos-loader.sh"),
        );
        let loader_path = std::env::join_paths(
            std::iter::once(rust_sysroot.join("lib")).chain(
                std::env::var_os("DYLD_FALLBACK_LIBRARY_PATH")
                    .iter()
                    .flat_map(std::env::split_paths),
            ),
        )
        .expect("Rust sysroot paths are valid DYLD_FALLBACK_LIBRARY_PATH entries");
        // cargo-zigbuild invokes rust-objcopy itself after compilation, so the
        // wrapper alone cannot repair that process. Seed the nested command as
        // well; its own Cargo children inherit this value.
        cmd.env("DYLD_FALLBACK_LIBRARY_PATH", loader_path);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (workspace_root, rust_sysroot);
        cmd.env("RUSTC_WRAPPER", "");
    }
}

fn rustc_sysroot(rustc: &str) -> Result<PathBuf, String> {
    let output = super::helper_command(rustc)
        .args(["--print", "sysroot"])
        .output()
        .map_err(|error| format!("run {rustc} --print sysroot: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{rustc} --print sysroot failed with {}",
            output.status
        ));
    }
    let path = String::from_utf8(output.stdout)
        .map_err(|_| format!("{rustc} printed a non-UTF-8 sysroot"))?
        .trim()
        .to_string();
    if path.is_empty() {
        return Err(format!("{rustc} returned an empty sysroot"));
    }
    Ok(PathBuf::from(path))
}

/// Keep cargo-zigbuild and Zig caches under the nested target root instead of
/// platform-global defaults like `~/Library/Caches/cargo-zigbuild`, which make
/// source builds depend on unrelated host cache permissions and break
/// sandboxed verification.
fn apply_zigbuild_env(cmd: &mut Command, target_dir: &Path) -> Result<(), String> {
    let zigbuild_cache_dir = zigbuild_cache_dir(target_dir);
    let zig_global_cache_dir = zig_global_cache_dir(target_dir);
    for dir in [&zigbuild_cache_dir, &zig_global_cache_dir] {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    cmd.env("CARGO_ZIGBUILD_CACHE_DIR", zigbuild_cache_dir);
    cmd.env("ZIG_GLOBAL_CACHE_DIR", zig_global_cache_dir);
    Ok(())
}

fn zigbuild_cache_dir(target_dir: &Path) -> PathBuf {
    scoped_tool_cache_dir("cargo-zigbuild", target_dir)
}

fn zig_global_cache_dir(target_dir: &Path) -> PathBuf {
    scoped_tool_cache_dir("zig", target_dir)
}

fn scoped_tool_cache_dir(tool: &str, target_dir: &Path) -> PathBuf {
    target_dir
        .parent()
        .unwrap_or(target_dir)
        .join("tool-cache")
        .join(tool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_sources_use_one_snapshot_across_payload_packages() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
        for (name, dependencies) in [
            ("first", "[dependencies]\nshared = { path = '../shared' }\n"),
            (
                "second",
                "[dependencies]\nshared = { path = '../shared' }\n",
            ),
            ("shared", ""),
        ] {
            let member = root.join("crates").join(name);
            std::fs::create_dir_all(member.join("src")).unwrap();
            std::fs::write(
                member.join("Cargo.toml"),
                format!("[package]\nname = '{name}'\nversion = '0.1.0'\n{dependencies}"),
            )
            .unwrap();
            std::fs::write(member.join("src/lib.rs"), "pub fn original() {}\n").unwrap();
        }
        let mut cache = EmbedCache::with_root(root, Some(root.join("store")));
        let expected = build_embed_cache::workspace_closure(&cache.graph, &["second"])
            .iter()
            .flat_map(|member| build_embed_cache::hash_member(root, &cache.graph.dirs[member]))
            .collect::<Vec<_>>();
        cache.closure_sources("first");
        std::fs::write(
            root.join("crates/shared/src/lib.rs"),
            "pub fn changed() {}\n",
        )
        .unwrap();

        let mut expected = expected;
        expected.sort();
        assert_eq!(cache.closure_sources("second"), expected);
        let paths = cache
            .watched_paths()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(paths.len(), 6);
        assert!(paths.contains("crates/shared/src/lib.rs"));
        assert!(paths.contains("crates/first/Cargo.toml"));
        assert!(paths.contains("crates/second/Cargo.toml"));
        assert_eq!(cache.watched_paths().count(), paths.len());
        let mut next = EmbedCache::with_root(root, Some(root.join("store")));
        assert_ne!(next.closure_sources("second"), expected);
    }

    #[test]
    fn root_profile_snapshot_rekeys_every_payload_for_both_architectures() {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let binaries = read_manifest(workspace).unwrap();
        assert_eq!(binaries.len(), 5);
        for arch in ["aarch64", "x86_64"] {
            let pin =
                super::super::embed_toolchain::try_read_pinned_toolchain(workspace, arch).unwrap();
            for binary in &binaries {
                let directory = tempfile::tempdir().unwrap();
                let root = directory.path();
                let manifest = "[workspace]\n[profile.release]\nstrip = true\n";
                std::fs::write(root.join("Cargo.toml"), manifest).unwrap();
                let mut before = EmbedCache::with_root(root, Some(root.join("store")));
                let key = artifact_key_for(&mut before, binary, &pin).unwrap();
                assert_eq!(artifact_key_for(&mut before, binary, &pin).unwrap(), key);
                std::fs::write(
                    root.join("Cargo.toml"),
                    format!("{manifest}[profile.release.build-override]\nstrip = false\n"),
                )
                .unwrap();
                // One cache owns one snapshot; callers freeze the remaining
                // build inputs independently of this cache-key calculation.
                assert_eq!(artifact_key_for(&mut before, binary, &pin).unwrap(), key);
                let mut after = EmbedCache::with_root(root, Some(root.join("store")));
                let changed = artifact_key_for(&mut after, binary, &pin).unwrap();
                assert_ne!(key, changed, "{} {arch}", binary.name);
                assert_eq!(artifact_key_for(&mut after, binary, &pin).unwrap(), changed);
            }
        }
    }

    #[test]
    fn manifest_failure_never_mints_a_reusable_key_and_cache_off_stays_off() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let request = KeyRequest {
            package: "mvm-builder-guest",
            binary: "mvm-builderd",
            features: "",
            target: "x86_64-unknown-linux-musl",
            toolchain: "test",
            flavor: "musl-static",
        };
        let mut missing = EmbedCache::with_root(root, Some(root.join("store")));
        assert!(missing.key_for(&request).is_none());
        std::fs::create_dir(root.join("Cargo.toml")).unwrap();
        let mut unreadable = EmbedCache::with_root(root, Some(root.join("store")));
        assert!(unreadable.key_for(&request).is_none());
        std::fs::remove_dir(root.join("Cargo.toml")).unwrap();
        for invalid in ["", "not valid [", "[package]\nname = 'not-a-workspace'\n"] {
            std::fs::write(root.join("Cargo.toml"), invalid).unwrap();
            let mut cache = EmbedCache::with_root(root, Some(root.join("store")));
            assert!(cache.key_for(&request).is_none());
        }
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
        let mut off = EmbedCache::with_root(root, None);
        assert!(off.key_for(&request).is_none());
        assert!(!root.join("store").exists());
    }

    #[test]
    fn payload_key_uses_the_same_manifest_bound_common_writer_in_both_includers() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
        let mut cache = EmbedCache::with_root(root, Some(root.join("store")));
        let request = KeyRequest {
            package: "mvm-builder-guest",
            binary: "mvm-builderd",
            features: "",
            target: "x86_64-unknown-linux-musl",
            toolchain: "test",
            flavor: "musl-static",
        };
        let expected = build_embed_cache::artifact_key(&build_embed_cache::KeyInputs {
            package: request.package.into(),
            binary: request.binary.into(),
            features: request.features.into(),
            target: request.target.into(),
            toolchain: format!("{} rust={}", request.toolchain, cache.toolchain_file),
            flavor: request.flavor.into(),
            lockfile: cache.lockfile.clone(),
            workspace_manifest: build_embed_cache::WorkspaceManifestDigest::read(root).unwrap(),
            sources: Vec::new(),
        });
        assert_eq!(cache.key_for(&request), Some(expected));
    }

    #[test]
    fn nested_rust_env_drops_outer_nightly_flags_and_selects_safe_wrapper() {
        let mut cmd = Command::new("cargo");
        cmd.env("RUSTFLAGS", "-Zthreads=8")
            .env("CARGO_ENCODED_RUSTFLAGS", "-Zthreads=8")
            .env("RUSTC_WRAPPER", "outer-rustc-wrapper");

        apply_nested_rust_env(
            &mut cmd,
            "/toolchain/rustc",
            Path::new("/nested-target"),
            Path::new("/workspace"),
            Path::new("/toolchain"),
        );

        let env = cmd
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|item| item.to_string_lossy().into_owned()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(env.get("RUSTC"), Some(&Some("/toolchain/rustc".into())));
        assert_eq!(
            env.get("CARGO_TARGET_DIR"),
            Some(&Some("/nested-target".into()))
        );
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                env.get("RUSTC_WRAPPER"),
                Some(&Some(
                    "/workspace/scripts/rustc-macos-loader.sh".to_string()
                ))
            );
            let loader_path = env
                .get("DYLD_FALLBACK_LIBRARY_PATH")
                .and_then(Option::as_deref)
                .expect("nested loader path");
            assert!(loader_path.starts_with("/toolchain/lib"), "{loader_path}");
        }
        #[cfg(not(target_os = "macos"))]
        assert_eq!(env.get("RUSTC_WRAPPER"), Some(&Some(String::new())));
        assert_eq!(
            env.get("RUSTC_WORKSPACE_WRAPPER"),
            Some(&Some(String::new()))
        );
        assert_eq!(env.get("RUSTFLAGS"), Some(&None));
        assert_eq!(env.get("CARGO_ENCODED_RUSTFLAGS"), Some(&None));
        assert_eq!(env.get("RUSTUP_TOOLCHAIN"), Some(&None));
    }

    #[test]
    fn zigbuild_cache_dirs_live_next_to_nested_target_dir() {
        let target_dir = Path::new("/tmp/build/out/host-vm-target");
        assert_eq!(
            zigbuild_cache_dir(target_dir),
            PathBuf::from("/tmp/build/out/tool-cache/cargo-zigbuild")
        );
        assert_eq!(
            zig_global_cache_dir(target_dir),
            PathBuf::from("/tmp/build/out/tool-cache/zig")
        );
    }

    #[test]
    fn the_spec_args_are_the_shared_plan_args() {
        let binary = EmbeddedSourceBinary {
            package: "mvm-agentd".to_string(),
            name: "mvm-egress-client".to_string(),
            features: "addons".to_string(),
        };
        let pin = Pin {
            rust: "1.91.1".to_string(),
            zig: "0.13.0".to_string(),
            cargo_zigbuild: "0.23.0".to_string(),
            target: "aarch64-unknown-linux-musl".to_string(),
        };
        for quiet in [false, true] {
            let spec = ZigbuildRequest::default()
                .with_root(Path::new("/workspace"))
                .with_target_dir(Path::new("/nested"))
                .with_binary(&binary)
                .with_pin(&pin)
                .with_output(Path::new("/out/bin"))
                .with_quiet(quiet)
                .build();
            assert_eq!(
                spec.args(),
                payload_build_plan::zigbuild_args(&binary, &pin.target, quiet)
            );
        }
    }

    #[test]
    fn zigbuild_output_drops_the_glibc_suffix_from_the_target_dir() {
        assert_eq!(
            zigbuild_output(
                Path::new("/nested"),
                "aarch64-unknown-linux-gnu.2.17",
                "mvm-host-vm-init"
            ),
            PathBuf::from("/nested/aarch64-unknown-linux-gnu/release/mvm-host-vm-init")
        );
    }

    /// The build script parses the manifest's text and `mvmctl` reads the
    /// compiled constants, so the two must describe the same binaries in the
    /// same order — the order is part of the payload's identity.
    #[test]
    fn the_parsed_manifest_is_the_compiled_one() {
        use crate::host_binaries::manifest::{
            BOOTSTRAP_SUPPORT_BINARIES, HOST_BINARIES, SEED_BINARIES,
        };

        let parsed = payload_build_plan::parse_embedded_manifest(include_str!(
            "../../../mvm-builder-guest/src/host_payload_manifest.rs"
        ))
        .unwrap();
        let compiled: Vec<EmbeddedSourceBinary> = HOST_BINARIES
            .iter()
            .map(|bin| (bin.package, bin.name))
            .chain(
                SEED_BINARIES
                    .iter()
                    .map(|name| ("mvm-builder-guest", *name)),
            )
            .map(|(package, name)| EmbeddedSourceBinary {
                package: package.to_string(),
                name: name.to_string(),
                features: String::new(),
            })
            .chain(
                BOOTSTRAP_SUPPORT_BINARIES
                    .iter()
                    .map(|bin| EmbeddedSourceBinary {
                        package: bin.package.to_string(),
                        name: bin.name.to_string(),
                        features: bin.features.to_string(),
                    }),
            )
            .collect();
        assert_eq!(parsed, compiled);
    }
}
