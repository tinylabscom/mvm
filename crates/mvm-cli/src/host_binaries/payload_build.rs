//! Producing the Linux host payload: which binaries it holds, the content-store
//! key each one is filed under, and the `cargo zigbuild` that compiles one.
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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../../build_embed_cache.rs"]
pub(crate) mod build_embed_cache;

use super::embed_toolchain::{Pin, resolve_pinned_zig, strip_glibc, try_rustup_cargo_and_rustc};

/// One binary in the payload, as `manifest.rs` declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EmbeddedSourceBinary {
    pub package: String,
    pub name: String,
    pub features: String,
}

/// The payload manifest, relative to the workspace root.
pub(crate) const MANIFEST_PATH: &str = "crates/mvm-cli/src/host_binaries/manifest.rs";

/// Every binary in the payload, read from the manifest in `workspace_root`.
pub(crate) fn read_manifest(workspace_root: &Path) -> Result<Vec<EmbeddedSourceBinary>, String> {
    let path = workspace_root.join(MANIFEST_PATH);
    let src =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    parse_embedded_manifest(&src)
}

/// Every binary in the payload, in the order the table lists them.
///
/// Read out of the *text* of `crates/mvm-cli/src/host_binaries/manifest.rs`,
/// because a build script cannot depend on the crate it is building. The order
/// is part of the payload's identity — extraction hashes the table in order —
/// so both callers must read the same text the same way.
///
/// `HOST_BINARIES` (installed into the builder VM rootfs) and `SEED_BINARIES`
/// (host-side only, e.g. the Stage 0 nix-seed's `/init`) are both `mvm-build`
/// `[[bin]]`s; the bootstrap support list carries its own package names, so it
/// cannot assume one.
pub(crate) fn parse_embedded_manifest(src: &str) -> Result<Vec<EmbeddedSourceBinary>, String> {
    let mvm_build_bins = read_quoted_field_block(src, "HOST_BINARIES", "name:")?
        .into_iter()
        .chain(read_quoted_strings_block(src, "SEED_BINARIES")?)
        .map(|name| EmbeddedSourceBinary {
            package: "mvm-build".to_string(),
            name,
            features: String::new(),
        });
    let mut manifest: Vec<EmbeddedSourceBinary> = mvm_build_bins.collect();
    manifest.extend(parse_bootstrap_support_binaries(src)?);
    Ok(manifest)
}

fn parse_bootstrap_support_binaries(src: &str) -> Result<Vec<EmbeddedSourceBinary>, String> {
    let section = "BOOTSTRAP_SUPPORT_BINARIES";
    let packages = read_quoted_field_block(src, section, "package:")?;
    let names = read_quoted_field_block(src, section, "name:")?;
    let features = read_quoted_field_block(src, section, "features:")?;
    if packages.len() != names.len() || packages.len() != features.len() {
        return Err(format!(
            "{section} in manifest.rs has {} packages, {} names and {} feature lists; \
             every entry needs all three",
            packages.len(),
            names.len(),
            features.len()
        ));
    }
    Ok(packages
        .into_iter()
        .zip(names)
        .zip(features)
        .map(|((package, name), features)| EmbeddedSourceBinary {
            package,
            name,
            features,
        })
        .collect())
}

fn read_manifest_section<'a>(src: &'a str, name: &str) -> Result<&'a str, String> {
    let start = src
        .find(name)
        .ok_or_else(|| format!("manifest.rs declares no {name}"))?;
    let rest = &src[start..];
    let end = rest.find("];").map(|i| i + 2).unwrap_or(rest.len());
    Ok(&rest[..end])
}

fn read_quoted_field_block(src: &str, section: &str, field: &str) -> Result<Vec<String>, String> {
    Ok(read_manifest_section(src, section)?
        .lines()
        .filter_map(|line| extract_quoted_after(line, field))
        .collect())
}

fn read_quoted_strings_block(src: &str, section: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut s = read_manifest_section(src, section)?;
    while let Some(q1) = s.find('"') {
        let after = &s[q1 + 1..];
        let Some(q2) = after.find('"') else { break };
        out.push(after[..q2].to_string());
        s = &after[q2 + 1..];
    }
    Ok(out)
}

/// Extract the quoted string after `key` on one line, e.g.
/// `name: "mvm-host-vm-init",` + `"name:"` → `Some("mvm-host-vm-init")`.
pub(crate) fn extract_quoted_after(line: &str, key: &str) -> Option<String> {
    let i = line.find(key)? + key.len();
    let rest = &line[i..];
    let q1 = rest.find('"')? + 1;
    let q2 = rest[q1..].find('"')?;
    Some(rest[q1..q1 + q2].to_string())
}

/// What identifies one cacheable artifact.
struct KeyRequest<'a> {
    package: &'a str,
    binary: &'a str,
    features: &'a str,
    target: &'a str,
    toolchain: &'a str,
    flavor: &'a str,
}

/// The content store, plus the per-package source hashes its keys are built
/// from. Hashing a closure is the expensive part, so it is memoised: the
/// embedded binaries share two root packages between them.
pub(crate) struct EmbedCache {
    pub workspace_root: PathBuf,
    pub graph: build_embed_cache::WorkspaceGraph,
    lockfile: String,
    toolchain_file: String,
    pub root: Option<PathBuf>,
    sources: BTreeMap<String, Vec<(String, String)>>,
    /// Every workspace member a computed key hashed.
    pub watched: BTreeSet<String>,
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
            root,
            sources: BTreeMap::new(),
            watched: BTreeSet::new(),
        }
    }

    /// Source hashes for everything `package` can reach inside the workspace.
    fn closure_sources(&mut self, package: &str) -> Vec<(String, String)> {
        if let Some(hit) = self.sources.get(package) {
            return hit.clone();
        }
        let mut hashes = Vec::new();
        for member in build_embed_cache::workspace_closure(&self.graph, &[package]) {
            let Some(dir) = self.graph.dirs.get(&member) else {
                continue;
            };
            self.watched.insert(member.clone());
            hashes.extend(build_embed_cache::hash_member(&self.workspace_root, dir));
        }
        hashes.sort();
        self.sources.insert(package.to_string(), hashes.clone());
        hashes
    }

    /// `None` when caching is off or unavailable — callers then build.
    fn key_for(&mut self, request: &KeyRequest<'_>) -> Option<String> {
        self.root.as_ref()?;
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
    /// The `cargo` arguments, after the program name.
    fn args(&self) -> Vec<&str> {
        let binary = self.binary;
        let mut args = vec!["zigbuild", "--release"];
        if self.quiet {
            args.push("--quiet");
        }
        args.extend([
            "--target",
            self.pin.target.as_str(),
            "-p",
            binary.package.as_str(),
            "--bin",
            binary.name.as_str(),
        ]);
        if !binary.features.is_empty() {
            args.extend(["--features", binary.features.as_str()]);
        }
        args
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
    let mut cmd = Command::new(&cargo);
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
    // Empty values normally prevent a global sccache wrapper from leaking
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
    let output = Command::new(rustc)
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
    fn nested_rust_env_drops_outer_nightly_flags_and_selects_safe_wrapper() {
        let mut cmd = Command::new("cargo");
        cmd.env("RUSTFLAGS", "-Zthreads=8")
            .env("CARGO_ENCODED_RUSTFLAGS", "-Zthreads=8")
            .env("RUSTC_WRAPPER", "sccache");

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

    fn spec_args(binary: &EmbeddedSourceBinary, quiet: bool) -> Vec<String> {
        let pin = Pin {
            rust: "1.91.1".to_string(),
            zig: "0.13.0".to_string(),
            cargo_zigbuild: "0.23.0".to_string(),
            target: "aarch64-unknown-linux-musl".to_string(),
        };
        ZigbuildRequest::default()
            .with_root(Path::new("/workspace"))
            .with_target_dir(Path::new("/nested"))
            .with_binary(binary)
            .with_pin(&pin)
            .with_output(Path::new("/out/bin"))
            .with_quiet(quiet)
            .build()
            .args()
            .into_iter()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn the_zigbuild_names_the_package_binary_features_and_target() {
        let binary = EmbeddedSourceBinary {
            package: "mvm-agentd".to_string(),
            name: "mvm-egress-client".to_string(),
            features: "addons".to_string(),
        };
        assert_eq!(
            spec_args(&binary, false),
            [
                "zigbuild",
                "--release",
                "--target",
                "aarch64-unknown-linux-musl",
                "-p",
                "mvm-agentd",
                "--bin",
                "mvm-egress-client",
                "--features",
                "addons",
            ]
        );
    }

    /// Runtime callers pass `--quiet` unless asked to be verbose; nothing else
    /// about the compile may change with it, or the bytes would.
    #[test]
    fn a_quiet_zigbuild_differs_only_by_quiet() {
        let binary = EmbeddedSourceBinary {
            package: "mvm-build".to_string(),
            name: "mvm-host-vm-init".to_string(),
            features: String::new(),
        };
        let loud = spec_args(&binary, false);
        let quiet = spec_args(&binary, true);
        assert!(!loud.contains(&"--quiet".to_string()));
        assert_eq!(
            quiet
                .iter()
                .filter(|arg| *arg != "--quiet")
                .collect::<Vec<_>>(),
            loud.iter().collect::<Vec<_>>()
        );
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

    #[test]
    fn parses_bootstrap_support_binaries_with_their_own_package() {
        let src = r#"
pub const BOOTSTRAP_SUPPORT_BINARIES: &[SourceBuiltBinary] = &[
    SourceBuiltBinary {
        package: "mvm-agentd",
        name: "mvm-egress-client",
        features: "addons",
    },
];
"#;
        assert_eq!(
            parse_bootstrap_support_binaries(src).unwrap(),
            vec![EmbeddedSourceBinary {
                package: "mvm-agentd".to_string(),
                name: "mvm-egress-client".to_string(),
                features: "addons".to_string(),
            }]
        );
    }

    #[test]
    fn a_support_entry_missing_a_field_is_refused_rather_than_misaligned() {
        let src = r#"
pub const BOOTSTRAP_SUPPORT_BINARIES: &[SourceBuiltBinary] = &[
    SourceBuiltBinary { package: "mvm-agentd", name: "mvm-egress-client" },
];
"#;
        let reason = parse_bootstrap_support_binaries(src).unwrap_err();
        assert!(reason.contains("every entry needs all three"), "{reason}");
    }

    #[test]
    fn host_binary_names_exclude_bootstrap_support_entries() {
        let src = r#"
pub const HOST_BINARIES: &[HostBinary] = &[
    HostBinary { name: "mvm-host-vm-init", install_path: "/sbin/mvm-host-vm-init", mode: 0o755 },
    HostBinary { name: "mvm-builderd", install_path: "/sbin/mvm-builderd", mode: 0o755 },
];
pub const SEED_BINARIES: &[&str] = &["stage0-init"];
pub const BOOTSTRAP_SUPPORT_BINARIES: &[SourceBuiltBinary] = &[SourceBuiltBinary {
    package: "mvm-agentd",
    name: "mvm-egress-client",
    features: "addons",
}];
"#;
        assert_eq!(
            read_quoted_field_block(src, "HOST_BINARIES", "name:").unwrap(),
            vec!["mvm-host-vm-init".to_string(), "mvm-builderd".to_string()]
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

        let parsed = parse_embedded_manifest(include_str!("manifest.rs")).unwrap();
        let compiled: Vec<EmbeddedSourceBinary> = HOST_BINARIES
            .iter()
            .map(|bin| bin.name)
            .chain(SEED_BINARIES.iter().copied())
            .map(|name| EmbeddedSourceBinary {
                package: "mvm-build".to_string(),
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

    #[test]
    fn extract_quoted_after_reads_the_quoted_value() {
        assert_eq!(
            extract_quoted_after(r#"        name: "mvm-host-vm-init","#, "name:"),
            Some("mvm-host-vm-init".to_string())
        );
        assert_eq!(extract_quoted_after("no key here", "name:"), None);
    }
}
