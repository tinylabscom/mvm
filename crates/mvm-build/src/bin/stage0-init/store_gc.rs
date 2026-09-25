//! When Stage 0 garbage-collects its persistent Nix store, and what it keeps.
//!
//! The store is Stage 0's build cache: a later bootstrap reuses the kernel and
//! host binaries it compiled. Nothing bounded it, so every source revision's
//! intermediates stayed until the image hit its 64 GiB ceiling. Stage 0 now
//! collects past the same cap the steady-state builder uses, which keeps a warm
//! cache below it.
//!
//! Collecting safely needs two things the store did not have. The seed's own
//! paths — the `nix` that runs Stage 0 and its CA bundle — were never loaded
//! into the Nix database, and Nix ignores a root that points at an unregistered
//! path and deletes unregistered paths as garbage. So the seed is registered
//! from its `.reginfo` and rooted before any collection, and the build output
//! is rooted so an unchanged next bootstrap is still a cache hit.

use std::path::{Component, Path, PathBuf};

use mvm_build::builder_vm_runtime::{
    DEFAULT_BUILDER_STORE_GC_GIB, STAGE0_STORE_GC_KIB_CMDLINE_KEY,
};

/// Where Nix looks for roots; a symlink here pins its target's closure.
pub(super) const GC_ROOTS_DIR: &str = "/nix/var/nix/gcroots";

/// The seed's `.reginfo`, copied out of the root disk before the persistent
/// store is bound over `/nix` and hides it.
#[cfg(target_os = "linux")]
pub(super) const SEED_REGINFO_STASH: &str = "/run/mvm-stage0-seed.reginfo";

/// The collection threshold, in KiB of used space, read off the kernel
/// cmdline. A cmdline without the token — an older host, or a backend whose
/// Stage 0 does not carry it — gets the default that host would have applied
/// to its steady-state store.
pub(super) fn cap_kib(cmdline: &str) -> u64 {
    cmdline
        .split_whitespace()
        .find_map(|token| {
            token
                .strip_prefix(&format!("{STAGE0_STORE_GC_KIB_CMDLINE_KEY}="))?
                .parse::<u64>()
                .ok()
        })
        .filter(|kib| *kib > 0)
        .unwrap_or(u64::from(DEFAULT_BUILDER_STORE_GC_GIB) * 1024 * 1024)
}

/// Whether a store using `used_kib` should be collected.
pub(super) fn over_cap(used_kib: u64, cap_kib: u64) -> bool {
    used_kib > cap_kib
}

/// Used space of a filesystem, in KiB, from its `statvfs` counters.
pub(super) fn used_kib(total_blocks: u64, free_blocks: u64, fragment_size: u64) -> u64 {
    total_blocks
        .saturating_sub(free_blocks)
        .saturating_mul(fragment_size)
        / 1024
}

/// The root pinning the last output of one Stage 0 output mode, so building
/// the kernel does not unroot the image and the reverse.
///
/// `None` for a mode that is not a plain token: it becomes a file name.
pub(super) fn output_root(mode: &str) -> Option<PathBuf> {
    plain_token(mode).then(|| Path::new(GC_ROOTS_DIR).join(format!("mvm-stage0-{mode}")))
}

/// The root pinning one seed component (`nix`, `cacert`).
#[cfg(target_os = "linux")]
pub(super) fn seed_root(component: &str) -> PathBuf {
    Path::new(GC_ROOTS_DIR).join(format!("mvm-stage0-seed-{component}"))
}

/// The top-level store path that contains `path`, e.g.
/// `/nix/store/<hash>-nix-2.34/bin/nix` → `/nix/store/<hash>-nix-2.34`.
pub(super) fn store_path_of(path: &Path) -> Option<PathBuf> {
    let mut components = path.components();
    let prefix = [components.next()?, components.next()?, components.next()?];
    let [
        Component::RootDir,
        Component::Normal(nix),
        Component::Normal(store),
    ] = prefix
    else {
        return None;
    };
    if nix != "nix" || store != "store" {
        return None;
    }
    let Component::Normal(entry) = components.next()? else {
        return None;
    };
    Some(Path::new("/nix/store").join(entry))
}

/// The kernel's `struct fstrim_range`, the argument to [`FITRIM`].
#[repr(C)]
#[derive(Debug, Default)]
pub(super) struct FstrimRange {
    pub start: u64,
    pub len: u64,
    pub minlen: u64,
}

// linux/fs.h: three `__u64`s, in this order.
const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<FstrimRange>() == 24);
    assert!(align_of::<FstrimRange>() == 8);
    assert!(offset_of!(FstrimRange, start) == 0);
    assert!(offset_of!(FstrimRange, len) == 8);
    assert!(offset_of!(FstrimRange, minlen) == 16);
};

impl FstrimRange {
    /// Trim every free block in the filesystem.
    pub(super) fn whole_filesystem() -> Self {
        Self {
            start: 0,
            len: u64::MAX,
            minlen: 0,
        }
    }
}

/// `FITRIM`, which `libc` does not export: `_IOWR('X', 121, struct
/// fstrim_range)`.
pub(super) const FITRIM: u32 = ioctl_read_write(b'X', 121, std::mem::size_of::<FstrimRange>());

/// Linux's `_IOWR` encoding: direction in the top two bits, then the argument
/// size, the type byte, and the number.
const fn ioctl_read_write(kind: u8, number: u8, size: usize) -> u32 {
    const READ_WRITE: u32 = 3;
    (READ_WRITE << 30) | ((size as u32) << 16) | ((kind as u32) << 8) | number as u32
}

fn plain_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Registering, rooting, collecting and trimming, inside the Stage 0 guest.
#[cfg(target_os = "linux")]
pub(super) mod collect {
    use std::path::Path;
    use std::process::{Command, Stdio};

    use crate::linux::{
        NIX_TARGET, STAGE0_NIX_STORE_MARKER, STAGE0_NIX_STORE_MOUNT, is_mountpoint,
    };
    use crate::seed::{find_seed_bin, find_seed_cacert};

    /// Copy the seed's `.reginfo` somewhere that survives the persistent store
    /// being bound over `/nix`. Best-effort: without it Stage 0 still builds,
    /// it just cannot register the seed, so it will not collect garbage.
    pub(crate) fn stash_seed_reginfo() {
        let seed_reginfo = Path::new(NIX_TARGET).join(".reginfo");
        if let Err(e) = std::fs::copy(&seed_reginfo, super::SEED_REGINFO_STASH) {
            eprintln!(
                "stage0-init: no seed registration at {} ({e}); store garbage collection is off for this run",
                seed_reginfo.display()
            );
        }
    }

    /// Root the build output so a collection keeps it and an unchanged next
    /// bootstrap is a cache hit. Best-effort: an unrooted output is only a
    /// colder next run.
    pub(crate) fn root_stage0_output(store_path: &Path, mode: &str) {
        let Some(root) = super::output_root(mode) else {
            return;
        };
        if let Err(e) = replace_symlink(&root, store_path) {
            eprintln!("stage0-init: could not root {}: {e}", store_path.display());
        }
    }

    fn replace_symlink(link: &Path, target: &Path) -> Result<(), String> {
        if let Some(parent) = link.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        match std::fs::remove_file(link) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("remove {}: {e}", link.display())),
        }
        std::os::unix::fs::symlink(target, link)
            .map_err(|e| format!("symlink {} -> {}: {e}", link.display(), target.display()))
    }

    /// Collect the persistent store once it is past the host's cap.
    ///
    /// Never fails Stage 0: the artifacts are already on the output disk, and a
    /// store left large is the state every run before this one left.
    pub(crate) fn collect_stage0_store_garbage() {
        if !is_mountpoint(STAGE0_NIX_STORE_MOUNT) {
            eprintln!("stage0-init: no persistent Nix store mounted; not collecting garbage");
            return;
        }
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        let cap = super::cap_kib(&cmdline);
        let Some(used) = filesystem_used_kib(STAGE0_NIX_STORE_MOUNT) else {
            eprintln!("stage0-init: could not measure the Nix store; not collecting");
            return;
        };
        if !super::over_cap(used, cap) {
            eprintln!("stage0-init: Nix store uses {used} KiB, within the {cap} KiB cap");
            return;
        }
        eprintln!(
            "stage0-init: Nix store uses {used} KiB, past the {cap} KiB cap; collecting garbage"
        );
        if let Err(e) = protect_seed_from_collection() {
            eprintln!("stage0-init: not collecting garbage: {e}");
            return;
        }
        match run_store_gc() {
            Ok(()) => {
                let after = filesystem_used_kib(STAGE0_NIX_STORE_MOUNT).unwrap_or(used);
                eprintln!(
                    "stage0-init: Nix store {used} KiB -> {after} KiB after garbage collection"
                );
            }
            Err(e) => eprintln!("stage0-init: garbage collection failed (continuing): {e}"),
        }
        trim_stage0_store();
        // A store that reuses its marker without a seed would boot with no
        // `nix`. Dropping the marker makes the next run reseed instead.
        if find_seed_bin("nix").is_err() || find_seed_cacert().is_err() {
            eprintln!(
                "stage0-init: the seed did not survive garbage collection; \
                 the next bootstrap reseeds the store"
            );
            let _ = std::fs::remove_file(STAGE0_NIX_STORE_MARKER);
        }
    }

    /// Register the seed's paths and root `nix` and its CA bundle. Nix skips a
    /// root that points at an unregistered path and collects unregistered
    /// paths, so without both steps the collection would take the seed.
    fn protect_seed_from_collection() -> Result<(), String> {
        let reginfo = std::fs::File::open(super::SEED_REGINFO_STASH)
            .map_err(|e| format!("open {}: {e}", super::SEED_REGINFO_STASH))?;
        let nix_store = find_seed_bin("nix-store")?;
        let status = Command::new(&nix_store)
            .arg("--load-db")
            .stdin(Stdio::from(reginfo))
            .status()
            .map_err(|e| format!("run {} --load-db: {e}", nix_store.display()))?;
        if !status.success() {
            return Err(format!(
                "nix-store --load-db exit {}",
                status.code().unwrap_or(-1)
            ));
        }
        for (component, path) in [
            ("nix", find_seed_bin("nix")?),
            ("cacert", find_seed_cacert()?),
        ] {
            let store_path = super::store_path_of(&path)
                .ok_or_else(|| format!("{} is not under /nix/store", path.display()))?;
            replace_symlink(&super::seed_root(component), &store_path)?;
        }
        Ok(())
    }

    /// Tell the store's disk which blocks the collection freed. The host file
    /// only shrinks when the block device honours the discard: a device
    /// without discard answers EOPNOTSUPP, which is expected and not an error.
    fn trim_stage0_store() {
        let path = match std::ffi::CString::new(STAGE0_NIX_STORE_MOUNT) {
            Ok(path) => path,
            Err(_) => return,
        };
        // SAFETY: `path` is NUL-terminated; the descriptor is checked before use
        // and closed on every path out of this block.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        if fd < 0 {
            eprintln!(
                "stage0-init: could not open {STAGE0_NIX_STORE_MOUNT} to trim: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        let mut range = super::FstrimRange::whole_filesystem();
        // SAFETY: `fd` is an open directory on the store filesystem and `range`
        // is a live `struct fstrim_range` the kernel reads and writes back. The
        // request's type is `c_int` on musl and `c_ulong` on glibc; `as _` keeps
        // the same bits for both.
        let result = unsafe {
            let rc = libc::ioctl(fd, super::FITRIM as _, &mut range);
            let error = std::io::Error::last_os_error();
            libc::close(fd);
            if rc == 0 { Ok(()) } else { Err(error) }
        };
        match result {
            Ok(()) => eprintln!(
                "stage0-init: trimmed {} bytes of freed store blocks",
                range.len
            ),
            Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {
                eprintln!(
                    "stage0-init: the store disk does not support discard; freed blocks stay allocated on the host"
                );
            }
            Err(e) => eprintln!("stage0-init: trimming the store failed (continuing): {e}"),
        }
    }

    fn run_store_gc() -> Result<(), String> {
        let nix = find_seed_bin("nix")?;
        let status = Command::new(&nix)
            .args([
                "store",
                "gc",
                "--extra-experimental-features",
                "nix-command",
            ])
            .status()
            .map_err(|e| format!("run nix store gc: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("nix store gc exit {}", status.code().unwrap_or(-1)))
        }
    }

    fn filesystem_used_kib(mount: &str) -> Option<u64> {
        let path = std::ffi::CString::new(mount).ok()?;
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: `path` is NUL-terminated and outlives the call, and `stats`
        // is a correctly sized out-parameter that statvfs initializes whenever
        // it returns 0, which is the only case in which it is read.
        let stats = unsafe {
            if libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) != 0 {
                return None;
            }
            stats.assume_init()
        };
        // Both guest targets (aarch64 and x86_64 musl) use 64-bit counters.
        let (blocks, free, fragment): (u64, u64, u64) =
            (stats.f_blocks, stats.f_bfree, stats.f_frsize);
        Some(super::used_kib(blocks, free, fragment))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_cap_governs_collection() {
        assert_eq!(
            cap_kib("console=ttyS0 mvm.store_gc_kib=1048576 mvm.vsock_egress=1"),
            1_048_576
        );
    }

    #[test]
    fn a_cmdline_from_an_older_host_gets_the_steady_state_default() {
        assert_eq!(cap_kib("console=ttyS0 root=/dev/vda rw"), 25_165_824);
        assert_eq!(cap_kib(""), 25_165_824);
    }

    #[test]
    fn a_zero_or_garbage_cap_does_not_collect_everything() {
        // Zero would collect on every run and throw away the warm cache.
        for bad in ["0", "", "lots", "-5"] {
            assert_eq!(
                cap_kib(&format!("root=/dev/vda mvm.store_gc_kib={bad}")),
                25_165_824,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_token_that_merely_ends_in_the_key_is_not_the_cap() {
        assert_eq!(cap_kib("other.mvm.store_gc_kib=99"), 25_165_824);
    }

    #[test]
    fn only_a_store_past_the_cap_is_collected() {
        assert!(!over_cap(100, 100), "at the cap is not over it");
        assert!(over_cap(101, 100));
        assert!(!over_cap(12 * 1024 * 1024, 24 * 1024 * 1024));
    }

    #[test]
    fn used_space_counts_allocated_blocks_in_kib() {
        assert_eq!(used_kib(1000, 250, 4096), 3000);
        assert_eq!(
            used_kib(10, 20, 4096),
            0,
            "free past total must not underflow"
        );
    }

    #[test]
    fn each_output_mode_has_its_own_root() {
        assert_eq!(
            output_root("kernel"),
            Some(PathBuf::from("/nix/var/nix/gcroots/mvm-stage0-kernel"))
        );
        assert_ne!(output_root("kernel"), output_root("image"));
    }

    #[test]
    fn a_mode_that_is_not_a_plain_token_gets_no_root() {
        for bad in ["", "../escape", "a/b", "sp ace"] {
            assert_eq!(output_root(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_seed_binary_resolves_to_its_whole_store_path() {
        assert_eq!(
            store_path_of(Path::new("/nix/store/abc123-nix-2.34.7/bin/nix")),
            Some(PathBuf::from("/nix/store/abc123-nix-2.34.7"))
        );
        assert_eq!(
            store_path_of(Path::new(
                "/nix/store/def456-nss-cacert-3.101/etc/ssl/certs/ca-bundle.crt"
            )),
            Some(PathBuf::from("/nix/store/def456-nss-cacert-3.101"))
        );
    }

    #[test]
    fn fitrim_matches_the_kernel_uapi() {
        // linux/fs.h: #define FITRIM _IOWR('X', 121, struct fstrim_range)
        assert_eq!(std::mem::size_of::<FstrimRange>(), 24);
        assert_eq!(FITRIM, 0xC018_5879);
    }

    #[test]
    fn a_whole_filesystem_trim_covers_every_block() {
        let range = FstrimRange::whole_filesystem();
        assert_eq!((range.start, range.len, range.minlen), (0, u64::MAX, 0));
    }

    #[test]
    fn a_path_outside_the_store_has_no_store_path() {
        for path in [
            "/bin/sh",
            "/nix/var/nix/db",
            "nix/store/x/bin/nix",
            "/nix/store",
        ] {
            assert_eq!(store_path_of(Path::new(path)), None, "{path}");
        }
    }
}
