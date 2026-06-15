//! mvm-egress-proxy — Linux-only binary that fronts the builder
//! VM's application-deps install with an HTTP CONNECT proxy.
//!
//! The binary:
//!
//! 1. Builds an `Allowlist` (production hostnames by default;
//!    `MVM_EGRESS_ALLOWLIST` env-var override gated behind the
//!    `dev-shell` Cargo feature for tests).
//! 2. Binds the proxy at `DEFAULT_BIND` (or
//!    `MVM_EGRESS_BIND` if set — gated the same way for tests).
//! 3. Prints `mvm-egress-proxy: listening on <addr>` to stdout so
//!    the parent (mvm-host-vm-init) can scrape the addr if it
//!    needs to confirm.
//! 4. Waits for SIGTERM / SIGINT.
//!
//! On non-Linux hosts the binary still compiles (for workspace
//! ergonomics) but prints a hint + exits 1. The production caller
//! cross-compiles for `<arch>-unknown-linux-musl` from the
//! builder VM flake (`nix/images/builder-vm/flake.nix`).

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "mvm-egress-proxy is Linux-only (in-VM egress allowlist proxy \
             for the libkrun builder VM). On a developer host this binary \
             is a no-op; the production binary is cross-compiled to \
             <arch>-unknown-linux-musl via nix/images/builder-vm/flake.nix. \
             See specs/plans/73-sdk-port-followups.md §B.2.x."
        );
        ExitCode::FAILURE
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::process::ExitCode;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use mvm_build::egress_proxy::Allowlist;
    use mvm_build::egress_proxy::{DEFAULT_BIND, start};

    pub fn run() -> ExitCode {
        let allowlist = build_allowlist();
        let bind_addr = resolve_bind_addr();

        let handle = match start(&bind_addr, allowlist) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("mvm-egress-proxy: failed to bind {bind_addr}: {e}");
                return ExitCode::FAILURE;
            }
        };
        println!("mvm-egress-proxy: listening on {}", handle.local_addr);

        // Park until SIGTERM / SIGINT. mvm-host-vm-init signals
        // SIGTERM after the installer exits; we shut the listener
        // down cleanly and join the accept thread before exiting.
        let stop = Arc::new(AtomicBool::new(false));
        install_signal_handlers(Arc::clone(&stop));
        while !stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
        }

        eprintln!("mvm-egress-proxy: shutting down");
        // Drop runs ProxyHandle::shutdown which joins the accept
        // thread. Explicit for readability.
        drop(handle);
        ExitCode::SUCCESS
    }

    /// Resolve the allowlist. Production: the hard-coded
    /// hostnames. Dev-shell feature: optional
    /// `MVM_EGRESS_ALLOWLIST=host1,host2,host3` override + optional
    /// `MVM_EGRESS_ALLOWLIST_PORT=443` override.
    fn build_allowlist() -> Allowlist {
        #[cfg(feature = "dev-shell")]
        {
            if let Ok(raw) = std::env::var("MVM_EGRESS_ALLOWLIST") {
                let hosts: Vec<String> = raw
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                let port = std::env::var("MVM_EGRESS_ALLOWLIST_PORT")
                    .ok()
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(mvm_build::egress_proxy::ALLOWED_PORT);
                eprintln!(
                    "mvm-egress-proxy: dev-shell feature on — allowlist override `{raw}` :{port}"
                );
                return Allowlist::from_parts(hosts, port);
            }
        }
        Allowlist::production()
    }

    fn resolve_bind_addr() -> String {
        #[cfg(feature = "dev-shell")]
        {
            if let Ok(b) = std::env::var("MVM_EGRESS_BIND") {
                return b;
            }
        }
        DEFAULT_BIND.to_string()
    }

    /// Install SIGINT + SIGTERM handlers that flip `stop` so the
    /// main loop exits. Best-effort: if `signal_hook`-style setup
    /// fails we fall back to a no-op handler — the proxy then
    /// only exits on kill -9, which mvm-host-vm-init does as the
    /// SIGTERM fallback anyway.
    fn install_signal_handlers(stop: Arc<AtomicBool>) {
        // SAFETY: setting a signal handler is unsafe because the
        // handler runs in async-signal context; we only flip an
        // atomic, which is async-signal-safe.
        unsafe {
            libc_sigaction(libc::SIGTERM, &stop);
            libc_sigaction(libc::SIGINT, &stop);
        }
    }

    /// Bridge to libc::sigaction with a context-carrying handler.
    /// Stored as a static so the C-callable handler can find it.
    static STOP_FLAG: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

    extern "C" fn signal_handler(_sig: libc::c_int) {
        if let Some(flag) = STOP_FLAG.get() {
            flag.store(true, Ordering::SeqCst);
        }
    }

    /// # Safety
    ///
    /// Caller must ensure `stop` outlives the process or the
    /// handler is replaced before drop. We satisfy this by storing
    /// the Arc in a static OnceLock.
    unsafe fn libc_sigaction(sig: libc::c_int, stop: &Arc<AtomicBool>) {
        let _ = STOP_FLAG.set(Arc::clone(stop));
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        // Two-step cast (fn item → `*const ()` → `usize`) keeps rustc
        // happy under `function-casts-as-integer` (warn-by-default in
        // recent nightlies, hard error under workspace `-D warnings`).
        sa.sa_sigaction = signal_handler as *const () as usize;
        unsafe { libc::sigaction(sig, &sa, std::ptr::null_mut()) };
    }
}

#[cfg(all(target_os = "linux", test))]
mod tests {
    // The library tests in `proxy.rs` cover the proxy lifecycle
    // end-to-end. The binary's `main()` is a thin wrapper around
    // `crate::proxy::start` + a signal-driven park loop; the
    // signal path is exercised by mvm-host-vm-init's integration
    // test (`install::tests::proxy_lifecycle_wraps_installer`).
    // No standalone binary test fixture lives here.
}
