//! Runtime integration test for the TPM2 attestation provider.
//!
//! This test starts a local software TPM (`swtpm`) and exercises the real
//! `tss-esapi` quote path through `Tpm2Provider::measure()`. It is gated to
//! Linux + `attestation-tpm2` because that is the only configuration that
//! links `tss-esapi`.

#![cfg(all(target_os = "linux", feature = "attestation-tpm2"))]

use mvm_core::crypto::attestation::provider::{
    HwAttestationProvider, HwProviderKind, Tpm2Provider,
};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tempfile::TempDir;

struct SwtpmGuard {
    child: Child,
}

impl Drop for SwtpmGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn find_swtpm() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("swtpm"))
            .find(|candidate| candidate.is_file())
    })
}

/// Return a TCP port that is currently free. We still race with other
/// processes, but this is enough for a sandboxed Nix build.
fn free_local_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn wait_for_tcp(port: u16, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("swtpm did not accept TCP connections in time");
}

#[test]
fn tpm2_quote_against_swtpm() {
    let swtpm_bin = match find_swtpm() {
        Some(p) => p,
        None => {
            eprintln!("swtpm not found in PATH; skipping runtime TPM2 test");
            return;
        }
    };

    let tmp = TempDir::new().expect("create temp directory");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&state_dir).expect("create swtpm state directory");

    let command_port = free_local_port();
    let control_port = command_port + 1;

    let child = Command::new(&swtpm_bin)
        .arg("socket")
        .arg("--tpm2")
        .arg("--server")
        .arg(format!("type=tcp,port={command_port}"))
        .arg("--ctrl")
        .arg(format!("type=tcp,port={control_port}"))
        .arg("--flags")
        .arg("not-need-init")
        .arg("--tpmstate")
        .arg(format!("dir={}", state_dir.display()))
        .spawn()
        .expect("spawn swtpm");

    let _guard = SwtpmGuard { child };

    wait_for_tcp(command_port, Duration::from_secs(10));

    // SAFETY: this is a single-threaded test and no TPM context exists yet,
    // so mutating the process environment before the first call is safe.
    let tcti = format!("swtpm:host=127.0.0.1,port={command_port}");
    unsafe {
        std::env::set_var("TCTI", &tcti);
        std::env::set_var("TPM2TOOLS_TCTI", &tcti);
    }

    let measurement = Tpm2Provider
        .measure()
        .expect("TPM2 measurement should succeed against swtpm");

    assert_eq!(measurement.provider, HwProviderKind::Tpm2);

    let envelope_bytes = hex::decode(&measurement.measurement_hex).expect("valid hex payload");
    let envelope: serde_json::Value =
        serde_json::from_slice(&envelope_bytes).expect("valid JSON envelope");

    assert_eq!(envelope.get("version").and_then(|v| v.as_u64()), Some(1));
    assert!(
        envelope.get("quote_b64").and_then(|v| v.as_str()).is_some(),
        "quote_b64 missing"
    );
    assert!(
        envelope
            .get("signature_b64")
            .and_then(|v| v.as_str())
            .is_some(),
        "signature_b64 missing"
    );
    assert!(
        envelope
            .get("ak_public_b64")
            .and_then(|v| v.as_str())
            .is_some(),
        "ak_public_b64 missing"
    );

    let pcrs = envelope
        .get("pcrs")
        .and_then(|v| v.as_array())
        .expect("pcrs array");
    assert_eq!(pcrs.len(), 8, "expected PCRs 0-7");
}
