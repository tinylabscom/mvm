//! Throwaway: drive a real `RunEntrypoint` against a running function
//! workload microVM by name — the in-VM acceptance `mvmctl invoke` covers
//! but which needs the template lifecycle. Mirrors `dispatch_inner` in
//! `commands/vm/invoke.rs`: connect, `send_run_entrypoint`, collect stdout.
//!
//! The wrapper reads stdin as JSON `[args, kwargs]`; for `greet(name)` we
//! send `[["<name>"], {}]` and expect the JSON-encoded return `"hello <name>"`.
//!
//!   cargo run -p mvm-cli --example agent_invoke -- <vm-name> [name]

use std::cell::RefCell;

fn main() -> anyhow::Result<()> {
    let vm = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: agent_invoke <vm-name> [name]"))?;
    let name = std::env::args().nth(2).unwrap_or_else(|| "ari".to_string());

    // [args, kwargs] = [["<name>"], {}]. `{name:?}` quotes+escapes the
    // string into valid JSON for ordinary names.
    let payload = format!("[[{name:?}], {{}}]").into_bytes();

    let transport = mvm::vsock_transport::for_vm(&vm)?;
    let mut stream = transport.connect(mvm_guest::vsock::GUEST_AGENT_PORT)?;

    let stdout = RefCell::new(Vec::<u8>::new());
    let stderr = RefCell::new(Vec::<u8>::new());
    let terminal =
        mvm_guest::vsock::send_run_entrypoint(&mut stream, payload, 30, Vec::new(), |event| {
            match event {
                mvm_guest::vsock::EntrypointEvent::Stdout { chunk } => {
                    stdout.borrow_mut().extend_from_slice(chunk)
                }
                mvm_guest::vsock::EntrypointEvent::Stderr { chunk } => {
                    stderr.borrow_mut().extend_from_slice(chunk)
                }
                _ => {}
            }
        })?;

    println!("STDOUT: {}", String::from_utf8_lossy(&stdout.borrow()));
    let err = stderr.borrow();
    if !err.is_empty() {
        println!("STDERR: {}", String::from_utf8_lossy(&err));
    }
    println!("TERMINAL: {terminal:?}");
    Ok(())
}
