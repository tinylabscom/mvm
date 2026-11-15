//! The factory-edge demo through the library, the same steps as
//! `scripts/factory-edge-demo.sh`.
//!
//! Three small workloads start at the same time, each allowed one destination.
//! The maintenance workload asks for a destination it was not given; the host
//! refuses it, records that, and the other two carry on.
//!
//! Needs a prepared home (see `scripts/factory-edge-demo.md`):
//!
//! ```sh
//! MVM_HOME=$HOME/.mvm-demo cargo run -p mvm-client --example factory_edge
//! ```

use std::time::{Duration, Instant};

use mvm_client::{LaunchRequest, LifecycleMode, LocalBackend, RootfsSource, explain, inventory};

const IMAGE: &str = "curlimages/curl:8.21.0";

/// A workload that asks for `host` every couple of seconds.
fn requests_for(host: &str) -> Vec<String> {
    let script =
        format!("while true; do curl -sS -m 10 -o /dev/null https://{host}/; sleep 2; done");
    vec!["sh".into(), "-c".into(), script]
}

fn request(name: &str, allowed: &str, asks_for: &str) -> mvm_client::Result<LaunchRequest> {
    let image: RootfsSource = IMAGE.parse().expect("an OCI reference");
    LaunchRequest::builder(LifecycleMode::Persistent, image)
        .name(name)
        .command(requests_for(asks_for))
        .allow_egress(allowed, 443)
        .build()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() % 100_000);
    let (a, b, m) = (
        format!("line-a-{id}"),
        format!("line-b-{id}"),
        format!("maintenance-{id}"),
    );
    let backend = LocalBackend::new();

    println!("Starting three workloads at once, each allowed one destination");
    let started = Instant::now();
    let (ra, rb, rm) = tokio::join!(
        backend.launch(request(&a, "pypi.org", "pypi.org")?),
        backend.launch(request(
            &b,
            "files.pythonhosted.org",
            "files.pythonhosted.org"
        )?),
        // The maintenance workload is allowed api.github.com and asks for example.com.
        backend.launch(request(&m, "api.github.com", "example.com")?),
    );
    let launched = [ra?, rb?, rm?];
    println!(
        "all three launched in {:.1} s",
        started.elapsed().as_secs_f32()
    );

    println!("\n== 1. All three are running");
    for record in inventory::list_local_inventory(&backend).await? {
        if launched.iter().any(|l| l.machine.name == record.name) {
            println!("{:<24} {:?}", record.name, record.status);
        }
    }

    println!("\n== 2. The maintenance workload asks for example.com, which it was not given");
    let deadline = Instant::now() + Duration::from_secs(40);
    let denied = loop {
        let run = explain::explain_local_run("local", &m)?;
        if !run.egress_denials.is_empty() || Instant::now() > deadline {
            break run;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    for d in &denied.egress_denials {
        println!("refused: {} x{} ({})", d.destination, d.count, d.reason);
    }
    println!("audit chain verified: {}", denied.chain_verified);

    println!("\n== 3. The inspection workloads are unaffected");
    for name in [&a, &b] {
        let run = explain::explain_local_run("local", name)?;
        println!(
            "{name}: {} refusals, chain verified: {}",
            run.egress_denials.len(),
            run.chain_verified
        );
    }
    println!("\nRemove them with: scripts/factory-edge-demo.sh --down");
    Ok(())
}
