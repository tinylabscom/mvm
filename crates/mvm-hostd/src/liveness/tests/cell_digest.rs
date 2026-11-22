//! The periodic cell digest and the timer it shares with the liveness watch.

use std::time::Duration as StdDuration;

use sha2::{Digest as _, Sha256};

use super::*;
use crate::state_cells::digest::{CELL_DIGEST_PERIOD, CellDigest, STATE_CELL_DIGEST_EVENT};
use crate::supervisor::lifecycle::liveness_expiry::UnitTimer;

const VALUE: &[u8] = b"open-valve-7";

fn digest(host: &Host, unit: &str) -> CellDigest {
    let signer = crate::audit::host_keypair::load_or_init_at(&keys_dir(host.home.path())).unwrap();
    CellDigest {
        tenant: tenant(),
        unit: id(unit),
        host_signer_keys_dir: None,
        emitter: Arc::new(
            AuditEmitter::with_dir(signer.signing, &host.home.path().join("audit")).unwrap(),
        ),
        period: CELL_DIGEST_PERIOD,
    }
}

fn write(host: &Host, unit: &str, cell: &str, version: u64, value: &[u8]) -> Result<()> {
    let (t, u) = (tenant(), id(unit));
    StateCells {
        host_signer_keys_dir: None,
        audit: &host.emitter,
    }
    .write(
        &CellCaller {
            tenant: &t,
            unit: &u,
            epoch: epoch(1),
            cell,
        },
        version,
        value,
    )
}

/// `(cell, version, previous_version)` of every digest entry, in chain order.
fn digests(host: &Host) -> Vec<(String, String, String)> {
    host.events(STATE_CELL_DIGEST_EVENT)
        .iter()
        .map(|e| {
            let l = &e["labels"];
            (
                l["cell"].as_str().unwrap().to_string(),
                l["version"].as_str().unwrap().to_string(),
                l["previous_version"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn entry(cell: &str, version: u64, previous: u64) -> (String, String, String) {
    (cell.to_string(), version.to_string(), previous.to_string())
}

fn chain_text(host: &Host) -> String {
    std::fs::read_to_string(
        host.home
            .path()
            .join("audit")
            .join(format!("{TENANT}.jsonl")),
    )
    .unwrap_or_default()
}

/// [`topology`] with a second cell, `trim`, written by `reader`.
fn two_writers(generation: u64) -> Topology {
    let mut t = topology(generation, PERIOD_MS);
    let mut trim = t.cells[0].clone();
    trim.name = "trim".to_string();
    trim.writer = id("reader");
    t.cells.push(trim);
    t
}

#[test]
fn a_changed_cell_is_digested_once_per_period_and_an_unchanged_one_not_at_all() {
    let host = Host::admitted();
    let monotonic = Arc::new(TestMonotonic::default());
    let timer = UnitTimer {
        liveness: None,
        digest: Some(digest(&host, "controller")),
        monotonic: monotonic.clone(),
    };
    let mut pauses = Vec::new();
    timer.run(|pause| {
        pauses.push(pause);
        monotonic.advance(pause);
        match pauses.len() {
            // Two writes within one period are one entry.
            1 => {
                write(&host, "controller", "setpoint", 1, b"a").unwrap();
                write(&host, "controller", "setpoint", 2, VALUE).unwrap();
            }
            3 => write(&host, "controller", "setpoint", 3, b"b").unwrap(),
            _ => {}
        }
        pauses.len() < 4
    });
    assert_eq!(pauses, vec![CELL_DIGEST_PERIOD; 4]);
    assert_eq!(
        digests(&host),
        vec![entry("setpoint", 2, 0), entry("setpoint", 3, 2)],
        "nothing for the start (never written) or the idle period"
    );
    let first = &host.events(STATE_CELL_DIGEST_EVENT)[0]["labels"];
    assert_eq!(first["value_sha256"], hex::encode(Sha256::digest(VALUE)));
    assert_eq!(
        first["cell_sha256"],
        hex::encode(Sha256::digest("setpoint"))
    );
    assert_eq!(first["unit"], "controller");
    assert!(
        !chain_text(&host).contains(std::str::from_utf8(VALUE).unwrap()),
        "the value never reaches the chain"
    );
}

#[test]
fn a_restarted_owner_neither_repeats_nor_loses_a_change() {
    let host = Host::admitted();
    write(&host, "controller", "setpoint", 1, b"a").unwrap();
    assert_eq!(digest(&host, "controller").pass().unwrap(), 1);
    // Restarted: a new owner with no memory of the last pass.
    assert_eq!(digest(&host, "controller").pass().unwrap(), 0);
    write(&host, "controller", "setpoint", 5, b"b").unwrap();
    assert_eq!(digest(&host, "controller").pass().unwrap(), 1);
    assert_eq!(
        digests(&host),
        vec![entry("setpoint", 1, 0), entry("setpoint", 5, 1)]
    );
}

#[test]
fn each_owner_digests_only_the_cells_its_unit_writes_and_the_chain_verifies() {
    let host = Host::admitted();
    host.admit(&two_writers(2), BackendKind::Mock).unwrap();
    write(&host, "controller", "setpoint", 1, b"a").unwrap();
    write(&host, "reader", "trim", 1, b"b").unwrap();
    // Another writer on the same chain between the digests: a refusal.
    write(&host, "reader", "setpoint", 2, b"c").unwrap_err();

    assert_eq!(digest(&host, "controller").pass().unwrap(), 1);
    assert_eq!(digests(&host), vec![entry("setpoint", 1, 0)]);
    assert_eq!(digest(&host, "reader").pass().unwrap(), 1);
    assert_eq!(
        digests(&host),
        vec![entry("setpoint", 1, 0), entry("trim", 1, 0)]
    );
    // And an expiry after them.
    host.signal("controller", 1).unwrap();
    host.clock.advance_ms(i64::from(PERIOD_MS));
    assert_eq!(host.expire().len(), 1);

    let chain = host
        .home
        .path()
        .join("audit")
        .join(format!("{TENANT}.jsonl"));
    let verifying = crate::audit::host_keypair::load_or_init_at(&keys_dir(host.home.path()))
        .unwrap()
        .signing
        .verifying_key();
    let entries = crate::audit::audit_file::verify_audit_chain(&chain, &verifying).unwrap();
    assert!(entries >= 4, "{entries}");
    assert!(
        !host
            .events(crate::state_cells::STATE_CELL_REFUSED_EVENT)
            .is_empty()
    );
}

#[test]
fn a_removed_cell_takes_its_marker_and_returns_empty() {
    let host = Host::admitted();
    write(&host, "controller", "setpoint", 3, b"a").unwrap();
    assert_eq!(digest(&host, "controller").pass().unwrap(), 1);
    let mut bare = topology(2, PERIOD_MS);
    bare.cells.clear();
    host.admit(&bare, BackendKind::Mock).unwrap();
    let dir = mvm_core::config::state_cells_dir_at(host.home.path()).join(TENANT);
    let marker = dir.join(format!(
        "{}.digest",
        hex::encode(Sha256::digest("setpoint"))
    ));
    assert!(!marker.exists());

    // Declared again, it starts at version 0 and its first change is
    // digested even at a version seen before.
    host.admit(&topology(3, PERIOD_MS), BackendKind::Mock)
        .unwrap();
    write(&host, "controller", "setpoint", 3, b"z").unwrap();
    assert_eq!(digest(&host, "controller").pass().unwrap(), 1);
    assert_eq!(
        digests(&host),
        vec![entry("setpoint", 3, 0), entry("setpoint", 3, 0)]
    );
}

#[test]
fn the_digest_and_the_deadline_share_one_wait() {
    let host = Host::admitted();
    host.signal("controller", 1).unwrap();
    let signer = crate::audit::host_keypair::load_or_init_at(&keys_dir(host.home.path())).unwrap();
    let monotonic = Arc::new(TestMonotonic::default());
    let timer = UnitTimer {
        liveness: Some(
            crate::supervisor::lifecycle::liveness_expiry::LivenessWatch {
                tenant: tenant(),
                unit: id("controller"),
                epoch: epoch(1),
                period: StdDuration::from_millis(u64::from(PERIOD_MS)),
                host_signer_keys_dir: None,
                emitter: Arc::new(
                    AuditEmitter::with_dir(signer.signing, &host.home.path().join("audit"))
                        .unwrap(),
                ),
                clock: host.clock.clone(),
                authority: Box::new(host.store()),
            },
        ),
        digest: Some(digest(&host, "controller")),
        monotonic: monotonic.clone(),
    };
    let mut pauses = Vec::new();
    timer.run(|pause| {
        pauses.push(pause);
        monotonic.advance(pause);
        host.clock
            .advance_ms(i64::try_from(pause.as_millis()).unwrap());
        pauses.len() < 3
    });
    // The deadline comes first; once it has fenced, only the digest is left.
    assert_eq!(
        pauses,
        vec![
            StdDuration::from_millis(u64::from(PERIOD_MS)),
            CELL_DIGEST_PERIOD - StdDuration::from_millis(u64::from(PERIOD_MS)),
            CELL_DIGEST_PERIOD,
        ]
    );
    assert_eq!(host.events(LIVENESS_EPOCH_REPLACED_EVENT).len(), 1);
}
