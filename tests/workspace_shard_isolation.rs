use std::fs;

#[test]
fn workspace_shards_keep_mutable_state_per_worker_run() {
    let worker = fs::read_to_string(".github/workflows/workspace-shard.yml")
        .expect("read workspace shard workflow");

    assert!(
        worker.contains(
            "base=\"$RUNNER_TEMP/mvm-workspace-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${SHARD}\""
        ),
        "the persistent runner must not reuse another job's mutable state"
    );
    assert!(worker.contains("chmod 700 \"$base\" \"$base/tmp\""));
    assert!(worker.contains("CARGO_HOME=%s\\nRUSTUP_HOME=%s\\n"));
    assert!(worker.contains("HOME=%s\\nMVM_HOME=%s\\nTMPDIR=%s\\n"));
    assert!(worker.contains(">> \"$GITHUB_ENV\""));
    assert!(worker.contains("if: always()"));
    assert!(worker.contains("[ ! -L \"$base\" ]"));
    assert!(worker.contains("rm -rf -- \"$base\""));
}
