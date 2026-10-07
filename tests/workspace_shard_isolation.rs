use std::fs;

#[test]
fn workspace_shards_keep_mutable_state_per_worker_run() {
    let worker = fs::read_to_string(".github/workflows/workspace-shard.yml")
        .expect("read workspace shard workflow");

    assert!(
        worker.contains("base=\"/tmp/mvm-w-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${SHARD}\""),
        "the persistent runner must not reuse another job's mutable state"
    );
    assert!(worker.contains("mkdir -m 700 -- \"$base\""));
    assert!(worker.contains("mkdir -m 700 -- \"$base/home\" \"$base/mvm\" \"$base/tmp\""));
    assert!(worker.contains("CARGO_HOME=%s\\nRUSTUP_HOME=%s\\n"));
    assert!(worker.contains("\"$base/home\" \"$base/mvm\" \"$base/tmp\""));
    assert!(worker.contains(">> \"$GITHUB_ENV\""));
    assert!(worker.contains("if: always()"));
    assert!(worker.contains("[ ! -L \"$base\" ]"));
    assert!(worker.contains("chmod -R u+rwX -- \"$base\""));
    assert!(worker.contains("rm -rf -- \"$base\""));
}
