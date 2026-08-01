use std::path::Path;

fn workflow() -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/merge-queue-requeue.yml"),
    )
    .expect("merge-queue requeue workflow must be readable")
}

#[test]
fn privileged_requeue_workflow_never_executes_pull_request_code() {
    let source = workflow();

    assert!(source.contains("pull_request_target:\n    types: [dequeued]"));
    assert!(source.contains("contents: read\n  pull-requests: write"));
    assert!(!source.contains("actions/checkout"));
    assert!(!source.contains("github.event.pull_request.head"));
    assert!(!source.contains("github.head_ref"));
}

#[test]
fn retries_are_bounded_counted_and_conflict_aware() {
    let source = workflow();

    assert!(source.contains("MAX_ATTEMPTS: \"2\""));
    assert!(source.contains("mergeable_state"));
    assert!(source.contains("--remove-label auto-requeued"));
    assert!(source.contains("--add-label auto-requeued"));
    assert!(source.contains("gh pr merge \"${PR}\" --repo \"${REPO}\" --auto"));
}
