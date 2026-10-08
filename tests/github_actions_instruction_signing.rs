//! Structure checks for the instruction-file signing workflow and the
//! composite action other repositories call.

const WORKFLOW: &str = include_str!("../.github/workflows/sign-instructions.yml");
const ACTION: &str = include_str!("../.github/actions/sign-instructions/action.yml");

/// A called workflow signs under the called file's identity whoever called
/// it. This repository is public, so a `workflow_call` trigger would let any
/// repository mint signatures that the publisher entry trusting this
/// repository's instruction files accepts.
#[test]
fn the_signing_workflow_cannot_be_called_from_another_repository() {
    let triggers = WORKFLOW
        .split("\non:\n")
        .nth(1)
        .and_then(|rest| rest.split("\npermissions:\n").next())
        .expect("sign-instructions.yml declares its triggers before its permissions");
    assert!(triggers.contains("workflow_dispatch:"));
    assert!(
        !triggers.contains("workflow_call"),
        "sign-instructions.yml must not be a reusable workflow"
    );
}

/// The job publishes bundles as an artifact for a separately reviewed bundle
/// pull request and never writes to the repository itself.
#[test]
fn the_signing_workflow_holds_no_write_access() {
    let permissions = WORKFLOW
        .split("\npermissions:\n")
        .nth(1)
        .and_then(|rest| rest.split("\n\n").next())
        .expect("sign-instructions.yml declares workflow permissions");
    let granted: Vec<&str> = permissions.lines().map(str::trim).collect();
    assert_eq!(granted, ["contents: read", "id-token: write"]);
    assert_eq!(
        WORKFLOW.matches(": write").count(),
        1,
        "id-token is the only permission the signing workflow may write"
    );
}

/// This repository signs through the same action other repositories call,
/// so the documented caller runs code this workflow exercises.
#[test]
fn the_signing_workflow_runs_the_shared_action() {
    assert!(WORKFLOW.contains("uses: ./.github/actions/sign-instructions"));
    assert!(
        !WORKFLOW.contains("cosign sign-blob"),
        "signing steps belong in the composite action, not inline"
    );
    assert!(ACTION.contains("using: composite"));
}

/// This composite runs with an OIDC token, so every external action it loads
/// is executable signing-job code and must be pinned to an immutable commit.
#[test]
fn the_signing_action_pins_every_external_action_to_a_full_sha() {
    for line in ACTION.lines().map(str::trim) {
        let Some(target) = line.strip_prefix("uses: ") else {
            continue;
        };
        if target.starts_with("./") {
            continue;
        }
        let (action, reference) = target
            .split_once('@')
            .unwrap_or_else(|| panic!("external action is missing a ref: {target}"));
        let reference = reference
            .split_whitespace()
            .next()
            .expect("action ref precedes its version comment");
        assert!(
            reference.len() == 40 && reference.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "{action} must use an immutable full commit SHA, found {reference}"
        );
    }
}

/// Bundles for `.claude/**` and `.cursor/rules/**` sit under dot-directories,
/// which upload-artifact silently drops by default.
#[test]
fn the_uploaded_artifact_keeps_bundles_under_hidden_directories() {
    let upload = ACTION
        .split("uses: actions/upload-artifact@")
        .nth(1)
        .expect("the action uploads the bundles");
    assert!(
        upload.contains("include-hidden-files: true"),
        "the bundle upload must include hidden paths"
    );
}

/// The verification policy pins the calling workflow's own identity, which is
/// what the certificate of a composite action's signature carries.
#[test]
fn the_action_verifies_under_the_calling_workflow() {
    let verify = ACTION
        .split("- name: Verify the bundles under the calling workflow's identity")
        .nth(1)
        .expect("the action verifies what it signed");
    for needle in [
        "GITHUB_WORKFLOW_REF",
        "repository = \"${GITHUB_REPOSITORY}\"",
        "workflow = \"${workflow}\"",
        "ref = \"${GITHUB_REF}\"",
        "trust instructions verify",
    ] {
        assert!(verify.contains(needle), "verify step must use {needle}");
    }
}
