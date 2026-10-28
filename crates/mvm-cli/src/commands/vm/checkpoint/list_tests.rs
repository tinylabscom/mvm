use super::{checkpoint_list_json, rm};
use mvm_client::checkpoint::Checkpoints;

#[test]
fn list_json_uses_the_complete_client_catalog_reply_in_id_order() {
    let root = tempfile::tempdir().expect("catalog");
    let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../mvm-core/tests/fixtures/checkpoint-list.json"
    )))
    .expect("shared metadata fixture");
    for record in fixture.as_array().expect("records").iter().rev() {
        let directory = root.path().join(record["id"].as_str().expect("id"));
        std::fs::create_dir(&directory).expect("checkpoint directory");
        std::fs::write(
            directory.join("meta.json"),
            serde_json::to_vec(record).expect("metadata JSON"),
        )
        .expect("persist metadata");
    }
    let client = Checkpoints::at(root.path());
    let printed = checkpoint_list_json(&client).expect("CLI JSON");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&printed).expect("parse CLI JSON"),
        fixture
    );
    assert_eq!(
        printed,
        crate::json_out::to_json_string(&client.list().expect("client list")).expect("client JSON")
    );
}

#[test]
fn list_json_propagates_catalog_refusal_instead_of_reporting_empty_success() {
    let root = tempfile::tempdir().expect("catalog");
    let client = Checkpoints::at(root.path());
    assert_eq!(checkpoint_list_json(&client).expect("empty catalog"), "[]");
    std::fs::create_dir(root.path().join("broken")).expect("checkpoint");
    std::fs::write(root.path().join("broken/meta.json"), b"{").expect("malformed metadata");
    assert!(checkpoint_list_json(&client).is_err());
}

#[test]
fn removal_refuses_existing_unreadable_metadata_without_deleting_the_checkpoint() {
    let home = tempfile::tempdir().expect("home");
    let outside = tempfile::tempdir().expect("outside catalog");
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let root = mvm_core::config::checkpoints_dir();
    for id in ["missing-meta", "malformed", "oversized", "symlink"] {
        let directory = root.join(id);
        std::fs::create_dir_all(&directory).expect("checkpoint");
        let path = directory.join("meta.json");
        let record = mvm_core::checkpoint::CheckpointMeta::builder(
            mvm_core::checkpoint::CheckpointId::new(id),
            mvm_core::checkpoint::CheckpointClass::FsQuick,
            "fixture",
        )
        .build();
        match id {
            "missing-meta" => {}
            "malformed" => std::fs::write(&path, b"{").expect("malformed metadata"),
            "oversized" => {
                let mut bytes = serde_json::to_vec(&record).expect("valid metadata");
                bytes.resize(4 * 1024 * 1024 + 1, b' ');
                std::fs::write(&path, bytes).expect("oversized valid JSON");
            }
            "symlink" => {
                let target = outside.path().join("meta.json");
                std::fs::write(&target, serde_json::to_vec(&record).expect("metadata"))
                    .expect("outside metadata");
                std::os::unix::fs::symlink(&target, &path).expect("metadata symlink");
            }
            _ => unreachable!("closed test cases"),
        }
        let result = rm(id, true);
        assert!(directory.is_dir(), "refusal must preserve {id}");
        assert!(
            result.is_err(),
            "unreadable {id} must not report successful removal"
        );
    }
    assert!(outside.path().join("meta.json").is_file());
}

#[test]
fn removal_of_an_absent_checkpoint_remains_idempotent() {
    let home = tempfile::tempdir().expect("home");
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    rm("absent", true).expect("missing catalog is already removed");
    let incomplete = mvm_core::config::checkpoints_dir().join("incomplete");
    std::fs::create_dir_all(&incomplete).expect("incomplete checkpoint");
    rm("absent", true).expect("missing checkpoint is already removed");
    assert!(rm("incomplete", true).is_err());
    assert!(
        incomplete.is_dir(),
        "missing metadata is not a missing checkpoint"
    );
}
