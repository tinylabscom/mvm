use cucumber::{given, then, when};
use mvm_conformance::IsolatedHome;

use crate::world::CliWorld;

#[path = "../support/pack_build_fixture.rs"]
pub(super) mod fixture;

#[given("a local pack build fixture")]
fn local_pack_build_fixture(world: &mut CliWorld) {
    let dir = tempfile::tempdir().expect("create isolated pack fixture");
    fixture::stage(dir.path());
    world.sealed_bundle = Some(dir);
    world.isolated_home = Some(tempfile::tempdir().expect("create isolated pack build home"));
}

#[when(expr = "I run mvmctl against the pack fixture with {string}")]
fn run_pack_fixture(world: &mut CliWorld, args: String) {
    run(world, &args, false);
}

#[when(expr = "I run mvmctl against the live pack fixture with {string}")]
fn run_live_pack_fixture(world: &mut CliWorld, args: String) {
    run(world, &args, true);
}

#[when("the pack fixture source changes after locking")]
fn change_locked_source(world: &mut CliWorld) {
    let dir = world
        .sealed_bundle
        .as_ref()
        .expect("pack fixture is staged");
    std::fs::write(dir.path().join("app/hello.txt"), b"changed after locking\n")
        .expect("change the locked source");
}

#[then("the pack fixture has no archive or build progress")]
fn no_archive_or_build_progress(world: &mut CliWorld) {
    let dir = world
        .sealed_bundle
        .as_ref()
        .expect("pack fixture is staged");
    assert!(!dir.path().join("build.mvmpkg").exists());
    let output = world.last_run.as_ref().expect("pack build ran");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("Built pack "), "{stdout}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("in the builder VM"), "{stderr}");
    assert!(!stderr.contains("health check:"), "{stderr}");
}

fn run(world: &mut CliWorld, args: &str, live: bool) {
    let arguments = mvm_conformance::doc_examples::tokenize(args);
    let home = world
        .isolated_home
        .as_ref()
        .expect("pack fixture creates its home")
        .path();
    let dir = world
        .sealed_bundle
        .as_ref()
        .expect("pack fixture is staged")
        .path();
    let selected = fixture::producer_binary(
        &arguments,
        live,
        std::env::var_os("MVM_E2E_PRODUCER_MVMCTL"),
    );
    let mut command = match &selected {
        Some(path) => super::cli::command_for_binary(std::path::Path::new(&path)),
        None => super::cli::mvmctl_command(),
    };
    if live {
        super::live_home::prepare_live_home(home);
        super::live_home::use_seeded_runtime(&mut command);
        mvm_conformance::vmm_reaper::register_launched_home(home);
        world.last_live_home = Some(home.to_path_buf());
        if let Some(path) = &selected
            && let Some(refused) =
                super::cli::apply_producer_revocations(std::path::Path::new(path), dir, home)
        {
            world.last_run = Some(refused);
            return;
        }
    }
    world.last_run = Some(
        command
            .current_dir(dir)
            .isolated_home(home)
            .args(arguments)
            .output()
            .expect("spawn mvmctl against the pack fixture"),
    );
}

#[then("the pack build reports a signed archive")]
fn pack_build_reports_signed_archive(world: &mut CliWorld) {
    let output = world.last_run.as_ref().expect("pack build ran");
    assert!(output.status.success(), "pack build must succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Built pack acme/hello@1.0.0"), "{stdout}");
    assert!(
        stdout.contains("sha256=") && stdout.contains("key_id="),
        "{stdout}"
    );
    let dir = world
        .sealed_bundle
        .as_ref()
        .expect("pack fixture is staged");
    let archive = dir.path().join("build.mvmpkg");
    assert!(
        std::fs::metadata(&archive)
            .expect("pack build wrote the archive")
            .len()
            > 0
    );
    let home = world.last_live_home.as_ref().expect("live build ran");
    std::fs::copy(
        home.join("keys/host-signer.pub"),
        dir.path().join("publisher.pub"),
    )
    .expect("copy the build signer's public key for independent verification");
}
