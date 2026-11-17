//! Live witness for a built project's first committed policy generation.

use std::{fs, path::PathBuf};

use cucumber::{given, when};

use crate::world::CliWorld;

fn project(world: &CliWorld) -> PathBuf {
    world
        .scratch_dir
        .as_ref()
        .expect("policy-generation project was prepared")
        .path()
        .to_path_buf()
}

fn run(world: &mut CliWorld, args: &[&str]) {
    super::cli::run_mvmctl_isolated_live_home_argv(
        world,
        args.iter().map(|arg| (*arg).to_string()).collect(),
    );
}

#[given("an isolated built-policy project with a one-CPU ceiling")]
fn prepare_project(world: &mut CliWorld) {
    world.isolated_home = Some(tempfile::tempdir().expect("isolated live MVM home"));
    let project = tempfile::tempdir().expect("temporary project");
    let flake = super::cli::workspace_root().join("examples/exit_code");
    let profile = project.path().join("limit.toml");
    fs::write(&profile, "[overrides.resources]\nmax_cpus = 1\n")
        .expect("write authored project policy");
    fs::write(
        project.path().join("mvm.toml"),
        format!(
            "flake = {:?}\nprofile = \"default\"\ncpus = 1\nmem = \"256M\"\n\
             data_disk = \"0\"\nnet = false\n[policy]\nprofile = {:?}\n",
            flake.display().to_string(),
            profile.display().to_string()
        ),
    )
    .expect("write project manifest");
    world.scratch_dir = Some(project);
}

#[given("an isolated built-policy project with a CPU-share ceiling")]
fn prepare_share_project(world: &mut CliWorld) {
    prepare_project(world);
    fs::write(
        project(world).join("limit.toml"),
        "[overrides.resources]\nmax_cpus = 1\ncpu_millicores = 250\n",
    )
    .expect("write CPU-share policy");
}

#[when("I build and activate the isolated policy-generation project")]
fn build_and_activate(world: &mut CliWorld) {
    let manifest = project(world).join("mvm.toml");
    run(
        world,
        &[
            "machine",
            "build",
            "--mvm-config",
            manifest.to_str().expect("UTF-8 manifest path"),
        ],
    );
    let output = world.last_run.as_ref().expect("build result");
    assert!(
        output.status.success(),
        "project build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let project = project(world);
    run(
        world,
        &[
            "policy",
            "activate",
            project.to_str().expect("UTF-8 project path"),
        ],
    );
}

#[when("I widen the staged policy and manifest")]
fn widen_staged_project(world: &mut CliWorld) {
    let project = project(world);
    fs::write(
        project.join("limit.toml"),
        "[overrides.resources]\nmax_cpus = 4\n",
    )
    .expect("stage wider policy");
    fs::write(project.join("mvm.toml"), "image = \"alpine\"\ncpus = 4\n")
        .expect("stage another boot source");
}

#[when("I request two CPUs from the committed manifest")]
fn refused_wider_run(world: &mut CliWorld) {
    let manifest = project(world).join("mvm.toml");
    run(
        world,
        &[
            "machine",
            "run",
            "--manifest",
            manifest.to_str().expect("UTF-8 manifest path"),
            "--cpus",
            "2",
            "--entrypoint",
        ],
    );
}

#[when("I run the committed entrypoint with one CPU")]
fn admitted_original_run(world: &mut CliWorld) {
    let manifest = project(world).join("mvm.toml");
    run(
        world,
        &[
            "machine",
            "run",
            "--manifest",
            manifest.to_str().expect("UTF-8 manifest path"),
            "--cpus",
            "1",
            "--entrypoint",
        ],
    );
}

#[when("I run the committed project flake with one CPU")]
fn admitted_flake_run(world: &mut CliWorld) {
    let project = project(world);
    // The coordinator was started from the workspace root, not this project.
    super::cli::run_mvmctl_isolated_live_home_argv_in(
        world,
        [
            "machine",
            "run",
            "--flake",
            ".",
            "--cpus",
            "1",
            "--entrypoint",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        &project,
    );
}
