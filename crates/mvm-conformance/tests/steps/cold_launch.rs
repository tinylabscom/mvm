//! Step definitions for the prepared cold-launch lane scenarios.
//!
//! They drive `mvm_cli::bench::cold_launch::validate_lane` — the gate the
//! benchmark itself calls on every sample — rather than restating its rules,
//! so a scenario cannot pass while the shipped gate disagrees with it.
//! Hermetic: the gate is pure over a sample, and building a sample needs no
//! hypervisor.

use cucumber::{given, then, when};

use mvm_cli::bench::cold_launch::{
    ArtifactPaths, BuildProfile, GuestSizing, LAUNCH_SAMPLE_SCHEMA_VERSION, LaunchLane, LaunchMode,
    LaunchRootStrategy, LaunchSample, LaunchSubTimings, LaunchWork, RunPhaseTimings,
    validate_hard_boot_timing, validate_lane,
};

use crate::world::CliWorld;

/// A launch that booted, ran its command, and tore down — nothing else.
fn clean_sample(profile: BuildProfile) -> LaunchSample {
    LaunchSample {
        schema_version: LAUNCH_SAMPLE_SCHEMA_VERSION,
        build_profile: profile,
        mvm_version: env!("CARGO_PKG_VERSION").to_string(),
        backend: "hvf".to_string(),
        os: "macos".to_string(),
        arch: "aarch64".to_string(),
        launch_mode: LaunchMode::Cold,
        root_strategy: Some(LaunchRootStrategy::BlockExt4),
        sizing: GuestSizing {
            cpus: 2,
            memory_mib: 512,
            mem_initial_mib: None,
        },
        artifacts: ArtifactPaths::default(),
        work: LaunchWork::default(),
        phases: RunPhaseTimings {
            launch_mode: LaunchMode::Cold,
            resolve_ms: 0.4,
            drives_ms: 0.6,
            admit_ms: 12.0,
            pool_wait_ms: 0.0,
            claim_ms: 0.0,
            backend_start_ms: 120.0,
            vsock_wait_ms: 40.0,
            warm_window_ms: 160.0,
            command_ms: 3.0,
            teardown_ms: 20.0,
            total_ms: 196.0,
        },
        sub_phases: LaunchSubTimings {
            artifact_verify_ms: Some(0.3),
            vmm_create_ms: Some(118.0),
            guest_kernel_entry_ms: Some(30.0),
            agent_auth_ms: Some(4.0),
            first_dispatch_ms: Some(1.0),
            cleanup_handoff_ms: Some(19.0),
            ..LaunchSubTimings::default()
        },
        warm_first_command_memory: None,
        backend_phases: Vec::new(),
        degraded: Vec::new(),
    }
}

#[given(regex = r"^a (release|debug) launch sample whose launch performed no hidden work$")]
fn clean_launch_sample(world: &mut CliWorld, profile: String) {
    let profile = match profile.as_str() {
        "release" => BuildProfile::Release,
        "debug" => BuildProfile::Debug,
        other => panic!("unknown build profile {other:?}"),
    };
    world.cold_launch_sample = Some(clean_sample(profile));
}

#[given(regex = r"^a prepared-cold launch with a dispatch window of ([0-9.]+) ms$")]
fn launch_with_dispatch_window(world: &mut CliWorld, milliseconds: f64) {
    let mut sample = clean_sample(BuildProfile::Release);
    sample.phases.backend_start_ms = milliseconds;
    sample.phases.vsock_wait_ms = 0.0;
    sample.phases.warm_window_ms = milliseconds;
    world.cold_launch_sample = Some(sample);
}

#[given(
    regex = r"^a release launch sample whose launch performed (image_pull|image_build|mount_materialize|warm_claim|artifact_hash|process_table_scan)$"
)]
fn contaminated_launch_sample(world: &mut CliWorld, work: String) {
    let mut sample = clean_sample(BuildProfile::Release);
    match work.as_str() {
        "image_pull" => sample.work.image_pull = true,
        "image_build" => sample.work.image_build = true,
        "mount_materialize" => {
            sample.work.mount_materialize = true;
            sample.sub_phases.mount_materialize_ms = Some(429_809.0);
        }
        "warm_claim" => {
            sample.work.warm_claim = true;
            sample.launch_mode = LaunchMode::Warm;
        }
        // A rootfs-sized re-read of an artifact whose digest was already
        // cached: not a pull, a build, a materialization, or a claim, and so
        // the one kind of repeated work the lane could not previously name.
        "artifact_hash" => sample.work.artifact_bytes_hashed = 1_205_739_520,
        // Host maintenance charged to a launch that spawned nothing to clean.
        "process_table_scan" => sample.work.process_table_scans = 1,
        other => panic!("unknown work kind {other:?}"),
    }
    world.cold_launch_sample = Some(sample);
}

#[given("the launch was satisfied by a warm standby without setting the work flag")]
fn warm_launch_without_the_flag(world: &mut CliWorld) {
    let sample = world
        .cold_launch_sample
        .as_mut()
        .expect("a launch sample was staged");
    sample.launch_mode = LaunchMode::Warm;
    sample.work.warm_claim = false;
}

#[when("the sample is offered to the prepared-cold lane")]
fn offer_to_the_prepared_cold_lane(world: &mut CliWorld) {
    let sample = world
        .cold_launch_sample
        .as_ref()
        .expect("a launch sample was staged");
    world.cold_launch_lane_result =
        Some(validate_lane(LaunchLane::PreparedCold, sample).map_err(|e| e.to_string()));
}

#[when("the dispatch timing is checked against the hard boot requirement")]
fn check_hard_boot_requirement(world: &mut CliWorld) {
    let sample = world
        .cold_launch_sample
        .as_ref()
        .expect("a launch sample was staged");
    world.cold_launch_lane_result = Some(
        validate_hard_boot_timing(LaunchLane::PreparedCold, sample.phases.dispatch_window_ms())
            .map_err(|error| error.to_string()),
    );
}

#[then("the prepared-cold lane accepts the sample")]
fn the_lane_accepts(world: &mut CliWorld) {
    let outcome = world
        .cold_launch_lane_result
        .as_ref()
        .expect("the lane was offered a sample");
    assert_eq!(outcome, &Ok(()), "the lane refused a clean launch");
}

#[then("the hard boot requirement passes")]
fn hard_boot_requirement_passes(world: &mut CliWorld) {
    the_lane_accepts(world);
}

#[then("the hard boot requirement fails and says every boot must be under 200 ms")]
fn hard_boot_requirement_fails(world: &mut CliWorld) {
    let rendered = refusal(world);
    assert!(
        rendered.contains("every boot must be under 200.0ms"),
        "hard-limit refusal was not explicit: {rendered}"
    );
}

#[then(
    regex = r"^the prepared-cold lane refuses the sample naming (image_pull|image_build|mount_materialize|warm_claim|artifact_hash|process_table_scan)$"
)]
fn the_lane_refuses_naming(world: &mut CliWorld, work: String) {
    let rendered = refusal(world);
    assert!(
        rendered.contains(&work),
        "refusal did not name {work}: {rendered}"
    );
}

#[then("the prepared-cold lane refuses the sample as not a cold launch")]
fn the_lane_refuses_a_warm_launch(world: &mut CliWorld) {
    let rendered = refusal(world);
    assert!(
        rendered.contains("cannot be measured from a warm launch"),
        "refusal did not cite the launch mode: {rendered}"
    );
}

#[then("the prepared-cold lane refuses the sample as not release-built")]
fn the_lane_refuses_a_debug_build(world: &mut CliWorld) {
    let rendered = refusal(world);
    assert!(
        rendered.contains("release-only"),
        "refusal did not cite the build profile: {rendered}"
    );
}

/// The rendered refusal, failing the scenario if the lane accepted instead.
fn refusal(world: &CliWorld) -> String {
    match world
        .cold_launch_lane_result
        .as_ref()
        .expect("the lane was offered a sample")
    {
        Ok(()) => panic!("the prepared-cold lane accepted a sample it must refuse"),
        Err(rendered) => rendered.clone(),
    }
}
