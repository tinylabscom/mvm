use std::path::PathBuf;

const CONNECT_CLIENT_IMAGE: &str = "--image curlimages/curl:8.21.0";
const HTTPS_LIVE_FEATURES: &[&str] = &[
    "features/suites/s2_egress_vsock/admitted_egress_live.feature",
    "features/suites/s2_egress_vsock/hvf_egress_observable.feature",
    "features/suites/s5_lifecycle/transient_sandbox_boot.feature",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn live_https_egress_uses_a_connect_capable_client() {
    let mut commands = Vec::new();
    for relative in HTTPS_LIVE_FEATURES {
        let body = std::fs::read_to_string(repo_root().join(relative))
            .unwrap_or_else(|error| panic!("read {relative}: {error}"));
        commands.extend(
            body.lines()
                .filter(|line| line.contains("When I run mvmctl") && line.contains("https://"))
                .map(|line| ((*relative).to_string(), line.to_string())),
        );
    }

    assert_eq!(
        commands.len(),
        7,
        "the guarded HTTPS live-command set drifted"
    );
    for (feature, command) in commands {
        assert!(
            command.contains(CONNECT_CLIENT_IMAGE),
            "{feature} uses an HTTPS client image without a pinned CONNECT contract: {command}"
        );
        assert!(
            command.contains(" curl "),
            "{feature} does not exercise curl's CONNECT tunnel: {command}"
        );
        assert!(
            !command.contains("wget"),
            "{feature} regressed to BusyBox wget's refused HTTPS absolute form: {command}"
        );
    }
}
