use super::*;

fn prepare(root: &Path, names: &[&str]) -> PreparedOutputs {
    PreparedOutputs::prepare(
        names
            .iter()
            .map(|name| OutputGrant {
                guest_path: format!("/data/{name}"),
                host_path: root.join(name).to_string_lossy().into_owned(),
                max_bytes: MIB,
                max_entries: 10,
            })
            .collect(),
        &[],
    )
    .unwrap()
}

fn admit(root: &Path, name: &str, prepared: &PreparedOutputs) -> AdmissionContext {
    crate::admission::admit_plan_tests::admitted_outputs_into(
        &root.join("keys"),
        &root.join("audit"),
        name,
        prepared.grants(),
        mvm_hostd::run::shares_from_vm_volumes(&prepared.volumes()),
    )
}

fn image(path: &Path, body: &[u8]) {
    let bytes = mvm_fs::ext4::build_image(
        vec![mvm_fs::ext4::Node::File {
            path: "/result.txt".into(),
            mode: 0o644,
            data: body.to_vec(),
            xattrs: Vec::new(),
            owner: mvm_fs::ext4::Owner::ROOT,
        }],
        &Default::default(),
    )
    .unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn audit(root: &Path) -> String {
    std::fs::read_to_string(root.join("audit/local.jsonl")).unwrap()
}

#[test]
fn independently_admitted_identical_grants_cannot_exchange_output_images() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let a = prepare(home.path(), &["out"]);
    let b = prepare(home.path(), &["out"]);
    assert_eq!(a.grants(), b.grants());
    assert_ne!(a.outputs[0].image, b.outputs[0].image);
    image(&a.outputs[0].image, b"run A");
    image(&b.outputs[0].image, b"run B");
    let ctx_a = admit(home.path(), "output-a", &a);
    let ctx_b = admit(home.path(), "output-b", &b);
    assert_ne!(ctx_a.admitted.plan_id(), ctx_b.admitted.plan_id());
    a.validate_binding(Some(&ctx_a)).unwrap();
    b.validate_binding(Some(&ctx_b)).unwrap();
    let before = audit(home.path());
    let error = a
        .close_run(
            &RefCell::new(Some(ctx_b)),
            "firecracker",
            mvm_build::run_image::RootStrategy::BlockExt4,
            Ok(7),
            &mut |_| panic!("cross-context output must not be observed"),
        )
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("not named in the signed"),
        "{error:#}"
    );
    assert_eq!(
        audit(home.path()),
        before,
        "not even outcome audit may use B"
    );
    let destination = PathBuf::from(&a.grants()[0].host_path);
    assert!(!destination.exists());
    assert!(!mvm_fs::output::manifest_path_for(&destination).exists());

    // The same real image and its own independent admission still collect.
    let mut observed = Vec::new();
    let status = a
        .close_run(
            &RefCell::new(Some(ctx_a)),
            "firecracker",
            mvm_build::run_image::RootStrategy::BlockExt4,
            Ok(7),
            &mut |output| observed.push(output),
        )
        .unwrap();
    assert_eq!(status, 7);
    assert_eq!(
        std::fs::read(destination.join("result.txt")).unwrap(),
        b"run A"
    );
    assert_eq!(observed.len(), 1);
    assert!(observed[0].manifest_path.is_file());
    assert!(audit(home.path()).contains("\"outcome\":\"collected\""));
    let scratch_a = a.outputs[0].image.parent().unwrap().to_owned();
    let scratch_b = b.outputs[0].image.parent().unwrap().to_owned();
    drop(a);
    drop(b);
    assert!(!scratch_a.exists());
    assert!(!scratch_b.exists());
}

#[test]
fn admitted_bounds_and_run_failure_keep_their_refusal_tags() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let prepared = prepare(home.path(), &["out"]);
    image(
        &prepared.outputs[0].image,
        b"larger than the admitted byte bound",
    );
    let mut grants = prepared.grants();
    grants[0].max_bytes = 1;
    let ctx = crate::admission::admit_plan_tests::admitted_outputs_into(
        &home.path().join("keys"),
        &home.path().join("audit"),
        "output-narrowed",
        grants,
        mvm_hostd::run::shares_from_vm_volumes(&prepared.volumes()),
    );
    prepared.validate_binding(Some(&ctx)).unwrap();
    let error = prepared
        .collect(Some(&ctx), true, &mut |_| panic!("signed bound wins"))
        .unwrap_err();
    assert!(
        error.to_string().contains("output collection refused"),
        "{error:#}"
    );
    let chain = audit(home.path());
    assert!(chain.contains("\"reason\":\"byte_bound\""), "{chain}");
    assert!(!chain.contains("\"outcome\":\"collected\""), "{chain}");
    assert!(!Path::new(&prepared.grants()[0].host_path).exists());

    let error = prepared
        .close_run::<()>(
            &RefCell::new(Some(ctx)),
            "firecracker",
            mvm_build::run_image::RootStrategy::BlockExt4,
            Err(anyhow::anyhow!("original run failure")),
            &mut |_| panic!("failed run must not collect"),
        )
        .unwrap_err();
    assert_eq!(error.to_string(), "original run failure");
    assert!(audit(home.path()).contains("\"reason\":\"run_failed\""));
}

#[test]
fn all_images_are_bound_before_any_collection_or_audit() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let a = prepare(home.path(), &["one", "two"]);
    let b = prepare(home.path(), &["one", "two"]);
    for output in &a.outputs {
        image(&output.image, b"must not escape");
    }
    let mut shares = mvm_hostd::run::shares_from_vm_volumes(&a.volumes());
    shares[1].host_path = b.volumes()[1].host.clone();
    let ctx = crate::admission::admit_plan_tests::admitted_outputs_into(
        &home.path().join("keys"),
        &home.path().join("audit"),
        "output-mixed",
        a.grants(),
        shares,
    );
    let before = audit(home.path());
    let error = a
        .collect(Some(&ctx), true, &mut |_| panic!("no partial collection"))
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("not named in the signed"),
        "{error:#}"
    );
    assert_eq!(audit(home.path()), before);
    for grant in a.grants() {
        assert!(!Path::new(&grant.host_path).exists());
    }
}

#[test]
fn signed_destination_must_match_preparation_even_with_the_same_disk() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    let prepared = prepare(home.path(), &["out"]);
    let mut grants = prepared.grants();
    grants[0].host_path = home.path().join("elsewhere").to_string_lossy().into_owned();
    let ctx = crate::admission::admit_plan_tests::admitted_outputs_into(
        &home.path().join("keys"),
        &home.path().join("audit"),
        "output-destination",
        grants,
        mvm_hostd::run::shares_from_vm_volumes(&prepared.volumes()),
    );
    let before = audit(home.path());
    let error = prepared
        .collect(Some(&ctx), true, &mut |_| panic!("wrong destination"))
        .unwrap_err();
    assert!(error.to_string().contains("does not match"), "{error:#}");
    assert_eq!(audit(home.path()), before);
    assert!(!home.path().join("elsewhere").exists());
}

#[test]
fn protected_roots_are_refused_by_prepare_before_scratch() {
    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path().join("mvm"));
    env.set("HOME", home.path());
    std::fs::create_dir(home.path().join("mvm")).unwrap();
    for root in protected_host_roots() {
        // Even a missing protected root itself is forbidden.
        let grants = vec![OutputGrant {
            guest_path: "/data/out".into(),
            host_path: root.to_string_lossy().into_owned(),
            max_bytes: MIB,
            max_entries: 10,
        }];
        let error = PreparedOutputs::prepare(grants.clone(), &[]).err().unwrap();
        assert!(
            error.to_string().contains("protected directory"),
            "{error:#}"
        );
        assert!(!root.exists());
        std::fs::create_dir_all(&root).unwrap();
        let mut nested = grants;
        nested[0].host_path = root.join("out").to_string_lossy().into_owned();
        let error = PreparedOutputs::prepare(nested, &[]).err().unwrap();
        assert!(
            error.to_string().contains("protected directory"),
            "{error:#}"
        );
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 0);
    }
    assert!(
        !PathBuf::from(mvm_core::config::mvm_state_dir())
            .join("outputs")
            .exists()
    );
}

#[cfg(unix)]
#[test]
fn symlink_parents_are_resolved_for_both_legitimate_and_protected_destinations() {
    use std::os::unix::fs::symlink;

    let home = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path().join("missing/mvm"));
    env.set("HOME", home.path());
    assert_eq!(
        std::env::var_os("HOME").as_deref(),
        Some(home.path().as_os_str()),
        "credential roots must use the fixture HOME"
    );
    assert_eq!(
        std::env::var_os("MVM_HOME").as_deref(),
        Some(home.path().join("missing/mvm").as_os_str()),
        "mvm roots must stay isolated from the credential HOME"
    );
    let safe = home.path().join("safe");
    std::fs::create_dir(&safe).unwrap();
    let alias = home.path().join("alias");
    symlink(&safe, &alias).unwrap();
    let prepared = prepare(&alias, &["out"]);
    assert_eq!(
        PathBuf::from(&prepared.grants()[0].host_path),
        std::fs::canonicalize(&safe).unwrap().join("out")
    );
    drop(prepared);
    let ssh = home.path().join(".ssh");
    symlink(&safe, &ssh).unwrap();
    let roots = protected_host_roots();
    assert!(
        roots.contains(&ssh),
        "fixture .ssh must be a protected root; HOME={:?}, roots={roots:?}",
        std::env::var_os("HOME")
    );
    assert_eq!(
        std::fs::canonicalize(&ssh).unwrap(),
        std::fs::canonicalize(&safe).unwrap(),
        "the protected root and legitimate alias must resolve to the same directory"
    );
    let error = resolve_output_destination(&alias.join("out").to_string_lossy()).unwrap_err();
    assert!(
        error.to_string().contains("protected directory"),
        "{error:#}"
    );
    assert!(!safe.join("out").exists());
    let missing = home.path().join("not-there/out");
    let error = resolve_output_destination(&missing.to_string_lossy()).unwrap_err();
    assert!(
        error.to_string().contains("parent must already exist"),
        "{error:#}"
    );
}
