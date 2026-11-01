//! Builder smoke tests. Asserts the public
//! builders produce the expected `Workload` struct and that obvious
//! misuse (empty workload, missing required fields) is rejected.

use mvm_sdk::*;

#[test]
fn workload_with_one_app_round_trips() {
    let wl = workload("hello")
        .app(
            app("hello")
                .source(local_path("."))
                .image(nix_packages(["python312"]))
                .entrypoint(entrypoint_command(["python", "-m", "hello"]))
                .resources(resources(1, 256, 512))
                .build()
                .expect("app builds"),
        )
        .build()
        .expect("workload builds");

    assert_eq!(wl.id, "hello");
    assert_eq!(wl.schema_version, "0.1");
    assert_eq!(wl.apps.len(), 1);
    assert_eq!(wl.apps[0].name, "hello");
    assert_eq!(wl.apps[0].entrypoints.len(), 1);
}

#[test]
fn empty_workload_rejected() {
    let err = workload("nope").build().expect_err("must reject");
    matches!(err, BuildError::EmptyWorkload);
}

#[test]
fn app_missing_source_rejected() {
    let err = app("missing-src")
        .image(nix_packages(["python312"]))
        .entrypoint(entrypoint_command(["python"]))
        .resources(resources(1, 256, 512))
        .build()
        .expect_err("must reject");
    match err {
        BuildError::MissingField { name, field } => {
            assert_eq!(name, "missing-src");
            assert_eq!(field, "source");
        }
        e => panic!("wrong variant: {e:?}"),
    }
}

#[test]
fn app_missing_entrypoint_rejected() {
    let err = app("no-ep")
        .source(local_path("."))
        .image(nix_packages(["python312"]))
        .resources(resources(1, 256, 512))
        .build()
        .expect_err("must reject");
    matches!(
        err,
        BuildError::MissingField {
            field: "entrypoint",
            ..
        }
    );
}

#[test]
fn function_entrypoint_constructed() {
    let ep = entrypoint_function("python", "hello", "main");
    match ep {
        IrEntrypoint::Function {
            language,
            module,
            function,
            format,
            primary,
            ..
        } => {
            assert_eq!(language, "python");
            assert_eq!(module, "hello");
            assert_eq!(function, "main");
            assert_eq!(format, IrFormat::Json);
            assert!(!primary, "default primary=false");
        }
        _ => panic!("expected Function variant"),
    }
}

#[test]
fn deps_constructors_produce_typed_variants() {
    match python_deps("uv.lock") {
        IrDependencies::Python { lockfile, tool } => {
            assert_eq!(lockfile, "uv.lock");
            assert_eq!(tool, IrPythonTool::Uv);
        }
        _ => panic!("expected Python"),
    }
    match node_deps("pnpm-lock.yaml") {
        IrDependencies::Node { lockfile, tool } => {
            assert_eq!(lockfile, "pnpm-lock.yaml");
            assert_eq!(tool, IrNodeTool::Pnpm);
        }
        _ => panic!("expected Node"),
    }
    matches!(no_deps(), IrDependencies::None);
}
