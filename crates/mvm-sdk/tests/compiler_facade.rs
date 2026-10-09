//! Compatibility witnesses for compiler stages extracted from `mvm-sdk`.

#[test]
fn pinned_workload_compilation_is_byte_identical_through_both_apis() {
    use mvm_sdk::*;

    for (language, extension, app_source, helper_source) in [
        (
            "python",
            "py",
            "from helper import value\n\ndef answer():\n    return value\n",
            "value = 42\n",
        ),
        (
            "node",
            "ts",
            "import { value } from './helper.js';\nexport function answer() { return value; }\n",
            "export const value = 42;\n",
        ),
    ] {
        let root = tempfile::tempdir().expect("manifest directory");
        let source = root.path().join("app");
        std::fs::create_dir(&source).expect("source directory");
        std::fs::write(source.join(format!("app.{extension}")), app_source).expect("app");
        std::fs::write(source.join(format!("helper.{extension}")), helper_source).expect("helper");
        std::fs::write(source.join(format!("unused.{extension}")), "").expect("unused module");
        let mut workload = workload("compile-facade")
            .app(
                app("hello")
                    .source(local_path("app"))
                    .image(nix_packages(["python312", "nodejs"]))
                    .entrypoint(entrypoint_function(language, "app", "answer"))
                    .resources(resources(1, 256, 512))
                    .build()
                    .expect("app builds"),
            )
            .build()
            .expect("workload builds");
        workload.apps[0].dependencies = Some(no_deps());
        mvm_sdk::ir::validate(&workload).expect("fixture validates");
        let revision: mvm_sdk::compile::PinnedMvmRevision =
            mvm_compiler::PinnedMvmRevision::parse("32e44a05a884f41b94aba0cf8f99e00e55b0dc51")
                .expect("immutable revision");
        let sdk_out = root.path().join("sdk");
        let compiler_out = root.path().join("compiler");
        mvm_sdk::compile::compile_pinned(&workload, &sdk_out, root.path(), &revision)
            .expect("SDK directory");
        mvm_compiler::compile_pinned(&workload, &compiler_out, root.path(), &revision)
            .expect("compiler directory");
        for path in [
            "flake.nix".to_string(),
            "launch.json".to_string(),
            "workload.json".to_string(),
            format!("src/app.{extension}"),
            format!("src/helper.{extension}"),
        ] {
            assert_eq!(
                std::fs::read(sdk_out.join(&path)).expect("SDK artifact"),
                std::fs::read(compiler_out.join(&path)).expect("compiler artifact"),
                "{language}: {path}"
            );
        }
        assert!(!sdk_out.join(format!("src/unused.{extension}")).exists());
        assert!(
            !compiler_out
                .join(format!("src/unused.{extension}"))
                .exists()
        );
        let flake = std::fs::read_to_string(compiler_out.join("flake.nix")).expect("flake");
        assert!(
            flake.contains(revision.as_str()),
            "flake must carry the explicit pin"
        );

        let sdk_archive = root.path().join("sdk.tar.gz");
        let compiler_archive = root.path().join("compiler.tar.gz");
        mvm_sdk::compile::compile_archive_pinned(&workload, &sdk_archive, root.path(), &revision)
            .expect("SDK archive");
        mvm_compiler::compile_archive_pinned(&workload, &compiler_archive, root.path(), &revision)
            .expect("compiler archive");
        assert_eq!(
            std::fs::read(sdk_archive).expect("SDK archive bytes"),
            std::fs::read(compiler_archive).expect("compiler archive bytes"),
            "{language}: archives"
        );

        if let IrEntrypoint::Function { function, .. } = &mut workload.apps[0].entrypoints[0] {
            *function = "missing".to_string();
        }
        let sdk_error: mvm_compiler::CompileError =
            mvm_sdk::compile::compile_pinned(&workload, &sdk_out, root.path(), &revision)
                .expect_err("SDK rejects missing function");
        let compiler_error: mvm_sdk::compile::CompileError =
            mvm_compiler::compile_pinned(&workload, &compiler_out, root.path(), &revision)
                .expect_err("compiler rejects missing function");
        assert!(matches!(
            sdk_error,
            mvm_compiler::CompileError::FunctionNotFound { .. }
        ));
        assert_eq!(sdk_error.to_string(), compiler_error.to_string());
    }
}

#[test]
fn dependency_validation_remains_available_through_the_sdk_facade() {
    use mvm_sdk::*;

    let root = tempfile::tempdir().expect("manifest directory");
    let source = root.path().join("app");
    std::fs::create_dir(&source).expect("source directory");
    let mut workload = workload("lockfile-facade")
        .app(
            app("hello")
                .source(local_path("app"))
                .image(nix_packages(["python312"]))
                .entrypoint(entrypoint_command(["python", "app.py"]))
                .resources(resources(1, 256, 512))
                .build()
                .expect("app"),
        )
        .build()
        .expect("workload");
    workload.apps[0].dependencies = Some(python_deps("uv.lock"));
    let lockfile = source.join("uv.lock");
    std::fs::write(
        &lockfile,
        "[[package]]\nname = \"example\"\nversion = \"1.0\"\nhash = \"sha256:abc\"\n",
    )
    .expect("pinned lockfile");
    mvm_sdk::compile::validate_lockfiles(&workload, root.path()).expect("SDK facade");
    mvm_compiler::validate_lockfiles(&workload, root.path()).expect("compiler");

    std::fs::write(&lockfile, "[[package]]\nname = \"example\"\n").expect("unpinned lockfile");
    for error in [
        mvm_sdk::compile::deps::validate_lockfiles(&workload, root.path())
            .expect_err("SDK rejects"),
        mvm_compiler::deps::validate_lockfiles(&workload, root.path())
            .expect_err("compiler rejects"),
    ] {
        match error {
            mvm_sdk::compile::DepsError::Unpinned {
                app_index,
                path,
                detail,
            } => {
                assert_eq!(app_index, 0);
                assert_eq!(path, lockfile);
                assert_eq!(detail, "1/1 packages missing hash");
            }
            error => panic!("expected unpinned error, got {error:?}"),
        }
    }

    workload.apps[0].dependencies = Some(python_deps("missing.lock"));
    let error: mvm_sdk::compile::deps::DepsError =
        mvm_compiler::validate_lockfiles(&workload, root.path()).expect_err("missing lockfile");
    match error {
        mvm_compiler::DepsError::LockfileNotFound { app_index, path } => {
            assert_eq!(app_index, 0);
            assert_eq!(path, source.join("missing.lock"));
        }
        error => panic!("expected missing lockfile error, got {error:?}"),
    }
}

#[test]
fn archive_generation_remains_available_through_the_sdk_facade() {
    let staging = tempfile::tempdir().expect("staging");
    let output = tempfile::tempdir().expect("output");
    std::fs::create_dir(staging.path().join("source")).expect("source directory");
    std::fs::write(staging.path().join("source/app.py"), "print('ok')\n").expect("fixture");
    std::fs::write(staging.path().join("launch.json"), "{}\n").expect("launch fixture");
    let sdk_out = output.path().join("sdk.tar.gz");
    let compiler_out = output.path().join("compiler.tar.gz");

    mvm_sdk::compile::archive_dir(staging.path(), &sdk_out).expect("SDK facade");
    mvm_compiler::archive_dir(staging.path(), &compiler_out).expect("compiler");
    assert_eq!(
        std::fs::read(&sdk_out).expect("SDK archive"),
        std::fs::read(&compiler_out).expect("compiler archive")
    );

    let gz = flate2::read::GzDecoder::new(std::fs::File::open(sdk_out).expect("archive"));
    let mut archive = tar::Archive::new(gz);
    let extracted = output.path().join("extracted");
    archive.unpack(&extracted).expect("unpack");
    assert_eq!(
        std::fs::read(extracted.join("source/app.py")).expect("extracted source"),
        b"print('ok')\n"
    );
}

#[test]
fn archive_errors_retain_the_sdk_type() {
    let root = tempfile::tempdir().expect("tempdir");
    let missing = root.path().join("missing");
    let output = root.path().join("out.tar.gz");
    let error: mvm_sdk::compile::ArchiveError =
        mvm_compiler::archive::archive_dir(&missing, &output).expect_err("missing staging");
    assert_eq!(error.0.kind(), std::io::ErrorKind::NotFound);
    let facade_error: mvm_compiler::ArchiveError =
        mvm_sdk::compile::archive::archive_dir(&missing, &output).expect_err("missing staging");
    assert_eq!(facade_error.0.kind(), error.0.kind());
    assert!(!output.exists());
}

#[test]
fn reachability_remains_available_through_the_sdk_facade() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::write(root.path().join("app.py"), "print('ok')\n").expect("fixture");

    let through_sdk = mvm_sdk::compile::detect_language(root.path(), "app");
    let through_compiler = mvm_compiler::detect_language(root.path(), "app");

    assert_eq!(through_sdk, through_compiler);
    assert_eq!(through_sdk, Some(mvm_sdk::compile::Language::Python));
}

#[test]
fn framework_stripping_remains_available_through_the_sdk_facade() {
    let sdk_root = tempfile::tempdir().expect("tempdir");
    let compiler_root = tempfile::tempdir().expect("tempdir");
    let source = "from mvm import function\n\n@function\ndef answer():\n    return 42\n";
    std::fs::write(sdk_root.path().join("app.py"), source).expect("sdk fixture");
    std::fs::write(compiler_root.path().join("app.py"), source).expect("compiler fixture");

    mvm_sdk::compile::strip_framework::strip_python(sdk_root.path()).expect("SDK facade");
    mvm_compiler::strip_framework::strip_python(compiler_root.path()).expect("compiler");

    assert_eq!(
        std::fs::read(sdk_root.path().join("app.py")).expect("SDK output"),
        std::fs::read(compiler_root.path().join("app.py")).expect("compiler output")
    );
}

#[test]
fn function_description_remains_available_through_the_sdk_facade() {
    let source = b"def answer(value=42):\n    return value\n";

    let through_sdk =
        mvm_sdk::compile::describe_function(mvm_sdk::compile::Language::Python, source, "answer")
            .expect("SDK facade");
    let through_compiler =
        mvm_compiler::describe_function(mvm_compiler::Language::Python, source, "answer")
            .expect("compiler");

    assert_eq!(through_sdk, through_compiler);
}

#[test]
fn source_planning_remains_available_through_the_sdk_facade() {
    let source = tempfile::tempdir().expect("source");
    let sdk_out = tempfile::tempdir().expect("SDK output");
    let compiler_out = tempfile::tempdir().expect("compiler output");
    std::fs::write(source.path().join("app.py"), "print('ok')\n").expect("fixture");

    let through_sdk =
        mvm_sdk::compile::copy_source(source.path(), sdk_out.path(), &[], &[]).expect("SDK facade");
    let through_compiler =
        mvm_compiler::copy_source(source.path(), compiler_out.path(), &[], &[]).expect("compiler");

    assert_eq!(through_sdk.file_count, through_compiler.file_count);
    assert_eq!(through_sdk.tree_hash, through_compiler.tree_hash);
}
