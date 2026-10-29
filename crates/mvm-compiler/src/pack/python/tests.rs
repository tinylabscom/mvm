use super::*;
use crate::pack::test_support::spec;
use mvm_contract::pack_spec::{PackageRequest, PackageScope};

/// A lock uv 0.11 wrote for a project depending on `requests[socks]`,
/// `pydantic` (whose core is a native extension) and, on Windows only,
/// `colorama`, with `pytest` as a development dependency.
const FIXTURE: &str = include_str!("../../../tests/fixtures/pack-python/uv.lock");

const HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn python(minor: u32) -> Interpreter {
    Interpreter::from_attribute(&format!("python3{minor}")).unwrap()
}

fn names(environment: &PythonEnvironment) -> Vec<&str> {
    environment.wheels.iter().map(|w| w.name.as_str()).collect()
}

fn wheel<'a>(environment: &'a PythonEnvironment, name: &str) -> &'a LockedWheel {
    environment
        .wheels
        .iter()
        .find(|w| w.name == name)
        .unwrap_or_else(|| panic!("{name} is installed"))
}

#[test]
fn the_fixture_resolves_to_runtime_wheels_for_the_target() {
    let environment = resolve(FIXTURE, &python(12), PackTarget::X86_64Linux).unwrap();
    assert_eq!(environment.interpreter, "python312");
    assert_eq!(
        names(&environment),
        [
            "annotated-types",
            "certifi",
            "charset-normalizer",
            "idna",
            "pydantic",
            "pydantic-core",
            "pysocks",
            "requests",
            "typing-extensions",
            "typing-inspection",
            "urllib3",
        ],
        "dev dependencies and the win32-only colorama are left out; the socks extra is in"
    );
    let core = wheel(&environment, "pydantic-core");
    assert_eq!(
        core.filename,
        "pydantic_core-2.50.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
    );
    assert!(core.url.starts_with("https://files.pythonhosted.org/"));
    assert!(core.url.ends_with(&core.filename));
    assert_eq!(core.sha256.len(), 64);
    assert_eq!(
        wheel(&environment, "pysocks").filename,
        "PySocks-1.7.1-py3-none-any.whl"
    );
    assert_eq!(
        wheel(&environment, "charset-normalizer").filename,
        "charset_normalizer-3.5.2-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl"
    );
}

#[test]
fn the_fixture_selects_native_wheels_per_architecture() {
    let environment = resolve(FIXTURE, &python(12), PackTarget::Aarch64Linux).unwrap();
    assert_eq!(
        wheel(&environment, "pydantic-core").filename,
        "pydantic_core-2.50.1-cp312-cp312-manylinux_2_17_aarch64.manylinux2014_aarch64.whl"
    );
}

#[test]
fn resolution_is_deterministic_and_round_trips() {
    let first = resolve(FIXTURE, &python(12), PackTarget::X86_64Linux).unwrap();
    let second = resolve(FIXTURE, &python(12), PackTarget::X86_64Linux).unwrap();
    assert_eq!(first, second);
    let json = serde_json::to_string(&first).unwrap();
    assert_eq!(
        serde_json::from_str::<PythonEnvironment>(&json).unwrap(),
        first
    );
}

#[test]
fn an_interpreter_outside_requires_python_is_refused() {
    assert!(matches!(
        resolve(FIXTURE, &python(11), PackTarget::X86_64Linux),
        Err(PythonError::RequiresPython { .. })
    ));
    let patched = FIXTURE.replace(
        "requires-python = \">=3.12\"",
        "requires-python = \">=3.12.4\"",
    );
    assert!(matches!(
        resolve(&patched, &python(12), PackTarget::X86_64Linux),
        Err(PythonError::RequiresPythonPatch { .. })
    ));
    let malformed = FIXTURE.replace(
        "requires-python = \">=3.12\"",
        "requires-python = \">=3.*\"",
    );
    assert!(matches!(
        resolve(&malformed, &python(12), PackTarget::X86_64Linux),
        Err(PythonError::RequiresPythonSyntax(_))
    ));
}

fn with_packages(names: &[&str]) -> PackSpec {
    let mut spec = spec();
    spec.packages = names
        .iter()
        .map(|name| PackageRequest {
            name: (*name).into(),
            version: None,
            scope: PackageScope::Runtime,
        })
        .collect();
    spec
}

#[test]
fn the_interpreter_is_the_one_python3nn_package() {
    let found = Interpreter::from_spec(&with_packages(&["busybox", "python312"])).unwrap();
    assert_eq!(found, python(12));
    assert!(matches!(
        Interpreter::from_spec(&with_packages(&["busybox", "python3"])),
        Err(PythonError::NoInterpreter)
    ));
    assert!(matches!(
        Interpreter::from_spec(&with_packages(&["python3Full", "python313t", "python3123"])),
        Err(PythonError::NoInterpreter)
    ));
    let Err(PythonError::MultipleInterpreters(found)) =
        Interpreter::from_spec(&with_packages(&["python311", "python312"]))
    else {
        panic!("two interpreters are refused");
    };
    assert_eq!(found, ["python311", "python312"]);
}

/// A lock whose project depends on `dependencies`, followed by `packages`.
fn lock(dependencies: &str, packages: &str) -> String {
    format!(
        r#"version = 1
revision = 3
requires-python = ">=3.12"

[[package]]
name = "app"
version = "0.1.0"
source = {{ virtual = "." }}
dependencies = [{dependencies}]

[package.dev-dependencies]
dev = [{{ name = "devtool" }}]

{packages}"#
    )
}

fn package(name: &str, version: &str, extra: &str) -> String {
    let file = name.replace('-', "_");
    format!(
        r#"
[[package]]
name = "{name}"
version = "{version}"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [{{ url = "https://files.example/{file}-{version}-py3-none-any.whl", hash = "{HASH}" }}]
{extra}
"#
    )
}

fn resolved(lock: &str) -> Result<PythonEnvironment, PythonError> {
    resolve(lock, &python(12), PackTarget::X86_64Linux)
}

#[test]
fn development_dependencies_are_never_installed() {
    let text = lock(
        r#"{ name = "a" }"#,
        &(package("a", "1.0", "") + &package("devtool", "1.0", "")),
    );
    assert_eq!(names(&resolved(&text).unwrap()), ["a"]);
}

#[test]
fn extras_pull_in_their_optional_dependencies() {
    let text = lock(
        r#"{ name = "a", extra = ["fast"] }"#,
        &(package(
            "a",
            "1.0",
            "[package.optional-dependencies]\nfast = [{ name = \"b\" }]",
        ) + &package("b", "2.0", "")
            + &package("c", "3.0", "")),
    );
    assert_eq!(names(&resolved(&text).unwrap()), ["a", "b"]);
    let missing = lock(
        r#"{ name = "a", extra = ["slow"] }"#,
        &package("a", "1.0", ""),
    );
    assert!(matches!(
        resolved(&missing),
        Err(PythonError::MissingExtra { extra, .. }) if extra == "slow"
    ));
}

#[test]
fn markers_prune_edges_for_the_target() {
    let text = lock(
        r#"{ name = "a", marker = "sys_platform == 'win32'" }, { name = "b", marker = "platform_machine == 'x86_64' and python_version >= '3.12'" }"#,
        &(package("a", "1.0", "") + &package("b", "1.0", "")),
    );
    assert_eq!(names(&resolved(&text).unwrap()), ["b"]);
    assert!(
        resolve(&text, &python(12), PackTarget::Aarch64Linux)
            .unwrap()
            .wheels
            .is_empty()
    );
}

#[test]
fn a_marker_the_target_cannot_decide_is_refused_with_its_text() {
    let text = lock(
        r#"{ name = "a", marker = "platform_release >= '6.0'" }"#,
        &package("a", "1.0", ""),
    );
    let Err(PythonError::Marker { marker, reason, .. }) = resolved(&text) else {
        panic!("an undecidable marker is refused");
    };
    assert_eq!(marker, "platform_release >= '6.0'");
    assert_eq!(
        reason,
        MarkerError::UnsupportedVariable("platform_release".into())
    );
}

#[test]
fn same_named_packages_need_a_version_to_tell_them_apart() {
    let packages = package("a", "1.0", "") + &package("a", "2.0", "");
    assert!(matches!(
        resolved(&lock(r#"{ name = "a" }"#, &packages)),
        Err(PythonError::AmbiguousDependency { package }) if package == "a"
    ));
    let chosen = resolved(&lock(r#"{ name = "a", version = "2.0" }"#, &packages)).unwrap();
    assert_eq!(chosen.wheels[0].version, "2.0");
    assert!(matches!(
        resolved(&lock(r#"{ name = "a", version = "3.0" }"#, &packages)),
        Err(PythonError::MissingPackage { .. })
    ));
}

#[test]
fn two_versions_of_one_package_cannot_both_install() {
    let text = lock(
        r#"{ name = "a", version = "1.0" }, { name = "a", version = "2.0" }"#,
        &(package("a", "1.0", "") + &package("a", "2.0", "")),
    );
    assert!(matches!(
        resolved(&text),
        Err(PythonError::ConflictingVersions { package, .. }) if package == "a"
    ));
}

#[test]
fn packages_from_outside_a_registry_are_refused() {
    for source in [
        r#"{ git = "https://example.com/a.git?rev=main#abc" }"#,
        r#"{ url = "https://example.com/a-1.0.tar.gz" }"#,
        r#"{ path = "vendor/a-1.0-py3-none-any.whl" }"#,
        r#"{ directory = "../a" }"#,
        r#"{ editable = "../a" }"#,
    ] {
        let text = lock(
            r#"{ name = "a" }"#,
            &format!("[[package]]\nname = \"a\"\nversion = \"1.0\"\nsource = {source}\n"),
        );
        assert!(
            matches!(resolved(&text), Err(PythonError::UnsupportedSource { .. })),
            "{source}"
        );
    }
}

#[test]
fn an_sdist_only_package_is_refused_by_name_and_version() {
    let text = lock(
        r#"{ name = "a" }"#,
        r#"
[[package]]
name = "a"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.example/a-1.0.tar.gz", hash = "sha256:00" }
"#,
    );
    let Err(error @ PythonError::NoCompatibleWheel { .. }) = resolved(&text) else {
        panic!("an sdist-only package is refused");
    };
    let message = error.to_string();
    assert!(message.contains("a 1.0"), "{message}");
    assert!(message.contains("CPython 3.12"), "{message}");
}

#[test]
fn a_wheel_for_another_platform_only_is_refused() {
    let text = lock(
        r#"{ name = "a" }"#,
        &format!(
            r#"
[[package]]
name = "a"
version = "1.0"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [
    {{ url = "https://files.example/a-1.0-cp312-cp312-musllinux_1_2_x86_64.whl", hash = "{HASH}" }},
    {{ url = "https://files.example/a-1.0-cp312-cp312-win_amd64.whl", hash = "{HASH}" }},
]
"#
        ),
    );
    assert!(matches!(
        resolved(&text),
        Err(PythonError::NoCompatibleWheel { .. })
    ));
}

fn single_wheel(url: &str, hash: &str) -> String {
    lock(
        r#"{ name = "a" }"#,
        &format!(
            "[[package]]\nname = \"a\"\nversion = \"1.0\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\nwheels = [{{ url = \"{url}\", hash = \"{hash}\" }}]\n"
        ),
    )
}

#[test]
fn the_chosen_wheel_must_be_https_and_sha256_pinned() {
    for (url, hash) in [
        ("http://files.example/a-1.0-py3-none-any.whl", HASH),
        ("file:///tmp/a-1.0-py3-none-any.whl", HASH),
        ("https://files.example/a-1.0-py3-none-any.whl", "sha256:abc"),
        (
            "https://files.example/a-1.0-py3-none-any.whl",
            "md5:00000000000000000000000000000000",
        ),
        (
            "https://files.example/a-1.0-py3-none-any.whl",
            "sha256:000000000000000000000000000000000000000000000000000000000000000G",
        ),
    ] {
        assert!(
            matches!(
                resolved(&single_wheel(url, hash)),
                Err(PythonError::InvalidWheel { .. })
            ),
            "{url} {hash}"
        );
    }
}

#[test]
fn a_wheel_must_name_its_package_and_version() {
    for url in [
        "https://files.example/b-1.0-py3-none-any.whl",
        "https://files.example/a-1.1-py3-none-any.whl",
        "https://files.example/a-1.0.whl",
    ] {
        assert!(
            matches!(
                resolved(&single_wheel(url, HASH)),
                Err(PythonError::InvalidWheel { .. })
            ),
            "{url}"
        );
    }
    let escaped = resolved(&single_wheel(
        "https://files.example/a-1.0%2Bcpu-py3-none-any.whl?sig=1",
        HASH,
    ));
    assert!(
        matches!(&escaped, Err(PythonError::InvalidWheel { reason, .. }) if reason.contains("version")),
        "a local version is not the locked version: {escaped:?}"
    );
}

#[test]
fn the_best_ranked_wheel_wins_whatever_the_lockfile_order() {
    let text = lock(
        r#"{ name = "a" }"#,
        &format!(
            r#"
[[package]]
name = "a"
version = "1.0"
source = {{ registry = "https://pypi.org/simple" }}
wheels = [
    {{ url = "https://files.example/a-1.0-py3-none-any.whl", hash = "{HASH}" }},
    {{ url = "https://files.example/a-1.0-cp312-abi3-manylinux_2_17_x86_64.whl", hash = "{HASH}" }},
    {{ url = "https://files.example/a-1.0-cp312-cp312-manylinux_2_28_x86_64.whl", hash = "{HASH}" }},
]
"#
        ),
    );
    assert_eq!(
        resolved(&text).unwrap().wheels[0].filename,
        "a-1.0-cp312-cp312-manylinux_2_28_x86_64.whl"
    );
}

#[test]
fn malformed_locks_are_refused() {
    assert!(matches!(
        resolved("version = 1\n[[package]\n"),
        Err(PythonError::LockSyntax(_))
    ));
    assert!(matches!(
        resolved(&lock("", "").replace("version = 1\n", "version = 2\n")),
        Err(PythonError::LockVersion(2))
    ));
    assert!(matches!(
        resolved("version = 1\n"),
        Err(PythonError::NoProject)
    ));
    let two_projects = lock("", "")
        + "[[package]]\nname = \"other\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n";
    assert!(matches!(
        resolved(&two_projects),
        Err(PythonError::MultipleProjects(_))
    ));
    assert!(matches!(
        resolved(&lock(r#"{ name = "absent" }"#, "")),
        Err(PythonError::MissingPackage { .. })
    ));
}
