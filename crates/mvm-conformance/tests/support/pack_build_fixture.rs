use std::path::Path;

pub fn producer_binary(
    arguments: &[String],
    live: bool,
    configured: Option<std::ffi::OsString>,
) -> Option<std::ffi::OsString> {
    if live
        && arguments.first().is_some_and(|arg| arg == "pack")
        && arguments.get(1).is_some_and(|arg| arg == "build")
    {
        configured
    } else {
        None
    }
}

/// Stage authored data independently of the output archive and lock, so later
/// outputs cannot change the source tree the lock commits to.
pub fn stage(dir: &Path) {
    let mut spec: serde_json::Value = serde_json::from_str(include_str!(
        "../../../mvm-contract/tests/fixtures/pack-spec-v1/minimal.json"
    ))
    .expect("the shared minimal pack spec is valid JSON");
    spec["target"] = format!("{}-linux", std::env::consts::ARCH).into();
    spec["source"]["path"] = "app".into();
    spec["resources"]["memory_mb"] = 256.into();
    std::fs::create_dir_all(dir.join("app")).expect("create pack source directory");
    std::fs::write(dir.join("app/hello.txt"), b"pack health witness\n")
        .expect("write pack health payload");
    std::fs::write(
        dir.join("pack.json"),
        serde_json::to_vec_pretty(&spec).expect("serialize pack spec"),
    )
    .expect("write pack spec");
}
