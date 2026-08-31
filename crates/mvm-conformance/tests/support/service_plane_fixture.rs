use std::path::Path;

pub(crate) fn command(service: &str, fixture_dir: &Path) -> String {
    format!(
        "run --runtime python --host-service {service} --mount {}:/work/fixtures:ro --timeout 300 -- python /work/fixtures/kv_roundtrip.py",
        fixture_dir.display()
    )
}
