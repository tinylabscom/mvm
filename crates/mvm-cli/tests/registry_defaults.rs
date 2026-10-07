use mvm_cli::pack_registry::{DEFAULT_PACK_REGISTRY, PACK_REGISTRY_ENV, PackRegistryConfig};
use mvm_cli::template_registry::RegistryConfig;
use mvm_core::util::test_env::TestEnv;

const RENAMED_REPOSITORY_URL: &str = "https://raw.githubusercontent.com/tinylabscom/mvm-packs/main";

#[test]
fn pack_and_template_indexes_use_the_renamed_repository_without_redirects() {
    let mut env = TestEnv::new();
    let home = tempfile::tempdir().expect("isolated home");
    env.isolate_mvm_home(home.path());
    env.remove(PACK_REGISTRY_ENV);
    env.remove("MVM_TEMPLATE_REGISTRY");

    assert_eq!(DEFAULT_PACK_REGISTRY, RENAMED_REPOSITORY_URL);
    assert_eq!(
        PackRegistryConfig::load().registry_url,
        RENAMED_REPOSITORY_URL
    );
    assert_eq!(RegistryConfig::load().registry_url, RENAMED_REPOSITORY_URL);

    env.set(PACK_REGISTRY_ENV, "file:///tmp/packs-mirror");
    env.set("MVM_TEMPLATE_REGISTRY", "file:///tmp/templates-mirror");
    assert_eq!(
        PackRegistryConfig::load().registry_url,
        "file:///tmp/packs-mirror"
    );
    assert_eq!(
        RegistryConfig::load().registry_url,
        "file:///tmp/templates-mirror"
    );
}
