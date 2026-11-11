use super::*;
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

struct BindingCase {
    base: PathBuf,
    root: PathBuf,
    key: InstallationKey,
}
impl BindingCase {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = std::env::temp_dir().join(format!(
            "spiral-owner-binding-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&base).unwrap();
        Self {
            root: base.join("installation"),
            base,
            key: InstallationKey {
                installation: [0x91; 32],
                profile: [0xa4; 32],
            },
        }
    }
}
impl Drop for BindingCase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

#[test]
fn active_binding_returns_only_original_identity_and_current_active_epoch() {
    let fixture = BindingCase::new();
    let mut owner = InstallationOwner::initialize(&fixture.root, fixture.key).unwrap();
    let first = owner.begin().unwrap();
    let binding = owner.active_binding(first).unwrap();
    assert_eq!(binding.root, fixture.root);
    assert_eq!(binding.key, fixture.key);
    assert_eq!(binding.generation, first.generation());

    owner.finish(first).unwrap();
    assert!(matches!(
        owner.active_binding(first),
        Err(OwnerError::StaleEpoch)
    ));
    let second = owner.begin().unwrap();
    assert_eq!(second.generation(), first.generation() + 1);
    assert!(matches!(
        owner.active_binding(first),
        Err(OwnerError::StaleEpoch)
    ));
    let binding = owner.active_binding(second).unwrap();
    assert_eq!(binding.root, fixture.root);
    assert_eq!(binding.key, fixture.key);
    assert_eq!(binding.generation, second.generation());
    owner.finish(second).unwrap();
}

#[test]
fn active_binding_uses_the_existing_canonical_storage_fence() {
    let fixture = BindingCase::new();
    let mut owner = InstallationOwner::initialize(&fixture.root, fixture.key).unwrap();
    let epoch = owner.begin().unwrap();
    owner.active_binding(epoch).unwrap();
    // Damage the real fixed record without duplicating its parser/checksum.
    // A later metadata query must not use cached identity to bypass current().
    let state_path = fixture.root.join("state.bin");
    let mut damaged = fs::read(&state_path).unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    fs::write(&state_path, &damaged).unwrap();
    assert!(matches!(
        owner.active_binding(epoch),
        Err(OwnerError::Fenced)
    ));
    assert!(matches!(owner.snapshot(), Err(OwnerError::Fenced)));
    assert_eq!(fs::read(state_path).unwrap(), damaged);
}
