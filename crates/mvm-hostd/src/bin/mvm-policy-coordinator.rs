//! Automatically managed local lifecycle policy coordinator.

fn main() -> anyhow::Result<()> {
    mvm_hostd::policy_generation::coordinator::serve()
}
