//! Source selection and one-launch runtime identity at the CLI admission handoff.

/// The source choices held while constructing the transient command request.
pub(super) struct ImageSelection {
    pub(super) image_ref: Option<String>,
    pub(super) prod: bool,
    pub(super) runtime_pack: bool,
}

/// A copied archive identity is not proof that this launch owns the same set.
pub(super) fn same_launch_runtime<T>(
    owner: Option<&std::sync::Arc<T>>,
    checked: Option<&T>,
) -> bool {
    match (owner, checked) {
        (None, None) => true,
        (Some(owner), Some(checked)) => std::ptr::eq(owner.as_ref(), checked),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_owner_must_be_the_set_used_for_this_admission() {
        let first = std::sync::Arc::new("same runtime identity");
        let later = std::sync::Arc::new("same runtime identity");
        assert!(same_launch_runtime(Some(&first), Some(first.as_ref())));
        assert!(!same_launch_runtime(Some(&later), Some(first.as_ref())));
        assert!(!same_launch_runtime(Some(&first), None));
        assert!(!same_launch_runtime(None, Some(first.as_ref())));
    }
}
