//! Pure output parsing for the live machine-journey witness.

/// Return the checkpoint id only from a successful full-VM capture report.
pub fn vm_full_checkpoint_id(stdout: &str) -> Option<&str> {
    stdout
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(4)
        .find_map(|words| match words {
            ["vm_full", "checkpoint", id, "created"] => Some(*id),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::vm_full_checkpoint_id;

    #[test]
    fn parses_only_a_full_checkpoint_creation_report() {
        assert_eq!(
            vm_full_checkpoint_id("bdd-journey: vm_full checkpoint ckpt-123 created\n"),
            Some("ckpt-123")
        );
        assert_eq!(vm_full_checkpoint_id("no checkpoint was created\n"), None);
        assert_eq!(
            vm_full_checkpoint_id("bdd-journey: fs_quick checkpoint ckpt-123 created\n"),
            None
        );
    }
}
