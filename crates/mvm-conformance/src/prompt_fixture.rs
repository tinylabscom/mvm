//! Names and local-state cleanup for the persistent prompt/replay witness.

use std::io::{self, ErrorKind};
use std::path::Path;

/// Machine whose prompts are recorded during the live witness.
pub const AGENT_MACHINE: &str = "bdd-prompt";
/// Fork receiving the recorded prompts during the live witness.
pub const REPLAY_MACHINE: &str = "bdd-prompt-replay";
/// Fork of the first fork's own session: a prompt to a replayed fork is
/// recorded and step-checkpointed, so the fork's session replays in turn.
pub const SECOND_REPLAY_MACHINE: &str = "bdd-prompt-replay-2";

/// Every machine, and so every prompt session, the live witness creates.
pub const PROMPT_MACHINES: [&str; 3] = [AGENT_MACHINE, REPLAY_MACHINE, SECOND_REPLAY_MACHINE];

/// Remove only the prompt-session directories left by an interrupted run.
///
/// # Errors
/// A session directory could not be inspected or removed.
pub fn clear_stale_prompt_sessions(home: &Path) -> io::Result<()> {
    let sessions = home.join("agent-sessions");
    let root = match std::fs::symlink_metadata(&sessions) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !root.is_dir() || root.file_type().is_symlink() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "agent-sessions root must be a non-symlink directory",
        ));
    }

    for name in PROMPT_MACHINES {
        let path = sessions.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                std::fs::remove_dir_all(&path)?;
            }
            Ok(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("prompt session {name} must be a non-symlink directory"),
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rerun_clears_every_prompt_session_but_preserves_other_sessions() {
        let home = tempfile::tempdir().expect("home");
        let sessions = home.path().join("agent-sessions");
        for name in PROMPT_MACHINES.into_iter().chain(["unrelated"]) {
            let dir = sessions.join(name);
            std::fs::create_dir_all(&dir).expect("session dir");
            std::fs::write(dir.join("history.jsonl"), name).expect("history");
        }

        clear_stale_prompt_sessions(home.path()).expect("clear stale prompt sessions");

        for name in PROMPT_MACHINES {
            assert!(!sessions.join(name).exists(), "{name}");
        }
        assert!(sessions.join("unrelated").join("history.jsonl").is_file());
    }

    #[test]
    fn a_home_without_prompt_sessions_needs_no_cleanup() {
        let home = tempfile::tempdir().expect("home");
        clear_stale_prompt_sessions(home.path()).expect("absent sessions are already clear");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_session_is_refused_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let home = tempfile::tempdir().expect("home");
        let outside = tempfile::tempdir().expect("outside");
        let sentinel = outside.path().join("history.jsonl");
        std::fs::write(&sentinel, "keep").expect("sentinel");
        let sessions = home.path().join("agent-sessions");
        std::fs::create_dir(&sessions).expect("sessions");
        symlink(outside.path(), sessions.join(AGENT_MACHINE)).expect("session symlink");

        let error = clear_stale_prompt_sessions(home.path()).expect_err("refuse symlink");
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(sentinel.is_file());
    }
}
