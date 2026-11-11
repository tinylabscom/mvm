//! Render and retain the v2 recipe's guest entrypoint as sealed filesystem input.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use mvm_core::packs::Sha256Hex;

use super::RuntimeLayerStageError;

const MARKER: &str = "etc/mvm/entrypoint";

pub(super) fn script(argv: &[String]) -> Vec<u8> {
    let mut text = String::from("#!/bin/sh\nexec");
    for arg in argv {
        // POSIX single quotes pass the authored argument literally, including
        // shell metacharacters. A quote itself closes and reopens the literal.
        text.push_str(" '");
        text.push_str(&arg.replace('\'', "'\\''"));
        text.push('\'');
    }
    text.push('\n');
    text.into_bytes()
}

fn require_directories(root: &Path) -> Result<(), RuntimeLayerStageError> {
    for relative in ["etc", "etc/mvm"] {
        let metadata = std::fs::symlink_metadata(root.join(relative))
            .map_err(|_| RuntimeLayerStageError::Entrypoint)?;
        if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o001 == 0 {
            return Err(RuntimeLayerStageError::Entrypoint);
        }
    }
    Ok(())
}

pub(super) fn write_script(
    root: &Path,
    argv: &[String],
) -> Result<Sha256Hex, RuntimeLayerStageError> {
    require_directories(root)?;
    let path = root.join(MARKER);
    if std::fs::symlink_metadata(&path).is_ok() {
        return Err(RuntimeLayerStageError::Entrypoint);
    }
    let bytes = script(argv);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&bytes)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o555))?;
    file.sync_all()?;
    Ok(Sha256Hex::from_bytes(&bytes))
}

pub(super) fn verify_script(root: &Path, digest: &Sha256Hex) -> Result<(), RuntimeLayerStageError> {
    require_directories(root)?;
    let path = root.join(MARKER);
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|_| RuntimeLayerStageError::Entrypoint)?;
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o7777 != 0o555
        || Sha256Hex::from_bytes(&std::fs::read(&path)?) != *digest
    {
        return Err(RuntimeLayerStageError::Entrypoint);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authored_arguments_are_literal_shell_words() {
        let command = script(&[
            "/usr/bin/printf".into(),
            "%s".into(),
            "a'b $HOME; $(false)".into(),
        ]);
        assert_eq!(
            command,
            b"#!/bin/sh\nexec '/usr/bin/printf' '%s' 'a'\\''b $HOME; $(false)'\n"
        );
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(String::from_utf8(command).unwrap())
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        assert_eq!(output.stdout, b"a'b $HOME; $(false)");
    }

    #[test]
    fn occupied_or_changed_host_owned_marker_is_refused() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("etc/mvm")).unwrap();
        let argv = ["/bin/true".into()];
        let digest = write_script(root.path(), &argv).unwrap();
        verify_script(root.path(), &digest).unwrap();
        assert!(matches!(
            write_script(root.path(), &argv),
            Err(RuntimeLayerStageError::Entrypoint)
        ));
        let marker = root.path().join(MARKER);
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&marker, b"tampered").unwrap();
        assert!(matches!(
            verify_script(root.path(), &digest),
            Err(RuntimeLayerStageError::Entrypoint)
        ));
        std::fs::remove_file(&marker).unwrap();
        std::fs::remove_dir(root.path().join("etc/mvm")).unwrap();
        std::os::unix::fs::symlink(root.path(), root.path().join("etc/mvm")).unwrap();
        assert!(matches!(
            write_script(root.path(), &argv),
            Err(RuntimeLayerStageError::Entrypoint)
        ));
    }
}
