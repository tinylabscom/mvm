//! Guest Unix-socket forwarding into an explicitly selected host service.

fn validate_unix_forward_guest_path(path: &str) -> anyhow::Result<()> {
    let path = std::path::Path::new(path);
    if !path.is_absolute() {
        anyhow::bail!("guest socket path must be absolute");
    }
    if !path.starts_with("/run/mvm/") {
        anyhow::bail!("guest socket path must be under /run/mvm");
    }
    Ok(())
}

pub(crate) fn start_unix_socket_forwarder(
    guest_path: &str,
    host_vsock_port: u32,
    socket_mode: u32,
) -> anyhow::Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::UnixListener;

    validate_unix_forward_guest_path(guest_path)?;
    let path = std::path::PathBuf::from(guest_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_socket() => {
            std::fs::remove_file(&path)?;
        }
        Ok(_) => {
            anyhow::bail!("refusing to replace non-socket path {}", path.display());
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(socket_mode & 0o777))?;
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let Ok(upstream) = mvm_agentd::vsock::connect_host_vsock(
                    host_vsock_port,
                    mvm_agentd::vsock::DEFAULT_TIMEOUT_SECS,
                ) else {
                    eprintln!("unix-fwd: connect_host_vsock({host_vsock_port}) failed");
                    return;
                };
                let Ok(mut guest_read) = stream.try_clone() else {
                    return;
                };
                let Ok(mut host_write) = upstream.try_clone() else {
                    return;
                };
                let mut guest_write = stream;
                let mut host_read = upstream;
                let h1 = std::thread::spawn(move || {
                    let _ = std::io::copy(&mut guest_read, &mut host_write);
                });
                let h2 = std::thread::spawn(move || {
                    let _ = std::io::copy(&mut host_read, &mut guest_write);
                });
                let _ = h1.join();
                let _ = h2.join();
            });
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_forward_guest_path_is_confined_to_run_mvm() {
        validate_unix_forward_guest_path("/run/mvm/forward.sock").expect("valid path");
        let relative = validate_unix_forward_guest_path("run/mvm/forward.sock")
            .expect_err("relative path rejected");
        assert!(relative.to_string().contains("absolute"));
        let outside =
            validate_unix_forward_guest_path("/tmp/forward.sock").expect_err("outside rejected");
        assert!(outside.to_string().contains("under /run/mvm"));
    }
}
