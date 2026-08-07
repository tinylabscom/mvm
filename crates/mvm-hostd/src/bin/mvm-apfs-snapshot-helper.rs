//! Narrow root-owned APFS snapshot service.
//!
//! This binary is deliberately not launched by the unprivileged client. A
//! host service manager must start it with an explicit state root, socket, and
//! client UID. The library server authenticates both sides of the Unix socket
//! and rejects paths outside that state root.

#[cfg(not(all(target_os = "macos", feature = "trusted-apfs")))]
fn main() {
    eprintln!("mvm-apfs-snapshot-helper requires macOS with the trusted-apfs feature");
    std::process::exit(1);
}

#[cfg(all(target_os = "macos", feature = "trusted-apfs"))]
fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let parsed = parse_args(&args);
    let (socket, root, uid) = match parsed {
        Ok(values) => values,
        Err(error) => {
            eprintln!("mvm-apfs-snapshot-helper: {error}");
            eprintln!("usage: mvm-apfs-snapshot-helper --socket PATH --root PATH --uid UID");
            std::process::exit(64);
        }
    };
    if let Err(error) = mvm_fs::trusted_snapshot::serve_apfs_snapshot_helper(socket, root, uid) {
        eprintln!("mvm-apfs-snapshot-helper: {error}");
        std::process::exit(1);
    }
}

#[cfg(all(target_os = "macos", feature = "trusted-apfs"))]
fn parse_args(
    args: &[std::ffi::OsString],
) -> Result<(std::path::PathBuf, std::path::PathBuf, u32), String> {
    let mut socket = None;
    let mut root = None;
    let mut uid = None;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index]
            .to_str()
            .ok_or_else(|| "arguments must be valid UTF-8".to_owned())?;
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag {
            "--socket" => socket = Some(std::path::PathBuf::from(value)),
            "--root" => root = Some(std::path::PathBuf::from(value)),
            "--uid" => {
                let text = value
                    .to_str()
                    .ok_or_else(|| "UID must be valid UTF-8".to_owned())?;
                uid = Some(
                    text.parse::<u32>()
                        .map_err(|_| "UID must be an unsigned integer".to_owned())?,
                );
            }
            _ => return Err(format!("unknown argument {flag}")),
        }
        index += 2;
    }
    let socket = socket.ok_or_else(|| "--socket is required".to_owned())?;
    let root = root.ok_or_else(|| "--root is required".to_owned())?;
    let uid = uid.ok_or_else(|| "--uid is required".to_owned())?;
    Ok((socket, root, uid))
}

#[cfg(all(test, target_os = "macos", feature = "trusted-apfs"))]
mod tests {
    use super::parse_args;
    use std::ffi::OsString;

    #[test]
    fn parses_explicit_socket_root_and_uid() {
        let args = [
            OsString::from("--socket"),
            OsString::from("/var/run/mvm/apfs.sock"),
            OsString::from("--root"),
            OsString::from("/Users/test/.mvm"),
            OsString::from("--uid"),
            OsString::from("501"),
        ];
        let (socket, root, uid) = parse_args(&args).expect("valid helper arguments");
        assert_eq!(socket, std::path::PathBuf::from("/var/run/mvm/apfs.sock"));
        assert_eq!(root, std::path::PathBuf::from("/Users/test/.mvm"));
        assert_eq!(uid, 501);
    }

    #[test]
    fn rejects_unknown_argument() {
        let args = [
            OsString::from("--socket"),
            OsString::from("/tmp/x"),
            OsString::from("--bad"),
            OsString::from("value"),
        ];
        let error = parse_args(&args).expect_err("unknown argument must fail");
        assert!(error.contains("unknown argument"));
    }
}
