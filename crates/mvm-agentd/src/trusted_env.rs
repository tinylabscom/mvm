//! Environment boundary for runtime helpers and elevated mediated tools.
//!
//! These are image/runtime binary directories, not workload search paths. Their
//! protection depends on the guest mount policy and the integrity of the image;
//! this is not validation of every symlink or of arbitrary tool behavior.
//! Programs can still choose their own environment, plugins, or executable paths.

use std::process::Command;

/// Fixed search path inherited by trusted programs and their ordinary children.
pub const TRUSTED_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Known loader, resolver, shell and interpreter startup injection controls.
///
/// This is deliberately not a claim to cover every interpreter or application's
/// configuration variables. Ordinary workload execution must not use this policy.
#[must_use]
pub fn is_startup_var(key: &str) -> bool {
    key.starts_with("LD_")
        || key.starts_with("DYLD_")
        || key.starts_with("BASH_FUNC_")
        || key.starts_with("PYTHON")
        || key.starts_with("LUA_INIT")
        || key.starts_with("LUA_PATH")
        || key.starts_with("LUA_CPATH")
        || matches!(
            key,
            "HOSTALIASES"
                | "RES_OPTIONS"
                | "LOCALDOMAIN"
                | "NLSPATH"
                | "LOCPATH"
                | "GCONV_PATH"
                | "GLIBC_TUNABLES"
                | "MALLOC_TRACE"
                | "MALLOC_CHECK_"
                | "BASH_ENV"
                | "ENV"
                | "BASHOPTS"
                | "SHELLOPTS"
                | "IFS"
                | "CDPATH"
                | "NODE_OPTIONS"
                | "NODE_PATH"
                | "PERL5OPT"
                | "PERL5LIB"
                | "PERLLIB"
                | "PERLIO"
                | "RUBYOPT"
                | "RUBYLIB"
                | "RUBYPATH"
                | "JAVA_TOOL_OPTIONS"
                | "JDK_JAVA_OPTIONS"
                | "_JAVA_OPTIONS"
                | "CLASSPATH"
                | "PHPRC"
                | "PHP_INI_SCAN_DIR"
                | "ZDOTDIR"
        )
}

/// Preserve application data while replacing executable search and removing
/// known startup controls, including duplicate PATH entries.
#[must_use]
pub fn sanitized_env(env: &[(String, String)]) -> Vec<(String, String)> {
    env.iter()
        .filter(|(key, value)| {
            !key.is_empty()
                && !key.contains(['=', '\0'])
                && !value.contains('\0')
                && key != "PATH"
                && !is_startup_var(key)
        })
        .cloned()
        .chain(std::iter::once(("PATH".into(), TRUSTED_PATH.into())))
        .collect()
}

/// Apply the trusted policy to the parent's inherited environment.
///
/// Call before adding runtime-owned overrides. In particular, a helper needing
/// an intentional GPU loader shim must add that override after this boundary,
/// never import a workload's loader configuration.
pub fn configure_command(command: &mut Command) {
    configure_with_env(command, std::env::vars_os());
}

/// Sanitize a fully assembled explicit environment, without importing any
/// additional variables from the parent. Apply after combining image and
/// request variables for a trusted mediated launch.
pub fn configure_explicit_command(command: &mut Command) {
    let env: Vec<_> = command
        .get_envs()
        .filter_map(|(key, value)| Some((key.to_owned(), value?.to_owned())))
        .collect();
    configure_with_env(command, env);
}

fn configure_with_env(
    command: &mut Command,
    env: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) {
    command.env_clear();
    command.envs(
        env.into_iter()
            .filter(|(key, _)| key != "PATH" && !is_startup_var(&key.to_string_lossy())),
    );
    command.env("PATH", TRUSTED_PATH);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_startup_controls_and_replaces_all_paths() {
        let mut env = vec![
            ("PATH".into(), "/work:/data:/tmp::.".into()),
            ("PATH".into(), "/home/tools".into()),
            ("TOKEN".into(), "application-data".into()),
            ("LD_PRELOAD=bad".into(), "bad".into()),
            ("PATH=/work".into(), "bad".into()),
            ("".into(), "bad".into()),
            ("GOOD".into(), "bad\0value".into()),
        ];
        for key in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "BASH_ENV",
            "ENV",
            "BASH_FUNC_ls%%",
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONSTARTUP",
            "NODE_OPTIONS",
            "NODE_PATH",
            "PERL5OPT",
            "PERL5LIB",
            "RUBYOPT",
            "RUBYLIB",
            "LUA_INIT_5_4",
            "LUA_PATH_5_4",
            "LUA_CPATH_5_4",
            "JAVA_TOOL_OPTIONS",
            "JDK_JAVA_OPTIONS",
            "_JAVA_OPTIONS",
            "CLASSPATH",
            "PHPRC",
            "PHP_INI_SCAN_DIR",
            "GCONV_PATH",
            "GLIBC_TUNABLES",
        ] {
            env.push((key.into(), "/tmp/injection".into()));
        }
        assert_eq!(
            sanitized_env(&env),
            vec![
                ("TOKEN".into(), "application-data".into()),
                ("PATH".into(), TRUSTED_PATH.into()),
            ]
        );
        assert!(TRUSTED_PATH.split(':').all(|dir| {
            dir.starts_with('/')
                && !["/work", "/data", "/tmp", "/home"]
                    .iter()
                    .any(|bad| dir.starts_with(bad))
        }));
        assert_eq!(
            sanitized_env(&[]),
            vec![("PATH".into(), TRUSTED_PATH.into())]
        );
    }

    #[test]
    fn helper_command_sets_explicit_path_and_clears_inheritance() {
        const PROBE: &str = "MVM_TRUSTED_ENV_PROBE";
        if std::env::var_os(PROBE).is_none() {
            // A separate process supplies hostile inherited variables without
            // mutating the environment of parallel tests.
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "trusted_env::tests::helper_command_sets_explicit_path_and_clears_inheritance",
                    "--nocapture",
                ])
                .env(PROBE, "1")
                .env("PATH", "/work:/data:/tmp::.")
                .env("BASH_ENV", "/tmp/hostile-startup")
                .env("PYTHONPATH", "/work/hostile-python")
                .env("NODE_OPTIONS", "--require=/tmp/hostile-node")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("trusted-env-probe-passed"));
            return;
        }
        assert!(std::env::var_os("BASH_ENV").is_some());
        assert!(std::env::var_os("PYTHONPATH").is_some());
        let mut command = Command::new("/bin/sh");
        configure_command(&mut command);
        let env: Vec<_> = command.get_envs().collect();
        assert!(env.iter().any(|(key, value)| {
            *key == "PATH" && *value == Some(std::ffi::OsStr::new(TRUSTED_PATH))
        }));
        assert!(
            env.iter()
                .all(|(key, _)| !is_startup_var(&key.to_string_lossy()))
        );
        #[cfg(unix)]
        {
            let output = command
                .args([
                    "-c",
                    "test \"$PATH\" = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' && test -z \"$BASH_ENV$PYTHONPATH$NODE_OPTIONS\"",
                ])
                .output()
                .unwrap();
            assert!(output.status.success());
        }
        println!("trusted-env-probe-passed");
    }

    #[cfg(unix)]
    #[test]
    fn trusted_shell_children_ignore_fake_ls_in_workload_path() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let fake_ls = dir.path().join("ls");
        std::fs::write(&fake_ls, "#!/bin/sh\nprintf hostile-ls\n").unwrap();
        std::fs::set_permissions(&fake_ls, std::fs::Permissions::from_mode(0o755)).unwrap();
        let env = vec![("PATH".into(), dir.path().to_str().unwrap().into())];
        let run = |env: &[(String, String)]| {
            Command::new("/bin/sh")
                .args(["-c", "ls /dev/null"])
                .env_clear()
                .envs(env.iter().cloned())
                .output()
                .unwrap()
        };
        let workload = run(&env);
        assert!(workload.status.success());
        assert_eq!(workload.stdout, b"hostile-ls");
        let trusted = run(&sanitized_env(&env));
        assert!(trusted.status.success());
        assert_ne!(trusted.stdout, workload.stdout);
        assert!(
            String::from_utf8(trusted.stdout)
                .unwrap()
                .contains("/dev/null")
        );
    }
}
