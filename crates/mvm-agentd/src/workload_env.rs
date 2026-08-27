//! The environment a workload process starts in, resolved from the image.
//!
//! An OCI image declares its `Env`, `WorkingDir`, and `Entrypoint`/`Cmd` in
//! its config blob. Image materialization copies that declaration into the
//! rootfs at [`CONFIG_PATH`]; this module is the only place the guest reads it
//! back, and the only place a workload environment is assembled.
//!
//! Every way into a workload goes through it. The entrypoint runner execs the
//! declared argv; ad-hoc exec runs a supplied command; the interactive console
//! starts a shell. The latter two inherit the agent's own vars, and only the
//! console describes a terminal. They agree on everything else, which is the
//! point: a second resolver is exactly how an image command can land in an
//! environment whose `PATH` is missing the image's own tools.

use std::ffi::{CString, OsStr, OsString};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Where image materialization writes the image's declared runtime config,
/// relative to the rootfs root. Materialization writes into a staging
/// directory on the host, so it needs the relative form.
pub const CONFIG_REL_PATH: &str = "etc/mvm/image-runtime.json";

/// [`CONFIG_REL_PATH`] as the guest sees it. The two are kept in step by
/// `config_paths_name_the_same_file`; `concat!` cannot join a `const`.
pub const CONFIG_PATH: &str = "/etc/mvm/image-runtime.json";

/// Search path for an image that declares no `PATH` of its own.
///
/// A workload with no `PATH` at all cannot resolve a bare command name, which
/// breaks every shell script an image ships. `scratch`-style images declare
/// nothing, so the floor has to come from somewhere.
pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Terminal type reported to an interactive session.
pub const INTERACTIVE_TERM: &str = "xterm-256color";

/// An image's declared runtime configuration, as materialized into its rootfs.
///
/// `argv` is the flattened `Entrypoint` + `Cmd`. It is allowed to be empty:
/// an image can declare an environment and no command, and dropping the
/// environment along with the absent command is what left `rust:latest`
/// without its toolchain on `PATH`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageRuntimeConfig {
    #[serde(default)]
    pub argv: Vec<String>,
    /// `KEY=VALUE` strings, in the image's own order, as the OCI config spells
    /// them.
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub working_dir: Option<String>,
}

impl ImageRuntimeConfig {
    /// Whether the image declared nothing worth materializing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.argv.is_empty() && self.env.is_empty() && self.working_dir().is_none()
    }

    /// The declared working directory, with an empty string read as absent.
    /// Images routinely serialize `"WorkingDir": ""` for "unset".
    #[must_use]
    pub fn working_dir(&self) -> Option<&str> {
        self.working_dir.as_deref().filter(|dir| !dir.is_empty())
    }

    /// Read the config a materialized rootfs carries.
    ///
    /// A missing file is not an error: an image that declares nothing gets
    /// none written, and the caller wants the same empty config either way.
    pub fn load_from(path: &Path) -> Result<Self, String> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(format!("read {}: {error}", path.display())),
        };
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))
    }

    /// [`Self::load_from`] against the well-known [`CONFIG_PATH`].
    pub fn load() -> Result<Self, String> {
        Self::load_from(Path::new(CONFIG_PATH))
    }
}

/// A resolved workload environment: a deduplicated variable set plus the
/// directory the process starts in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadEnvironment {
    vars: Vec<(OsString, OsString)>,
    working_dir: OsString,
}

impl WorkloadEnvironment {
    #[must_use]
    pub fn builder() -> WorkloadEnvironmentBuilder {
        WorkloadEnvironmentBuilder::default()
    }

    /// The variables, in resolution order, one entry per name.
    pub fn vars(&self) -> impl Iterator<Item = (&OsStr, &OsStr)> {
        self.vars
            .iter()
            .map(|(key, val)| (key.as_os_str(), val.as_os_str()))
    }

    /// The directory the workload starts in.
    #[must_use]
    pub fn working_dir(&self) -> &OsStr {
        &self.working_dir
    }

    /// The variable set as a NUL-terminated `KEY=VALUE` block for `execve`.
    ///
    /// A name or value carrying an interior NUL cannot cross the C ABI, so it
    /// is dropped rather than truncated.
    #[must_use]
    pub fn to_envp(&self) -> Vec<CString> {
        use std::os::unix::ffi::OsStrExt;
        self.vars
            .iter()
            .filter_map(|(key, val)| {
                let mut kv = key.as_bytes().to_vec();
                kv.push(b'=');
                kv.extend_from_slice(val.as_bytes());
                CString::new(kv).ok()
            })
            .collect()
    }
}

/// Assembles a [`WorkloadEnvironment`] in precedence order.
///
/// Later layers overwrite earlier ones **in place**, keeping the earlier
/// entry's position. That matters: `execve` accepts a block with a repeated
/// name and `getenv` returns the first, so appending an override without
/// removing what it overrides is a silent no-op.
#[derive(Debug, Default)]
pub struct WorkloadEnvironmentBuilder {
    vars: Vec<(OsString, OsString)>,
    working_dir: Option<OsString>,
    term: Option<&'static str>,
}

impl WorkloadEnvironmentBuilder {
    /// Variables inherited from the calling process.
    ///
    /// The console passes the agent's own environment so a workload keeps
    /// whatever the boot path exported. The entrypoint runner passes nothing:
    /// a non-interactive workload starts from the image's declaration alone.
    #[must_use]
    pub fn inherit<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        for (key, val) in vars {
            self.set(key.into(), val.into());
        }
        self
    }

    /// The image's own declaration. Overrides anything inherited — an image's
    /// `PATH` describes where that image put its tools, and the agent's does
    /// not.
    #[must_use]
    pub fn image(mut self, config: &ImageRuntimeConfig) -> Self {
        for item in &config.env {
            if let Some((key, val)) = item.split_once('=') {
                self.set(OsString::from(key), OsString::from(val));
            }
        }
        if let Some(dir) = config.working_dir() {
            self.working_dir = Some(OsString::from(dir));
        }
        self
    }

    /// Caller-supplied overrides — `mvmctl --env KEY=VALUE`. Highest
    /// precedence below the forced values, so an operator can always correct
    /// what an image declared.
    ///
    /// A name that is empty or contains `=`, or a name or value carrying an
    /// interior NUL, is dropped: none can be expressed in an environment
    /// block, so passing them on would corrupt the ones that follow.
    #[must_use]
    pub fn overrides<'a, I>(mut self, pairs: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        for (key, val) in pairs {
            if key.is_empty() || key.contains('=') || key.contains('\0') || val.contains('\0') {
                continue;
            }
            self.set(OsString::from(key), OsString::from(val));
        }
        self
    }

    /// Mark the session interactive, which sets `TERM`.
    #[must_use]
    pub fn interactive(mut self) -> Self {
        self.term = Some(INTERACTIVE_TERM);
        self
    }

    /// Resolve, forcing the values no layer may override.
    ///
    /// `HOME` is forced to the writable home the guest actually provides: an
    /// image's declared `HOME` names a directory in a read-only root that the
    /// workload uid cannot write, and often cannot read.
    #[must_use]
    pub fn build(mut self) -> WorkloadEnvironment {
        let home = crate::guest_mount::workload_home();
        self.set(OsString::from("HOME"), OsString::from(home));
        if let Some(term) = self.term {
            self.set(OsString::from("TERM"), OsString::from(term));
        }
        if !self.has("PATH") {
            self.set(OsString::from("PATH"), OsString::from(DEFAULT_PATH));
        }
        let working_dir = self
            .working_dir
            .unwrap_or_else(|| OsString::from(crate::guest_mount::workload_home()));
        WorkloadEnvironment {
            vars: self.vars,
            working_dir,
        }
    }

    fn has(&self, key: &str) -> bool {
        self.vars.iter().any(|(k, _)| k == OsStr::new(key))
    }

    fn set(&mut self, key: OsString, val: OsString) {
        match self.vars.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = val,
            None => self.vars.push((key, val)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(env: &WorkloadEnvironment) -> Vec<(String, String)> {
        env.vars()
            .map(|(k, v)| (k.to_string_lossy().into(), v.to_string_lossy().into()))
            .collect()
    }

    fn value(env: &WorkloadEnvironment, key: &str) -> Option<String> {
        pairs(env)
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    #[test]
    fn config_paths_name_the_same_file() {
        assert_eq!(CONFIG_PATH, format!("/{CONFIG_REL_PATH}"));
    }

    #[test]
    fn home_paths_name_the_same_dir() {
        assert_eq!(
            crate::guest_mount::WORKLOAD_HOME,
            format!("/{}", crate::guest_mount::WORKLOAD_HOME_REL)
        );
    }

    /// The precedence ladder, exercised in one shot: the default floor loses
    /// to the agent, the agent loses to the image, the image loses to the
    /// operator, and `HOME` loses to nobody.
    #[test]
    fn later_layers_replace_earlier_ones_rather_than_shadowing_them() {
        let image = ImageRuntimeConfig {
            argv: Vec::new(),
            env: vec!["PATH=/image".to_string(), "A=image".to_string()],
            working_dir: None,
        };
        let env = WorkloadEnvironment::builder()
            .inherit([("PATH", "/agent"), ("A", "agent"), ("B", "agent")])
            .image(&image)
            .overrides([("A", "operator")])
            .build();

        assert_eq!(value(&env, "PATH").as_deref(), Some("/image"));
        assert_eq!(value(&env, "A").as_deref(), Some("operator"));
        assert_eq!(value(&env, "B").as_deref(), Some("agent"));
        assert_eq!(
            value(&env, "HOME").as_deref(),
            Some(crate::guest_mount::workload_home())
        );

        // One entry per name. `execve` accepts a block with a repeated name
        // and `getenv` answers with the first, so an override that appended
        // instead of replacing would be a silent no-op.
        let names: Vec<String> = pairs(&env).into_iter().map(|(k, _)| k).collect();
        let mut deduped = names.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(names.len(), deduped.len(), "repeated name in {names:?}");
    }

    #[test]
    fn an_image_declaring_no_path_still_gets_one() {
        let env = WorkloadEnvironment::builder().build();
        assert_eq!(value(&env, "PATH").as_deref(), Some(DEFAULT_PATH));
    }

    #[test]
    fn a_declared_path_is_never_replaced_by_the_default() {
        let image = ImageRuntimeConfig {
            argv: Vec::new(),
            env: vec!["PATH=/only/here".to_string()],
            working_dir: None,
        };
        let env = WorkloadEnvironment::builder().image(&image).build();
        assert_eq!(value(&env, "PATH").as_deref(), Some("/only/here"));
    }

    #[test]
    fn term_is_set_only_for_an_interactive_session() {
        assert!(value(&WorkloadEnvironment::builder().build(), "TERM").is_none());
        assert_eq!(
            value(
                &WorkloadEnvironment::builder().interactive().build(),
                "TERM"
            )
            .as_deref(),
            Some(INTERACTIVE_TERM)
        );
    }

    #[test]
    fn unrepresentable_overrides_are_dropped_not_truncated() {
        let env = WorkloadEnvironment::builder()
            .overrides([
                ("", "empty name"),
                ("HAS=EQUALS", "v"),
                ("HAS\0NUL", "v"),
                ("OK", "has\0nul"),
                ("GOOD", "kept"),
            ])
            .build();
        let names: Vec<String> = pairs(&env).into_iter().map(|(k, _)| k).collect();
        assert!(names.contains(&"GOOD".to_string()));
        for rejected in ["", "HAS=EQUALS", "HAS\0NUL", "OK"] {
            assert!(!names.contains(&rejected.to_string()), "{names:?}");
        }
    }

    /// An empty `WorkingDir` is how images spell "unset"; treating it as a
    /// path would `chdir("")` and fail.
    #[test]
    fn an_empty_working_dir_reads_as_absent() {
        let image = ImageRuntimeConfig {
            argv: Vec::new(),
            env: Vec::new(),
            working_dir: Some(String::new()),
        };
        assert_eq!(image.working_dir(), None);
        assert!(image.is_empty());
        let env = WorkloadEnvironment::builder().image(&image).build();
        assert_eq!(
            env.working_dir(),
            std::ffi::OsStr::new(crate::guest_mount::workload_home())
        );
    }

    /// The regression that started this: an image declaring `Env` and no
    /// command must not read as empty, or materialization writes nothing and
    /// both consumers lose the image's `PATH`.
    #[test]
    fn env_without_argv_is_not_an_empty_config() {
        let image = ImageRuntimeConfig {
            argv: Vec::new(),
            env: vec!["PATH=/usr/local/cargo/bin".to_string()],
            working_dir: None,
        };
        assert!(!image.is_empty());
    }

    #[test]
    fn a_missing_config_is_an_empty_config_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let config = ImageRuntimeConfig::load_from(&dir.path().join("absent.json")).unwrap();
        assert_eq!(config, ImageRuntimeConfig::default());
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image-runtime.json");
        std::fs::write(&path, br#"{"argv":["sh"],"surprise":1}"#).unwrap();
        assert!(ImageRuntimeConfig::load_from(&path).is_err());
    }

    #[test]
    fn config_round_trips_through_the_materialized_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image-runtime.json");
        let config = ImageRuntimeConfig {
            argv: vec!["bash".to_string()],
            env: vec!["PATH=/usr/local/cargo/bin".to_string()],
            working_dir: Some("/usr/src/app".to_string()),
        };
        std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert_eq!(ImageRuntimeConfig::load_from(&path).unwrap(), config);
    }

    /// Both ways into a workload resolve the same image the same way. The
    /// console adds the agent's vars and a `TERM`; everything the image
    /// declared must be identical, which is the property that was missing.
    #[test]
    fn the_console_and_the_entrypoint_agree_on_what_the_image_declared() {
        let image = ImageRuntimeConfig {
            argv: vec!["bash".to_string()],
            env: vec![
                "PATH=/usr/local/cargo/bin:/usr/bin".to_string(),
                "CARGO_HOME=/usr/local/cargo".to_string(),
            ],
            working_dir: Some("/usr/src/app".to_string()),
        };
        let entrypoint = WorkloadEnvironment::builder().image(&image).build();
        let console = WorkloadEnvironment::builder()
            .inherit([("PATH", "/agent/bin"), ("AGENT_ONLY", "1")])
            .image(&image)
            .interactive()
            .build();

        for key in ["PATH", "CARGO_HOME", "HOME"] {
            assert_eq!(
                value(&entrypoint, key),
                value(&console, key),
                "{key} differs between the entrypoint and console paths"
            );
        }
        assert_eq!(entrypoint.working_dir(), console.working_dir());
        assert_eq!(value(&console, "AGENT_ONLY").as_deref(), Some("1"));
        assert!(value(&entrypoint, "AGENT_ONLY").is_none());
    }
}
