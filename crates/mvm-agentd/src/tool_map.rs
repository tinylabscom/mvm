//! Declared-command mediation state shared by the in-guest shim, the tool
//! helper, and the activation-time installer.
//!
//! When the admitted plan declares a tool with an exact executable path, the
//! guest init substitutes every runnable path to those bytes with the
//! `mvm-tool-shim` client and stashes the original bytes in a directory only
//! the tool helper's identity can read. From then on the workload cannot run
//! the tool itself: any path to the bytes reaches the shim, the shim relays
//! the exact invocation to the helper over a guest-local socket, and the
//! helper asks the host to decide the invocation before it will exec the
//! stash — as [`crate::guest_mount::TOOL_UID`]/[`crate::guest_mount::TOOL_GID`]
//! in a fresh session, attributed to the host-minted binding when the tool's
//! routes or secrets scope the endpoint.
//!
//! Three identities read this module. The shim is untrusted: it reports its
//! own path, argv, cwd and environment honestly but is believed only where the
//! kernel can corroborate it. The helper trusts nothing the shim says except
//! what `SO_PEERCRED` proves. The map file itself is written by PID 1 from the
//! activation message after that message's digest was matched against the
//! boot-pinned signed grant, and is readable only by root and the helper's
//! identity — the workload never sees which paths lead where, only that they
//! run.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Directory holding the helper socket and the shim client copy.
pub const TOOL_DIR: &str = "/run/mvm-tool";
/// The helper's guest-local listening socket, inside [`TOOL_DIR`].
pub const HELPER_SOCKET: &str = "/run/mvm-tool/helper.sock";
/// Root-only stash of the substituted tools' original bytes.
pub const STASH_DIR: &str = "/run/mvm/toolstash";
/// The installed map, written by PID 1 and read by the helper at startup.
pub const TOOL_MAP_PATH: &str = "/run/mvm-tool/map.json";

/// Largest map file the helper will read.
pub const MAX_MAP_BYTES: u64 = 64 * 1024;
/// Largest shim request or helper reply line either side will read.
pub const MAX_SHIM_FRAME_BYTES: u64 = 256 * 1024;
/// Largest helper-to-agent decision frame either side will read.
pub const MAX_DECISION_FRAME_BYTES: u64 = 4 * 1024;
/// Refuse to substitute a declared tool reached through more alias paths than
/// this: a pathological image turns the boot into a mount-table denial of
/// service long before the workload runs.
pub const MAX_ALIASES_PER_TOOL: usize = 1024;

/// Exit code the shim uses when the host denied the invocation.
pub const EXIT_DENIED: i32 = 126;
/// Exit code the shim uses when the helper (or the decision transport) is
/// unavailable, so a broken mediation path never masquerades as the tool.
pub const EXIT_UNAVAILABLE: i32 = 125;
/// Exit code when the helper could not exec the verified stash.
pub const EXIT_SPAWN: i32 = 127;

/// One declared tool's substituted executable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolEntry {
    /// Name in the admitted plan's tool rules.
    pub tool: String,
    /// The exact path the signed plan declared.
    pub executable: String,
    /// Every additional image path substituted with the shim because it
    /// resolves to the same bytes: hard links, symlinks to the same file, and
    /// content-identical copies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// Helper-readable copy of the original bytes. Executed only after the
    /// digest verified against [`Self::digest`], and only by the helper.
    pub stash: String,
    /// Lowercase hex sha256 of the original bytes.
    pub digest: String,
}

impl ToolEntry {
    /// Every path the shim is mounted at for this tool, declared first.
    pub fn paths(&self) -> impl Iterator<Item = &String> {
        std::iter::once(&self.executable).chain(self.aliases.iter())
    }

    /// Whether `path` is one of this tool's substituted paths.
    #[must_use]
    pub fn substitutes(&self, path: &str) -> bool {
        self.paths().any(|candidate| candidate == path)
    }
}

/// How the helper resolves one shim invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch<'a> {
    /// The invocation names this tool: ask the host, then run the stash as
    /// the tool identity in a fresh session.
    Mediate(&'a ToolEntry),
    /// The bytes are a shared binary (busybox-style) invoked under a name
    /// that is not the declared tool: run the stash with the caller's own
    /// identity, no host decision.
    Direct(&'a ToolEntry),
    /// The shim is running at a path the map does not know: refuse.
    Unknown,
}

/// The installed tool map, written at activation and loaded by the helper.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolMap {
    #[serde(default)]
    pub tools: Vec<ToolEntry>,
}

/// A map failed its structural validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MapError {
    #[error("tool map is not valid JSON: {0}")]
    Json(String),
    #[error("tool map entry is invalid: {0}")]
    Entry(String),
    #[error("tool map exceeds the {MAX_MAP_BYTES}-byte bound")]
    TooLarge,
}

impl ToolMap {
    /// Parse and structurally validate a map. Content trust comes from the
    /// activation-time digest match against the signed grant; this refuses
    /// shape breakage so a corrupt map fails closed instead of being acted
    /// on.
    pub fn load(bytes: &[u8]) -> Result<Self, MapError> {
        if bytes.len() as u64 > MAX_MAP_BYTES {
            return Err(MapError::TooLarge);
        }
        let parsed: Self =
            serde_json::from_slice(bytes).map_err(|error| MapError::Json(error.to_string()))?;
        parsed.validate()?;
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), MapError> {
        let mut tool_names = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for entry in &self.tools {
            if entry.tool.is_empty()
                || entry.tool.len()
                    > mvm_contract::protocol::network_flow::tool::MAX_TOOL_NAME_BYTES
                || entry.tool.contains('\0')
            {
                return Err(MapError::Entry(format!(
                    "tool name {:?} is not a valid tool identity",
                    entry.tool
                )));
            }
            if !tool_names.insert(entry.tool.as_str()) {
                return Err(MapError::Entry(format!(
                    "tool {:?} is listed more than once",
                    entry.tool
                )));
            }
            for path in entry.paths() {
                if path.is_empty() || path.len() > 4096 || !path.starts_with('/') {
                    return Err(MapError::Entry(format!(
                        "path {path:?} is not an absolute guest path"
                    )));
                }
                // Absolute paths lead with an empty first component; the
                // check is about empty *middle* components (`/bin//sh`).
                if path.contains('\0') || path[1..].split('/').any(|part| part.is_empty()) {
                    return Err(MapError::Entry(format!("path {path:?} is malformed")));
                }
                if !paths.insert(path.as_str()) {
                    return Err(MapError::Entry(format!(
                        "path {path:?} is substituted for more than one tool"
                    )));
                }
            }
            if entry.stash.len() as u64 > MAX_MAP_BYTES || !entry.stash.starts_with('/') {
                return Err(MapError::Entry(format!(
                    "stash path {:?} is not an absolute guest path",
                    entry.stash
                )));
            }
            if !is_lower_hex(&entry.digest) || entry.digest.len() != 64 {
                return Err(MapError::Entry(format!(
                    "digest for tool {:?} is not 64 lowercase hex chars",
                    entry.tool
                )));
            }
            if entry.aliases.len() > MAX_ALIASES_PER_TOOL {
                return Err(MapError::Entry(format!(
                    "tool {:?} has more than {MAX_ALIASES_PER_TOOL} alias paths",
                    entry.tool
                )));
            }
        }
        Ok(())
    }

    /// The entry whose substituted path is `path`.
    #[must_use]
    pub fn by_path(&self, path: &str) -> Option<&ToolEntry> {
        self.tools.iter().find(|entry| entry.substitutes(path))
    }

    /// Resolve one shim invocation.
    ///
    /// The tool identity is chosen from the path the kernel used to reach the
    /// shim, never from anything the caller wrote: `argv[0]` is attacker
    /// controlled, so it only ever escalates mediation (claiming the declared
    /// tool's name routes through the host gate) and never skips it. A shared
    /// binary substituted for a declared tool keeps its other applet names
    /// working by running the stash directly with the caller's identity.
    #[must_use]
    pub fn dispatch(&self, exe: &str, argv0: Option<&str>) -> Dispatch<'_> {
        let Some(entry) = self.by_path(exe) else {
            return Dispatch::Unknown;
        };
        let claimed = argv0
            .and_then(|value| value.rsplit('/').next())
            .filter(|value| !value.is_empty());
        let declared = entry
            .executable
            .rsplit('/')
            .next()
            .unwrap_or(&entry.executable);
        match claimed {
            Some(claimed) if claimed == declared => Dispatch::Mediate(entry),
            _ => Dispatch::Direct(entry),
        }
    }
}

/// Whether `text` is lowercase hexadecimal.
#[must_use]
pub fn is_lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Environment variables a mediated tool must not inherit: the dynamic
/// loader and resolver knobs that turn a verified binary into arbitrary code
/// or DNS forgery running as the tool identity.
#[must_use]
pub fn is_dangerous_loader_var(key: &str) -> bool {
    key.starts_with("LD_")
        || matches!(
            key,
            "HOSTALIASES"
                | "RES_OPTIONS"
                | "LOCALDOMAIN"
                | "NLSPATH"
                | "LOCPATH"
                | "MALLOC_TRACE"
                | "MALLOC_CHECK_"
        )
}

/// `env` with [`is_dangerous_loader_var`] entries removed.
#[must_use]
pub fn sanitized_tool_env(env: &[(String, String)]) -> Vec<(String, String)> {
    env.iter()
        .filter(|(key, _)| !is_dangerous_loader_var(key))
        .cloned()
        .collect()
}

/// One shim-to-helper request, sent as a single bounded JSON line with the
/// shim's descriptors 0, 1 and 2 attached out of band.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShimRequest {
    /// The shim's own executable path — the substituted path the kernel used
    /// to reach it. The helper maps this to the tool; the workload cannot
    /// choose a tool identity because it cannot choose which substituted path
    /// it ran.
    pub exe: String,
    /// The invocation exactly as the workload made it.
    pub argv: Vec<String>,
    /// The shim's working directory, applied to the tool.
    pub cwd: String,
    /// The shim's environment. The helper sanitizes it before a mediated
    /// spawn and passes it through unchanged for a direct one.
    pub env: Vec<(String, String)>,
}

/// The helper's one final reply. While the tool runs, its stdio flows over
/// the attached descriptors, not this connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HelperReply {
    /// The tool exited with `code`.
    Exited {
        /// The tool's wait status, shifted as a plain exit code.
        code: i32,
    },
    /// The host refused the invocation; the shim prints `reason` to stderr.
    Denied {
        /// Safe host-authored reason, never command text.
        reason: String,
    },
    /// Mediation is unavailable (helper has no map, no broker, no endpoint);
    /// the shim prints `reason` to stderr.
    Unavailable {
        /// Safe reason.
        reason: String,
    },
}

/// One helper-to-agent request on the agent's decision socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DecisionRequest {
    /// Consume the host decision the agent recorded when it spawned this
    /// MediatedExec relay. Keyed by the shim's kernel-authenticated pid; the
    /// agent re-validates liveness and start time, so a recycled pid cannot
    /// inherit a decision. Single use.
    Decided {
        /// The shim's pid, from `SO_PEERCRED` of the helper's shim socket.
        pid: u32,
    },
    /// Record a helper-spawned tool session for loopback egress attribution.
    Record {
        /// The tool's session id, equal to its pid.
        session: u32,
        /// The host-minted binding for a scoped tool, if any.
        binding: Option<mvm_contract::protocol::network_flow::attribution::ToolInvocationBinding>,
    },
    /// Retire a recorded session after its tool has exited.
    Retire {
        /// The session id recorded earlier.
        session: u32,
    },
}

/// The agent's answer to one [`DecisionRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum DecisionReply {
    /// The pid carried a recorded host decision, consumed by this answer.
    Decided {
        /// The binding from the host decision, if the tool scopes the
        /// endpoint.
        binding: Option<mvm_contract::protocol::network_flow::attribution::ToolInvocationBinding>,
    },
    /// No live decision for that pid.
    NotDecided,
    /// The request ran.
    Ok,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tool: &str, executable: &str, aliases: &[&str]) -> ToolEntry {
        ToolEntry {
            tool: tool.into(),
            executable: executable.into(),
            aliases: aliases.iter().map(ToString::to_string).collect(),
            stash: format!("/run/mvm/toolstash/{}", "a".repeat(64)),
            digest: "b".repeat(64),
        }
    }

    fn map(entries: Vec<ToolEntry>) -> ToolMap {
        ToolMap { tools: entries }
    }

    #[test]
    fn dispatch_mediates_the_declared_name_and_only_it() {
        let tools = map(vec![entry(
            "shell",
            "/bin/sh",
            &["/bin/busybox", "/bin/ash"],
        )]);

        // Reached through the declared path with the declared name.
        assert!(matches!(
            tools.dispatch("/bin/sh", Some("/bin/sh")),
            Dispatch::Mediate(_)
        ));
        // Reached through a shared-binary alias while claiming the declared
        // name: fail closed into mediation.
        assert!(matches!(
            tools.dispatch("/bin/busybox", Some("sh")),
            Dispatch::Mediate(_)
        ));
        assert!(matches!(
            tools.dispatch("/bin/busybox", Some("/bin/sh")),
            Dispatch::Mediate(_)
        ));
        // The same bytes under a non-tool applet name run directly.
        assert!(matches!(
            tools.dispatch("/bin/busybox", Some("ls")),
            Dispatch::Direct(_)
        ));
        assert!(matches!(
            tools.dispatch("/bin/ash", Some("ash")),
            Dispatch::Direct(_)
        ));
        // No argv0 at all cannot claim the tool.
        assert!(matches!(
            tools.dispatch("/bin/sh", None),
            Dispatch::Direct(_)
        ));
        // A path the map does not know is refused.
        assert!(matches!(
            tools.dispatch("/tmp/sh", Some("sh")),
            Dispatch::Unknown
        ));
    }

    #[test]
    fn map_load_validates_shape_and_uniqueness() {
        let tools = map(vec![entry("shell", "/bin/sh", &["/bin/busybox"])]);
        let bytes = serde_json::to_vec(&tools).expect("serialize");
        let loaded = ToolMap::load(&bytes).expect("valid map loads");
        assert_eq!(loaded, tools);

        let mut duplicate_tool = tools.clone();
        duplicate_tool.tools.push(entry("shell", "/bin/zsh", &[]));
        assert!(ToolMap::load(&serde_json::to_vec(&duplicate_tool).unwrap()).is_err());

        let mut duplicate_path = tools.clone();
        duplicate_path
            .tools
            .push(entry("other", "/bin/other", &["/bin/sh"]));
        assert!(ToolMap::load(&serde_json::to_vec(&duplicate_path).unwrap()).is_err());

        let mut bad_digest = tools.clone();
        bad_digest.tools[0].digest = "not-hex".into();
        assert!(ToolMap::load(&serde_json::to_vec(&bad_digest).unwrap()).is_err());

        let mut relative = tools.clone();
        relative.tools[0].executable = "bin/sh".into();
        assert!(ToolMap::load(&serde_json::to_vec(&relative).unwrap()).is_err());

        assert!(ToolMap::load(&[b'x'; 70 * 1024]).is_err());
        assert!(ToolMap::load(b"{not json").is_err());
    }

    #[test]
    fn loader_variables_are_stripped_and_others_kept() {
        assert!(is_dangerous_loader_var("LD_PRELOAD"));
        assert!(is_dangerous_loader_var("LD_LIBRARY_PATH"));
        assert!(is_dangerous_loader_var("LD_AUDIT"));
        assert!(is_dangerous_loader_var("HOSTALIASES"));
        assert!(!is_dangerous_loader_var("PATH"));
        assert!(!is_dangerous_loader_var("OPENAI_BASE_URL"));

        let cleaned = sanitized_tool_env(&[
            ("PATH".into(), "/bin".into()),
            ("LD_PRELOAD".into(), "/tmp/evil.so".into()),
            ("LD_AUDIT".into(), "/tmp/audit.so".into()),
            ("TOKEN".into(), "placeholder".into()),
        ]);
        assert_eq!(
            cleaned,
            vec![
                ("PATH".into(), "/bin".into()),
                ("TOKEN".into(), "placeholder".into()),
            ]
        );
    }

    #[test]
    fn wire_types_round_trip_and_reject_unknown_fields() {
        let request = ShimRequest {
            exe: "/bin/sh".into(),
            argv: vec!["sh".into(), "-c".into(), "echo ok".into()],
            cwd: "/work".into(),
            env: vec![("PATH".into(), "/bin".into())],
        };
        let bytes = serde_json::to_vec(&request).expect("serialize");
        let round: ShimRequest = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(round, request);
        assert!(
            serde_json::from_value::<ShimRequest>(serde_json::json!({
                "exe": "/bin/sh", "argv": [], "cwd": "/", "env": [], "extra": 1
            }))
            .is_err()
        );

        let decided = DecisionReply::Decided { binding: None };
        let round: DecisionReply =
            serde_json::from_slice(&serde_json::to_vec(&decided).unwrap()).unwrap();
        assert_eq!(round, decided);
    }
}
