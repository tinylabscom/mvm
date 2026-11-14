//! Resolve operator-supplied CLI options before the ordinary clap parse.
//!
//! This layer only supplies argv. Clap remains the owner of value parsing,
//! conflicts, required arguments, and the downstream command dispatch.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, ArgMatches, Command, error::ErrorKind};
use serde_json::{Map, Value};

type Options = BTreeMap<String, Vec<String>>;

fn canonical(arg: &Arg) -> String {
    arg.get_long()
        .map(str::to_string)
        .unwrap_or_else(|| arg.get_id().as_str().replace('_', "-"))
}

fn is_option(arg: &Arg) -> bool {
    arg.get_long().is_some() || arg.get_short().is_some()
}

struct Scope<'a> {
    command: &'a Command,
    name: String,
    insert_at: usize,
    explicit: BTreeSet<String>,
}

struct Scan<'a> {
    scopes: Vec<Scope<'a>>,
    files: Vec<PathBuf>,
    removed: BTreeSet<usize>,
    rewritten: BTreeMap<usize, OsString>,
    global_explicit: Vec<OsString>,
}

fn error(command: &Command, message: impl std::fmt::Display) -> clap::Error {
    command
        .clone()
        .error(ErrorKind::ValueValidation, message.to_string())
}

fn option<'a>(command: &'a Command, name: &str, aliases: bool) -> Option<&'a Arg> {
    command.get_arguments().find(|arg| {
        (is_option(arg) && canonical(arg) == name)
            || (aliases && arg.get_all_aliases().is_some_and(|a| a.contains(&name)))
    })
}

fn find_option<'a>(scopes: &'a [Scope<'a>], name: &str) -> Option<(usize, &'a Arg)> {
    scopes
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, scope)| option(scope.command, name, true).map(|arg| (index, arg)))
}

fn short_option<'a>(scopes: &'a [Scope<'a>], short: char) -> Option<(usize, &'a Arg)> {
    scopes.iter().enumerate().rev().find_map(|(index, scope)| {
        scope.command.get_arguments().find_map(|arg| {
            (arg.get_short() == Some(short)
                || arg
                    .get_all_short_aliases()
                    .is_some_and(|a| a.contains(&short)))
            .then_some((index, arg))
        })
    })
}

fn takes_value(arg: &Arg) -> bool {
    !matches!(
        arg.get_action(),
        ArgAction::SetTrue
            | ArgAction::SetFalse
            | ArgAction::Count
            | ArgAction::Help
            | ArgAction::HelpShort
            | ArgAction::HelpLong
            | ArgAction::Version
    )
}

// Only an explicit command token selects a scope. In particular, a file cannot
// select a command by setting a "command" key.
fn scan<'a>(root: &'a Command, argv: &[OsString]) -> Scan<'a> {
    let mut scopes = vec![Scope {
        command: root,
        name: String::new(),
        insert_at: 1,
        explicit: BTreeSet::new(),
    }];
    let mut files = Vec::new();
    let mut removed = BTreeSet::new();
    let mut rewritten = BTreeMap::new();
    let mut global_explicit = Vec::new();
    let mut after_separator = false;
    let mut i = 1;
    while i < argv.len() {
        let Some(token) = argv[i].to_str() else {
            i += 1;
            continue;
        };
        if token == "--" {
            after_separator = true;
            i += 1;
            continue;
        }
        if after_separator {
            i += 1;
            continue;
        }
        if let Some(flag) = token.strip_prefix("--") {
            let (name, attached) = flag
                .split_once('=')
                .map_or((flag, None), |(a, b)| (a, Some(b)));
            if let Some((index, arg)) = find_option(&scopes, name) {
                let id = arg.get_id().to_string();
                let consumes_value = takes_value(arg);
                if arg.is_global_set() && id != "config_file" {
                    removed.insert(i);
                    global_explicit.push(argv[i].clone());
                    if attached.is_none()
                        && consumes_value
                        && let Some(value) = argv.get(i + 1)
                    {
                        removed.insert(i + 1);
                        global_explicit.push(value.clone());
                    }
                }
                scopes[index].explicit.insert(id.clone());
                if id == "config_file" {
                    if let Some(path) = attached {
                        files.push(PathBuf::from(path));
                    } else if let Some(path) = argv.get(i + 1) {
                        files.push(PathBuf::from(path));
                    }
                }
                if attached.is_none() && consumes_value && argv.get(i + 1).is_some() {
                    i += 1;
                }
            }
        } else if token.starts_with('-') && token.len() > 1 {
            let mut chars = token[1..].chars().peekable();
            let mut kept = String::from("-");
            let mut moved = false;
            while let Some(short) = chars.next() {
                if let Some((index, arg)) = short_option(&scopes, short) {
                    let id = arg.get_id().to_string();
                    let consumes_value = takes_value(arg);
                    let global = arg.is_global_set() && id != "config_file";
                    if global {
                        moved = true;
                        global_explicit.push(OsString::from(format!("-{short}")));
                    } else {
                        kept.push(short);
                    }
                    scopes[index].explicit.insert(id);
                    if consumes_value {
                        if chars.peek().is_none() && argv.get(i + 1).is_some() {
                            if global {
                                removed.insert(i + 1);
                                global_explicit.push(argv[i + 1].clone());
                            }
                            i += 1;
                        } else if global {
                            global_explicit.push(OsString::from(chars.collect::<String>()));
                        } else {
                            kept.extend(chars);
                        }
                        break;
                    }
                } else {
                    kept.push(short);
                }
            }
            if moved {
                if kept == "-" {
                    removed.insert(i);
                } else {
                    rewritten.insert(i, OsString::from(kept));
                }
            }
        } else if let Some(sub) = scopes.last().and_then(|scope| {
            scope
                .command
                .get_subcommands()
                .find(|c| c.get_name() == token || c.get_all_aliases().any(|a| a == token))
        }) {
            scopes.push(Scope {
                command: sub,
                name: sub.get_name().to_string(),
                insert_at: i + 1,
                explicit: BTreeSet::new(),
            });
        }
        i += 1;
    }
    Scan {
        scopes,
        files,
        removed,
        rewritten,
        global_explicit,
    }
}

fn document(path: &Path, root: &Command) -> Result<Map<String, Value>, clap::Error> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| error(root, format!("reading {}: {e}", path.display())))?;
    let value: Value = match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => serde_json::from_str(&text)
            .map_err(|e| error(root, format!("parsing {}: {e}", path.display())))?,
        Some("toml") => {
            let value: toml::Value = toml::from_str(&text)
                .map_err(|e| error(root, format!("parsing {}: {e}", path.display())))?;
            serde_json::to_value(value)
                .map_err(|e| error(root, format!("parsing {}: {e}", path.display())))?
        }
        _ => {
            return Err(error(
                root,
                format!("{}: expected .toml or .json", path.display()),
            ));
        }
    };
    value
        .as_object()
        .cloned()
        .ok_or_else(|| error(root, format!("{}: expected a table/object", path.display())))
}

fn values(
    arg: &Arg,
    value: &Value,
    label: &str,
    root: &Command,
) -> Result<Vec<String>, clap::Error> {
    let invalid = || {
        error(
            root,
            format!("{label}: incompatible value for {}", canonical(arg)),
        )
    };
    match arg.get_action() {
        ArgAction::SetTrue | ArgAction::SetFalse => {
            let enabled = value.as_bool().ok_or_else(invalid)?;
            let present = if matches!(arg.get_action(), ArgAction::SetTrue) {
                enabled
            } else {
                !enabled
            };
            Ok(if present {
                vec![String::new()]
            } else {
                Vec::new()
            })
        }
        ArgAction::Count => {
            let count = value
                .as_u64()
                .filter(|n| *n <= u8::MAX as u64)
                .ok_or_else(invalid)?;
            Ok(vec![String::new(); count as usize])
        }
        ArgAction::Append => {
            let items = value.as_array().ok_or_else(invalid)?;
            items
                .iter()
                .map(|v| scalar(v).ok_or_else(invalid))
                .collect()
        }
        ArgAction::Set => Ok(vec![scalar(value).ok_or_else(invalid)?]),
        _ => Err(error(
            root,
            format!(
                "{label}: {} cannot be supplied by configuration",
                canonical(arg)
            ),
        )),
    }
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn options(
    table: &Map<String, Value>,
    scope: &Scope<'_>,
    label: &str,
    root: &Command,
) -> Result<Options, clap::Error> {
    let mut result = Options::new();
    for (key, value) in table {
        let arg = option(scope.command, key, false)
            .filter(|arg| is_option(arg) && arg.get_id() != "config_file")
            .ok_or_else(|| {
                error(
                    root,
                    format!("{label}: unknown option {key:?} in {}", scope.name),
                )
            })?;
        result.insert(arg.get_id().to_string(), values(arg, value, label, root)?);
    }
    Ok(result)
}

fn tables(
    value: &Map<String, Value>,
    scopes: &[Scope<'_>],
    label: &str,
    root: &Command,
) -> Result<Vec<Options>, clap::Error> {
    let mut result = vec![Options::new(); scopes.len()];
    for (key, table) in value {
        match key.as_str() {
            "global" => {
                let map = table
                    .as_object()
                    .ok_or_else(|| error(root, format!("{label}: global must be a table")))?;
                result[0] = options(map, &scopes[0], label, root)?;
            }
            "commands" => {
                let map = table
                    .as_object()
                    .ok_or_else(|| error(root, format!("{label}: commands must be a table")))?;
                command_tables(
                    map,
                    root,
                    1,
                    true,
                    &mut TableResolution {
                        scopes,
                        result: &mut result,
                        label,
                        root,
                    },
                )?;
            }
            _ => {
                return Err(error(
                    root,
                    format!("{label}: unknown top-level key {key:?}"),
                ));
            }
        }
    }
    Ok(result)
}

struct TableResolution<'a, 'b> {
    scopes: &'b [Scope<'a>],
    result: &'b mut [Options],
    label: &'b str,
    root: &'a Command,
}

fn command_tables(
    map: &Map<String, Value>,
    command: &Command,
    depth: usize,
    parent_selected: bool,
    target: &mut TableResolution<'_, '_>,
) -> Result<(), clap::Error> {
    for (name, value) in map {
        let selected = parent_selected && target.scopes.get(depth).is_some_and(|s| s.name == *name);
        let child = command
            .get_subcommands()
            .find(|sub| sub.get_name() == name)
            .ok_or_else(|| {
                error(
                    target.root,
                    format!("{}: unknown command {name:?}", target.label),
                )
            })?;
        let entries = value.as_object().ok_or_else(|| {
            error(
                target.root,
                format!("{}: command {name:?} must be a table", target.label),
            )
        })?;
        let mut own = Map::new();
        let mut nested = Map::new();
        for (key, value) in entries {
            if child.get_subcommands().any(|c| c.get_name() == key) {
                nested.insert(key.clone(), value.clone());
            } else {
                own.insert(key.clone(), value.clone());
            }
        }
        let scope = Scope {
            command: child,
            name: name.clone(),
            insert_at: 0,
            explicit: BTreeSet::new(),
        };
        let validated = options(&own, &scope, target.label, target.root)?;
        if selected {
            target.result[depth] = validated;
        }
        if !nested.is_empty() {
            command_tables(&nested, child, depth + 1, selected, target)?;
        }
    }
    Ok(())
}

fn env_name(depth: usize, arg: &Arg, scopes: &[Scope<'_>]) -> String {
    let mut parts = vec!["MVMCTL".to_string()];
    for item in scopes.iter().take(depth + 1).skip(1) {
        parts.push(item.name.replace('-', "_").to_ascii_uppercase());
    }
    parts.push(canonical(arg).replace('-', "_").to_ascii_uppercase());
    parts.join("_")
}

fn environment(
    scopes: &[Scope<'_>],
    files: &[Vec<Options>],
    root: &Command,
) -> Result<Vec<Options>, clap::Error> {
    let mut result = Vec::new();
    for (index, scope) in scopes.iter().enumerate() {
        let mut options = Options::new();
        for arg in scope
            .command
            .get_arguments()
            .filter(|a| is_option(a) && a.get_id() != "config_file")
        {
            if !matches!(arg.get_action(), ArgAction::Append | ArgAction::Count)
                && (scope.explicit.contains(arg.get_id().as_str())
                    || files
                        .iter()
                        .any(|file| file[index].contains_key(arg.get_id().as_str())))
            {
                continue;
            }
            let name = env_name(index, arg, scopes);
            let Some(raw) = std::env::var_os(&name) else {
                continue;
            };
            let raw = raw
                .into_string()
                .map_err(|_| error(root, format!("{name}: expected UTF-8")))?;
            let value = match arg.get_action() {
                ArgAction::Append if raw.starts_with('[') => serde_json::from_str::<Value>(&raw)
                    .map_err(|e| error(root, format!("{name}: invalid JSON array: {e}")))?,
                ArgAction::Append => Value::Array(vec![Value::String(raw)]),
                ArgAction::SetTrue | ArgAction::SetFalse => Value::Bool(match raw.as_str() {
                    "true" | "1" => true,
                    "false" | "0" => false,
                    _ => return Err(error(root, format!("{name}: expected true or false"))),
                }),
                ArgAction::Count => Value::Number(
                    raw.parse::<u64>()
                        .map_err(|_| error(root, format!("{name}: expected a nonnegative count")))?
                        .into(),
                ),
                _ => Value::String(raw),
            };
            options.insert(arg.get_id().to_string(), values(arg, &value, &name, root)?);
        }
        result.push(options);
    }
    Ok(result)
}

/// Feed merged options into the ordinary Clap parser without changing its validation.
pub(super) fn resolve(
    root: Command,
    argv: impl IntoIterator<Item = OsString>,
) -> Result<ArgMatches, clap::Error> {
    let argv: Vec<OsString> = argv.into_iter().collect();
    let Scan {
        scopes,
        files,
        removed,
        rewritten,
        global_explicit,
    } = scan(&root, &argv);
    // Help and version must work even when the environment or a file is invalid.
    if argv
        .iter()
        .any(|a| a == "--help" || a == "-h" || a == "--version")
    {
        return root.try_get_matches_from(argv);
    }
    let mut layers = Vec::new();
    for path in files {
        let map = document(&path, &root)?;
        layers.push(tables(&map, &scopes, &path.display().to_string(), &root)?);
    }
    let environment = environment(&scopes, &layers, &root)?;
    layers.insert(0, environment);
    let mut injections: BTreeMap<usize, Vec<OsString>> = BTreeMap::new();
    for (index, scope) in scopes.iter().enumerate() {
        for arg in scope
            .command
            .get_arguments()
            .filter(|a| is_option(a) && a.get_id() != "config_file")
        {
            let id = arg.get_id().as_str();
            let repeatable = matches!(arg.get_action(), ArgAction::Append | ArgAction::Count);
            let mut selected = Vec::new();
            for layer in &layers {
                if let Some(values) = layer[index].get(id) {
                    if repeatable {
                        selected.extend(values.iter().cloned());
                    } else {
                        selected = values.clone();
                    }
                }
            }
            if !repeatable && scope.explicit.contains(id) {
                continue;
            }
            // Clap propagates a global repeatable's last subcommand value back
            // to the root. Place its supplied values beside explicit leaf
            // flags so a count/append after the command is not lost.
            let at = if repeatable && arg.is_global_set() {
                scopes.last().map_or(scope.insert_at, |leaf| leaf.insert_at)
            } else {
                scope.insert_at
            };
            let output = injections.entry(at).or_default();
            for value in selected {
                let token = match (arg.get_long(), takes_value(arg)) {
                    (Some(long), true) => format!("--{long}={value}"),
                    (Some(long), false) => format!("--{long}"),
                    (None, true) => format!("-{}{value}", arg.get_short().unwrap_or_default()),
                    (None, false) => format!("-{}", arg.get_short().unwrap_or_default()),
                };
                output.push(OsString::from(token));
            }
        }
    }
    if !global_explicit.is_empty() {
        let at = scopes.last().map_or(1, |leaf| leaf.insert_at);
        injections.entry(at).or_default().extend(global_explicit);
    }
    let mut merged = Vec::new();
    let end = argv.len();
    for (index, token) in argv.into_iter().enumerate() {
        if let Some(values) = injections.remove(&index) {
            merged.extend(values);
        }
        if !removed.contains(&index) {
            merged.push(rewritten.get(&index).cloned().unwrap_or(token));
        }
    }
    if let Some(values) = injections.remove(&end) {
        merged.extend(values);
    }
    root.try_get_matches_from(merged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Arg, FromArgMatches};
    use mvm_core::util::test_env::TestEnv;

    fn isolated_env() -> TestEnv {
        let mut env = TestEnv::new();
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("MVMCTL_") {
                env.remove(key);
            }
        }
        env
    }

    fn command() -> Command {
        Command::new("mvmctl")
            .arg(
                Arg::new("config_file")
                    .long("config-file")
                    .global(true)
                    .action(ArgAction::Append),
            )
            .arg(
                Arg::new("verbose")
                    .long("verbose")
                    .short('v')
                    .global(true)
                    .action(ArgAction::Count),
            )
            .subcommand(
                Command::new("doctor")
                    .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
            )
            .subcommand(
                Command::new("machine").subcommand(
                    Command::new("run")
                        .arg(Arg::new("profile").long("profile").alias("posture"))
                        .arg(
                            Arg::new("allow_host")
                                .long("allow-host")
                                .action(ArgAction::Append),
                        )
                        .arg(Arg::new("net").long("net").action(ArgAction::SetTrue))
                        .arg(Arg::new("quiet").short('q').action(ArgAction::Count))
                        .arg(
                            Arg::new("step_checkpoints")
                                .long("no-step-checkpoints")
                                .action(ArgAction::SetFalse),
                        )
                        .arg(
                            Arg::new("no_build")
                                .long("no-build")
                                .action(ArgAction::SetTrue)
                                .conflicts_with("build"),
                        )
                        .arg(Arg::new("build").long("build").action(ArgAction::SetTrue)),
                ),
            )
    }

    fn parse(args: &[&str]) -> Result<ArgMatches, clap::Error> {
        resolve(command(), args.iter().map(OsString::from))
    }

    fn run(matches: &ArgMatches) -> &ArgMatches {
        matches
            .subcommand_matches("machine")
            .unwrap()
            .subcommand_matches("run")
            .unwrap()
    }

    #[test]
    fn three_sources_and_two_files_compose_at_option_granularity() {
        let mut env = isolated_env();
        env.set("MVMCTL_MACHINE_RUN_PROFILE", "env");
        env.set("MVMCTL_MACHINE_RUN_ALLOW_HOST", r#"["env.example"]"#);
        env.set("MVMCTL_VERBOSE", "1");
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("one.toml");
        let second = dir.path().join("two.json");
        std::fs::write(&first, "[global]\nverbose = 1\n[commands.machine.run]\nprofile = 'first'\nallow-host = ['first.example']\nnet = true\n").unwrap();
        std::fs::write(&second, r#"{"commands":{"machine":{"run":{"profile":"second","allow-host":["second.example"],"net":false}}}}"#).unwrap();
        let first = first.to_str().unwrap();
        let second = second.to_str().unwrap();
        let file_only = parse(&[
            "mvmctl",
            "machine",
            "run",
            "--config-file",
            first,
            "--config-file",
            second,
        ])
        .unwrap();
        assert_eq!(
            run(&file_only)
                .get_one::<String>("profile")
                .map(String::as_str),
            Some("second")
        );
        let matches = parse(&[
            "mvmctl",
            "--config-file",
            first,
            "machine",
            "run",
            "--config-file",
            second,
            "--posture",
            "explicit",
            "--allow-host",
            "flag.example",
            "-vv",
        ])
        .unwrap();
        assert_eq!(*matches.get_one::<u8>("verbose").unwrap(), 4);
        let run = run(&matches);
        assert_eq!(
            run.get_one::<String>("profile").map(String::as_str),
            Some("explicit")
        );
        assert_eq!(
            run.get_many::<String>("allow_host")
                .unwrap()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "env.example",
                "first.example",
                "second.example",
                "flag.example"
            ]
        );
        assert!(!run.get_flag("net"));
    }

    #[test]
    fn empty_lists_do_not_clear_and_false_cancels_true() {
        let mut env = isolated_env();
        env.set("MVMCTL_MACHINE_RUN_ALLOW_HOST", "env.example");
        env.set("MVMCTL_MACHINE_RUN_NET", "true");
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("opts.toml");
        std::fs::write(
            &file,
            "[commands.machine.run]\nallow-host = []\nnet = false\n",
        )
        .unwrap();
        let matches = parse(&[
            "mvmctl",
            "machine",
            "run",
            "--config-file",
            file.to_str().unwrap(),
        ])
        .unwrap();
        let run = run(&matches);
        assert_eq!(
            run.get_many::<String>("allow_host")
                .unwrap()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["env.example"]
        );
        assert!(!run.get_flag("net"));
    }

    #[test]
    fn short_only_counts_and_negative_boolean_flags_follow_the_same_rules() {
        let mut env = isolated_env();
        env.set("MVMCTL_MACHINE_RUN_QUIET", "1");
        env.set("MVMCTL_MACHINE_RUN_NO_STEP_CHECKPOINTS", "false");
        let env_only = parse(&["mvmctl", "machine", "run"]).unwrap();
        assert!(!run(&env_only).get_flag("step_checkpoints"));
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("opts.toml");
        std::fs::write(
            &file,
            "[commands.machine.run]\nquiet = 1\nno-step-checkpoints = true\n",
        )
        .unwrap();
        let matches = parse(&[
            "mvmctl",
            "machine",
            "run",
            "--config-file",
            file.to_str().unwrap(),
            "-q",
        ])
        .unwrap();
        let run = run(&matches);
        assert_eq!(*run.get_one::<u8>("quiet").unwrap(), 3);
        assert!(run.get_flag("step_checkpoints"));
    }

    #[test]
    fn overridden_invalid_environment_does_not_override_file_denial() {
        let mut env = isolated_env();
        env.set("MVMCTL_MACHINE_RUN_NET", "not-a-boolean");
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("opts.toml");
        std::fs::write(&file, "[commands.machine.run]\nnet = false\n").unwrap();
        let matches = parse(&[
            "mvmctl",
            "--config-file",
            file.to_str().unwrap(),
            "machine",
            "run",
        ])
        .unwrap();
        assert!(!run(&matches).get_flag("net"));
    }

    #[test]
    fn option_file_before_command_applies_at_end_of_argv() {
        let _env = isolated_env();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("opts.toml");
        std::fs::write(&file, "[commands.machine.run]\nnet = true\n").unwrap();
        let matches = parse(&[
            "mvmctl",
            "--config-file",
            file.to_str().unwrap(),
            "machine",
            "run",
        ])
        .unwrap();
        assert!(run(&matches).get_flag("net"));
    }

    #[test]
    fn values_starting_with_hyphens_remain_values() {
        let _env = isolated_env();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("opts.toml");
        std::fs::write(&file, "[commands.machine.run]\nprofile = '--literal'\n").unwrap();
        let matches = parse(&[
            "mvmctl",
            "--config-file",
            file.to_str().unwrap(),
            "machine",
            "run",
        ])
        .unwrap();
        assert_eq!(
            run(&matches)
                .get_one::<String>("profile")
                .map(String::as_str),
            Some("--literal")
        );
    }

    #[test]
    fn rejects_conflicts_and_unknown_keys() {
        let _env = isolated_env();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("opts.json");
        std::fs::write(
            &file,
            r#"{"commands":{"machine":{"run":{"build":true,"no-build":true}}}}"#,
        )
        .unwrap();
        let args = [
            "mvmctl",
            "machine",
            "run",
            "--config-file",
            file.to_str().unwrap(),
        ];
        let err = parse(&args).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
        std::fs::write(
            &file,
            r#"{"commands":{"machine":{"run":{"unknown":true}}}}"#,
        )
        .unwrap();
        assert!(
            parse(&args)
                .unwrap_err()
                .to_string()
                .contains("unknown option")
        );
        std::fs::write(&file, r#"{"commands":{"not-a-command":{"json":true}}}"#).unwrap();
        assert!(
            parse(&args)
                .unwrap_err()
                .to_string()
                .contains("unknown command")
        );
        std::fs::write(&file, r#"{"commands":{"machine":{"run":{"net":"true"}}}}"#).unwrap();
        assert!(
            parse(&args)
                .unwrap_err()
                .to_string()
                .contains("incompatible value")
        );
        std::fs::write(&file, "{bad json").unwrap();
        assert!(parse(&args).unwrap_err().to_string().contains("parsing"));
        let unsupported = dir.path().join("opts.yaml");
        std::fs::write(&unsupported, "global: {}").unwrap();
        let err = parse(&[
            "mvmctl",
            "--config-file",
            unsupported.to_str().unwrap(),
            "machine",
            "run",
        ])
        .unwrap_err();
        assert!(err.to_string().contains("expected .toml or .json"));
    }

    #[test]
    fn validates_but_ignores_options_for_other_commands() {
        let _env = isolated_env();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("opts.json");
        std::fs::write(
            &file,
            r#"{"commands":{"machine":{"run":{"net":true}},"doctor":{"json":true}}}"#,
        )
        .unwrap();
        let args = [
            "mvmctl",
            "machine",
            "run",
            "--config-file",
            file.to_str().unwrap(),
        ];
        assert!(run(&parse(&args).unwrap()).get_flag("net"));
        std::fs::write(
            &file,
            r#"{"commands":{"machine":{"run":{"net":true}},"doctor":{"unknown":true}}}"#,
        )
        .unwrap();
        assert!(
            parse(&args)
                .unwrap_err()
                .to_string()
                .contains("unknown option")
        );
    }

    #[test]
    fn real_cli_rejects_conflicting_security_options_before_dispatch() {
        let _env = isolated_env();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("opts.toml");
        std::fs::write(
            &file,
            "[commands.machine.run]\nbuild = true\nno-build = true\n",
        )
        .unwrap();
        let args = [
            "mvmctl",
            "--config-file",
            file.to_str().unwrap(),
            "machine",
            "run",
            "--image",
            "alpine",
        ];
        let err = resolve(super::super::cli_command(), args.map(OsString::from)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn real_cli_composes_requested_egress_without_replacing_security_profile() {
        let _env = isolated_env();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("opts.toml");
        std::fs::write(
            &file,
            "[commands.machine.run]\nprofile = 'restrictive'\nallow-host = ['file.example:443']\n",
        )
        .unwrap();
        let args = [
            "mvmctl",
            "machine",
            "run",
            "--config-file",
            file.to_str().unwrap(),
            "--image",
            "alpine",
            "--allow-host",
            "flag.example:443",
        ];
        let matches = resolve(super::super::cli_command(), args.map(OsString::from)).unwrap();
        let mut cli = super::super::Cli::from_arg_matches(&matches).unwrap();
        super::super::record_explicit_run_resources(&matches, &mut cli);
        let super::super::Commands::Machine(machine) = cli.command else {
            panic!("expected machine command");
        };
        let super::super::machine::MachineAction::Run(run) = machine.action else {
            panic!("expected run command");
        };
        assert_eq!(format!("{:?}", run.run.profile), "Restrictive");
        assert_eq!(run.run.allow_host, ["file.example:443", "flag.example:443"]);
    }

    #[test]
    fn configured_cpu_request_still_passes_through_the_host_ceiling() {
        use mvm_client::admission::run_grants::{GrantInputs, resolve_run_grants};

        let mut env = isolated_env();
        env.set("MVMCTL_RUN_CPU_LIMIT", "100");
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("opts.toml");
        std::fs::write(&file, "[commands.run]\ncpu-limit = 1000\n").unwrap();
        let matches = resolve(
            super::super::cli_command(),
            [
                "mvmctl",
                "--config-file",
                file.to_str().unwrap(),
                "run",
                "--no-detect",
                "--",
                "/bin/true",
            ]
            .map(OsString::from),
        )
        .unwrap();
        let cli = super::super::Cli::from_arg_matches(&matches).unwrap();
        let super::super::Commands::Run(verb) = cli.command else {
            panic!("expected run command");
        };
        let run = verb.machine.run;
        assert_eq!(run.cpu_limit, Some(1000));
        let config = mvm_core::user_config::MvmConfig {
            max_cpu_millicores: Some(500),
            ..Default::default()
        };
        let err = resolve_run_grants(GrantInputs {
            cpu_limit_millicores: run.cpu_limit,
            timeout_secs: run.timeout,
            allow_host: &run.allow_host,
            peer: &run.peer,
            net: run.net,
            network_preset: run.network_preset,
            grants_file: run.grants_file.as_deref(),
            manifest: None,
            config: &config,
            ai: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("host allows at most 500"), "{err}");
    }

    #[test]
    fn global_scalar_override_after_subcommand_replaces_file_value() {
        let _env = isolated_env();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("opts.toml");
        std::fs::write(&file, "[global]\nlog-format = 'human'\n").unwrap();
        let matches = resolve(
            super::super::cli_command(),
            [
                "mvmctl",
                "doctor",
                "--config-file",
                file.to_str().unwrap(),
                "--log-format",
                "json",
            ]
            .map(OsString::from),
        )
        .unwrap();
        assert_eq!(
            matches.get_one::<String>("log_format").map(String::as_str),
            Some("json")
        );
    }

    #[test]
    fn global_count_composes_with_explicit_flags_before_command() {
        let mut env = isolated_env();
        env.set("MVMCTL_VERBOSE", "1");
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("opts.toml");
        std::fs::write(&file, "[global]\nverbose = 1\n").unwrap();
        let matches = parse(&[
            "mvmctl",
            "-vv",
            "--config-file",
            file.to_str().unwrap(),
            "machine",
            "run",
        ])
        .unwrap();
        assert_eq!(*matches.get_one::<u8>("verbose").unwrap(), 4);
    }
}
