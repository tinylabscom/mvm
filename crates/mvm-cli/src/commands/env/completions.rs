use std::collections::BTreeSet;

use clap::{Command, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(in crate::commands) enum Shell {
    Bash,
    Zsh,
}

pub(in crate::commands) fn render(command: Command, shell: Shell) -> String {
    CompletionScript::builder()
        .shell(shell)
        .index(CompletionIndex::from_command(command))
        .build()
        .render()
}

#[derive(Debug, Clone)]
struct CompletionScript {
    index: CompletionIndex,
    shell: Shell,
}

impl CompletionScript {
    fn builder() -> CompletionScriptBuilder {
        CompletionScriptBuilder::default()
    }

    fn render(&self) -> String {
        format!(
            "{prelude}{helpers}\n{function}\n{registration}\n",
            prelude = self.shell_prelude(),
            helpers = self.path_helpers(),
            function = self.completion_function(),
            registration = self.shell_registration(),
        )
    }

    fn shell_prelude(&self) -> &'static str {
        match self.shell {
            Shell::Bash => "",
            Shell::Zsh => "autoload -U +X bashcompinit && bashcompinit\n",
        }
    }

    fn path_helpers(&self) -> String {
        let transitions = self
            .index
            .transitions()
            .into_iter()
            .map(render_transition)
            .collect::<Vec<_>>()
            .join("\n");
        let cases = self
            .index
            .entries
            .iter()
            .map(render_candidate_case)
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "_mvmctl_resolve_path() {{\n    case \"$1|$2\" in\n{transitions}\n        *) return 1 ;;\n    esac\n}}\n\n_mvmctl_candidates() {{\n    case \"$1\" in\n{cases}\n        *) printf '%s\\n' '' ;;\n    esac\n}}\n",
        )
    }

    fn completion_function(&self) -> &'static str {
        "_mvmctl_complete() {\n    local cur path next_path word candidates\n    COMPREPLY=()\n    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n    path=\"\"\n\n    for ((i = 1; i < COMP_CWORD; i++)); do\n        word=\"${COMP_WORDS[i]}\"\n        [[ \"$word\" == -* ]] && continue\n        next_path=\"$(_mvmctl_resolve_path \"$path\" \"$word\")\" || continue\n        path=\"$next_path\"\n    done\n\n    candidates=\"$(_mvmctl_candidates \"$path\")\"\n    COMPREPLY=( $(compgen -W \"$candidates\" -- \"$cur\") )\n}\n"
    }

    fn shell_registration(&self) -> &'static str {
        "complete -F _mvmctl_complete mvmctl"
    }
}

#[derive(Debug, Default, Clone)]
struct CompletionScriptBuilder {
    index: Option<CompletionIndex>,
    shell: Option<Shell>,
}

impl CompletionScriptBuilder {
    fn shell(mut self, shell: Shell) -> Self {
        self.shell = Some(shell);
        self
    }

    fn index(mut self, index: CompletionIndex) -> Self {
        self.index = Some(index);
        self
    }

    fn build(self) -> CompletionScript {
        CompletionScript {
            index: self.index.expect("completion index must be set"),
            shell: self.shell.expect("completion shell must be set"),
        }
    }
}

#[derive(Debug, Clone)]
struct CompletionIndex {
    entries: Vec<CompletionEntry>,
}

impl CompletionIndex {
    fn from_command(command: Command) -> Self {
        let mut builder = CompletionIndexBuilder::default();
        builder.visit(&command, Vec::new());
        builder.build()
    }

    fn transitions(&self) -> Vec<CompletionTransition> {
        self.entries
            .iter()
            .flat_map(CompletionEntry::transitions)
            .collect()
    }
}

#[derive(Debug, Default)]
struct CompletionIndexBuilder {
    entries: Vec<CompletionEntry>,
}

impl CompletionIndexBuilder {
    fn visit(&mut self, command: &Command, path: Vec<String>) {
        self.entries
            .push(CompletionEntry::from_command(path.clone(), command));
        for child in visible_subcommands(command) {
            let mut child_path = path.clone();
            child_path.push(child.get_name().to_string());
            self.visit(child, child_path);
        }
    }

    fn build(self) -> CompletionIndex {
        CompletionIndex {
            entries: self.entries,
        }
    }
}

#[derive(Debug, Clone)]
struct CompletionEntry {
    path: String,
    candidates: Vec<String>,
    subcommands: Vec<String>,
}

impl CompletionEntry {
    fn from_command(path: Vec<String>, command: &Command) -> Self {
        let subcommands = visible_subcommands(command)
            .map(|child| child.get_name().to_string())
            .collect::<Vec<_>>();
        let candidates = subcommands
            .iter()
            .cloned()
            .chain(visible_flags(command))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        Self {
            path: join_path(&path),
            candidates,
            subcommands,
        }
    }

    fn transitions(&self) -> Vec<CompletionTransition> {
        self.subcommands
            .iter()
            .map(|subcommand| CompletionTransition::new(&self.path, subcommand))
            .collect()
    }
}

#[derive(Debug, Clone)]
struct CompletionTransition {
    current_path: String,
    next_path: String,
    subcommand: String,
}

impl CompletionTransition {
    fn new(current_path: &str, subcommand: &str) -> Self {
        let next_path = if current_path.is_empty() {
            subcommand.to_string()
        } else {
            format!("{current_path} {subcommand}")
        };
        Self {
            current_path: current_path.to_string(),
            next_path,
            subcommand: subcommand.to_string(),
        }
    }
}

fn visible_subcommands(command: &Command) -> impl Iterator<Item = &Command> {
    command
        .get_subcommands()
        .filter(|child| !child.is_hide_set())
}

fn visible_flags(command: &Command) -> impl Iterator<Item = String> + '_ {
    command
        .get_arguments()
        .filter(|arg| !arg.is_hide_set())
        .flat_map(flag_names)
}

fn flag_names(arg: &clap::Arg) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(short) = arg.get_short() {
        names.push(format!("-{short}"));
    }
    if let Some(long) = arg.get_long() {
        names.push(format!("--{long}"));
    }
    names
}

fn join_path(path: &[String]) -> String {
    path.join(" ")
}

fn render_transition(transition: CompletionTransition) -> String {
    format!(
        "        \"{}|{}\") printf '%s\\n' '{}' ;;\n",
        transition.current_path, transition.subcommand, transition.next_path
    )
}

fn render_candidate_case(entry: &CompletionEntry) -> String {
    format!(
        "        \"{}\") printf '%s\\n' '{}' ;;\n",
        entry.path,
        entry.candidates.join(" ")
    )
}

#[cfg(test)]
mod tests {
    use clap::{Arg, ArgAction, Command};

    use super::*;

    #[test]
    fn bash_script_lists_public_root_commands() {
        let script = render(test_command(), Shell::Bash);
        assert!(script.contains("machine"));
        assert!(script.contains("dev"));
        assert!(!script.contains("__hidden"));
        assert!(!script.contains("--secret"));
    }

    #[test]
    fn zsh_script_bootstraps_bash_compat() {
        let script = render(test_command(), Shell::Zsh);
        assert!(script.contains("bashcompinit"));
        assert!(script.contains("complete -F _mvmctl_complete mvmctl"));
    }

    #[test]
    fn transitions_follow_subcommands() {
        let index = CompletionIndex::from_command(test_command());
        let transitions = index
            .transitions()
            .into_iter()
            .map(render_transition)
            .collect::<String>();
        assert!(transitions.contains("\"|machine\")"));
        assert!(transitions.contains("printf '%s\\n' 'machine'"));
    }

    fn test_command() -> Command {
        Command::new("mvmctl")
            .arg(
                Arg::new("verbose")
                    .short('v')
                    .long("verbose")
                    .action(ArgAction::Count),
            )
            .arg(Arg::new("secret").long("secret").hide(true))
            .subcommand(Command::new("machine"))
            .subcommand(Command::new("dev"))
            .subcommand(Command::new("__hidden").hide(true))
    }
}
