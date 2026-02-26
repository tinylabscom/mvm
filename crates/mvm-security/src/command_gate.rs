use aho_corasick::AhoCorasick;

use mvm_core::security::{BlocklistAction, BlocklistEntry, BlocklistSeverity, GateDecision};

/// Host-side command gate that evaluates vsock commands against a blocklist.
///
/// Uses Aho-Corasick for O(n) literal substring matching and simple glob
/// matching for wildcard patterns. Every command is evaluated and a
/// `GateDecision` is returned.
pub struct CommandGate {
    /// Aho-Corasick automaton for literal (non-glob) patterns.
    automaton: AhoCorasick,
    /// Blocklist entries corresponding to each automaton pattern (by index).
    literal_entries: Vec<BlocklistEntry>,
    /// Glob patterns (containing `*` or `?`) checked sequentially.
    glob_entries: Vec<BlocklistEntry>,
}

impl CommandGate {
    /// Build a command gate from a list of blocklist entries.
    ///
    /// Entries are partitioned into literal patterns (matched via Aho-Corasick)
    /// and glob patterns (matched sequentially). Literal patterns are compiled
    /// into a single automaton for efficient multi-pattern matching.
    pub fn new(blocklist: Vec<BlocklistEntry>) -> Self {
        let (literals, globs): (Vec<_>, Vec<_>) = blocklist
            .into_iter()
            .partition(|e| !e.pattern.contains('*') && !e.pattern.contains('?'));

        let patterns: Vec<&str> = literals.iter().map(|e| e.pattern.as_str()).collect();
        let automaton = AhoCorasick::new(&patterns)
            .expect("failed to build Aho-Corasick automaton from blocklist patterns");

        Self {
            automaton,
            literal_entries: literals,
            glob_entries: globs,
        }
    }

    /// Evaluate a command against the blocklist.
    ///
    /// Returns the highest-priority gate decision:
    /// - `Block` matches take precedence over `RequireApproval`
    /// - `RequireApproval` matches take precedence over `Log`
    /// - If no pattern matches, returns `Allow`
    pub fn evaluate(&self, command_text: &str) -> GateDecision {
        // Track the highest-severity decision seen so far.
        let mut pending_approval: Option<(&str, &str)> = None;

        // Tier 1: Aho-Corasick literal substring matching (single O(n) scan).
        for mat in self.automaton.find_iter(command_text) {
            let entry = &self.literal_entries[mat.pattern().as_usize()];
            match entry.action {
                BlocklistAction::Block => {
                    return GateDecision::Blocked {
                        pattern: entry.pattern.clone(),
                        reason: entry.category.clone(),
                    };
                }
                BlocklistAction::RequireApproval => {
                    if pending_approval.is_none() {
                        pending_approval = Some((entry.pattern.as_str(), entry.category.as_str()));
                    }
                }
                BlocklistAction::Log => {
                    tracing::info!(
                        pattern = %entry.pattern,
                        category = %entry.category,
                        "command gate: logged match (allowed)"
                    );
                }
            }
        }

        // Tier 2: Glob pattern matching (sequential).
        for entry in &self.glob_entries {
            if glob_match(&entry.pattern, command_text) {
                match entry.action {
                    BlocklistAction::Block => {
                        return GateDecision::Blocked {
                            pattern: entry.pattern.clone(),
                            reason: entry.category.clone(),
                        };
                    }
                    BlocklistAction::RequireApproval => {
                        if pending_approval.is_none() {
                            pending_approval =
                                Some((entry.pattern.as_str(), entry.category.as_str()));
                        }
                    }
                    BlocklistAction::Log => {
                        tracing::info!(
                            pattern = %entry.pattern,
                            category = %entry.category,
                            "command gate: logged glob match (allowed)"
                        );
                    }
                }
            }
        }

        if let Some((pattern, _category)) = pending_approval {
            return GateDecision::RequiresApproval {
                reason: format!("matched pattern: {}", pattern),
            };
        }

        GateDecision::Allow
    }

    /// Evaluate in dev mode: auto-approve `RequiresApproval` decisions with a warning.
    pub fn evaluate_dev_mode(&self, command_text: &str) -> GateDecision {
        match self.evaluate(command_text) {
            GateDecision::RequiresApproval { reason } => {
                tracing::warn!(
                    reason = %reason,
                    "command gate: auto-approved in dev mode"
                );
                GateDecision::Allow
            }
            other => other,
        }
    }
}

/// Simple glob pattern matching against the full text.
///
/// Supports `*` (matches zero or more characters) and `?` (matches exactly
/// one character). The pattern is matched against the entire input text.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    // Consume trailing stars.
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }

    pi == p.len()
}

/// Returns a default blocklist of commonly dangerous patterns.
///
/// This covers destructive commands, privilege escalation, sensitive file
/// access, and VM escape vectors. Callers can extend this with additional
/// entries from `SecurityPolicy.blocklist`.
pub fn default_blocklist() -> Vec<BlocklistEntry> {
    vec![
        // Destructive commands
        entry(
            "rm -rf /",
            "destructive",
            BlocklistSeverity::Critical,
            BlocklistAction::Block,
        ),
        entry(
            "mkfs",
            "destructive",
            BlocklistSeverity::Critical,
            BlocklistAction::Block,
        ),
        entry(
            "dd if=/dev/zero",
            "destructive",
            BlocklistSeverity::Critical,
            BlocklistAction::Block,
        ),
        entry(
            "> /dev/sda",
            "destructive",
            BlocklistSeverity::Critical,
            BlocklistAction::Block,
        ),
        entry(
            ":(){ :|:& };:",
            "destructive",
            BlocklistSeverity::Critical,
            BlocklistAction::Block,
        ),
        // Privilege escalation
        entry(
            "nsenter",
            "privilege_escalation",
            BlocklistSeverity::High,
            BlocklistAction::Block,
        ),
        entry(
            "unshare",
            "privilege_escalation",
            BlocklistSeverity::High,
            BlocklistAction::RequireApproval,
        ),
        entry(
            "chroot",
            "privilege_escalation",
            BlocklistSeverity::High,
            BlocklistAction::RequireApproval,
        ),
        // Sensitive file access
        entry(
            "/etc/shadow",
            "sensitive_file",
            BlocklistSeverity::High,
            BlocklistAction::Block,
        ),
        entry(
            ".ssh/id_rsa",
            "sensitive_file",
            BlocklistSeverity::High,
            BlocklistAction::Block,
        ),
        entry(
            ".aws/credentials",
            "sensitive_file",
            BlocklistSeverity::High,
            BlocklistAction::Block,
        ),
        // VM escape vectors
        entry(
            "/dev/kvm",
            "vm_escape",
            BlocklistSeverity::Critical,
            BlocklistAction::Block,
        ),
        entry(
            "release_agent",
            "vm_escape",
            BlocklistSeverity::Critical,
            BlocklistAction::Block,
        ),
    ]
}

fn entry(
    pattern: &str,
    category: &str,
    severity: BlocklistSeverity,
    action: BlocklistAction,
) -> BlocklistEntry {
    BlocklistEntry {
        pattern: pattern.to_string(),
        category: category.to_string(),
        severity,
        action,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_entry(pattern: &str, category: &str) -> BlocklistEntry {
        entry(
            pattern,
            category,
            BlocklistSeverity::High,
            BlocklistAction::Block,
        )
    }

    fn approval_entry(pattern: &str, category: &str) -> BlocklistEntry {
        entry(
            pattern,
            category,
            BlocklistSeverity::Medium,
            BlocklistAction::RequireApproval,
        )
    }

    fn log_entry(pattern: &str, category: &str) -> BlocklistEntry {
        entry(
            pattern,
            category,
            BlocklistSeverity::Low,
            BlocklistAction::Log,
        )
    }

    // -- glob_match tests --

    #[test]
    fn test_glob_exact_match() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }

    #[test]
    fn test_glob_star() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("hello*", "hello world"));
        assert!(glob_match("*world", "hello world"));
        assert!(glob_match("*llo*", "hello world"));
        assert!(!glob_match("hello*", "goodbye"));
    }

    #[test]
    fn test_glob_question_mark() {
        assert!(glob_match("h?llo", "hello"));
        assert!(glob_match("h?llo", "hallo"));
        assert!(!glob_match("h?llo", "hllo"));
    }

    #[test]
    fn test_glob_complex() {
        assert!(glob_match("*rm -rf*", "sudo rm -rf /"));
        assert!(glob_match("chmod 4??? *", "chmod 4755 /bin/sh"));
        assert!(!glob_match("chmod 4??? *", "chmod 755 /bin/sh"));
    }

    // -- CommandGate tests --

    #[test]
    fn test_empty_blocklist_allows_all() {
        let gate = CommandGate::new(vec![]);
        assert_eq!(gate.evaluate("rm -rf /"), GateDecision::Allow);
        assert_eq!(gate.evaluate("ls -la"), GateDecision::Allow);
    }

    #[test]
    fn test_literal_block() {
        let gate = CommandGate::new(vec![block_entry("rm -rf /", "destructive")]);

        assert_eq!(
            gate.evaluate("rm -rf /"),
            GateDecision::Blocked {
                pattern: "rm -rf /".to_string(),
                reason: "destructive".to_string(),
            }
        );
        // Also matches as substring
        assert_eq!(
            gate.evaluate("sudo rm -rf / --no-preserve-root"),
            GateDecision::Blocked {
                pattern: "rm -rf /".to_string(),
                reason: "destructive".to_string(),
            }
        );
    }

    #[test]
    fn test_literal_require_approval() {
        let gate = CommandGate::new(vec![approval_entry("chroot", "privilege_escalation")]);

        assert_eq!(
            gate.evaluate("chroot /mnt"),
            GateDecision::RequiresApproval {
                reason: "matched pattern: chroot".to_string(),
            }
        );
    }

    #[test]
    fn test_literal_log_allows() {
        let gate = CommandGate::new(vec![log_entry("curl", "network")]);
        // Log action should still allow the command
        assert_eq!(
            gate.evaluate("curl https://example.com"),
            GateDecision::Allow
        );
    }

    #[test]
    fn test_block_takes_precedence_over_approval() {
        let gate = CommandGate::new(vec![
            approval_entry("sudo", "escalation"),
            block_entry("rm -rf /", "destructive"),
        ]);

        // Command that matches both — Block should win
        assert_eq!(
            gate.evaluate("sudo rm -rf /"),
            GateDecision::Blocked {
                pattern: "rm -rf /".to_string(),
                reason: "destructive".to_string(),
            }
        );
    }

    #[test]
    fn test_glob_block() {
        let gate = CommandGate::new(vec![block_entry("*rm -rf*", "destructive")]);

        assert_eq!(
            gate.evaluate("please rm -rf everything"),
            GateDecision::Blocked {
                pattern: "*rm -rf*".to_string(),
                reason: "destructive".to_string(),
            }
        );
        assert_eq!(gate.evaluate("ls -la"), GateDecision::Allow);
    }

    #[test]
    fn test_dev_mode_auto_approves() {
        let gate = CommandGate::new(vec![approval_entry("chroot", "privilege_escalation")]);

        // Regular mode: RequiresApproval
        assert_eq!(
            gate.evaluate("chroot /mnt"),
            GateDecision::RequiresApproval {
                reason: "matched pattern: chroot".to_string(),
            }
        );

        // Dev mode: auto-approved → Allow
        assert_eq!(gate.evaluate_dev_mode("chroot /mnt"), GateDecision::Allow);
    }

    #[test]
    fn test_dev_mode_still_blocks() {
        let gate = CommandGate::new(vec![block_entry("rm -rf /", "destructive")]);

        // Dev mode does NOT auto-approve Block decisions
        assert_eq!(
            gate.evaluate_dev_mode("rm -rf /"),
            GateDecision::Blocked {
                pattern: "rm -rf /".to_string(),
                reason: "destructive".to_string(),
            }
        );
    }

    #[test]
    fn test_benign_commands_allowed() {
        let gate = CommandGate::new(default_blocklist());

        assert_eq!(gate.evaluate("ls -la /tmp"), GateDecision::Allow);
        assert_eq!(gate.evaluate("cat README.md"), GateDecision::Allow);
        assert_eq!(
            gate.evaluate("nix build .#packages.x86_64-linux.default"),
            GateDecision::Allow
        );
        assert_eq!(gate.evaluate("echo hello world"), GateDecision::Allow);
    }

    #[test]
    fn test_default_blocklist_blocks_dangerous() {
        let gate = CommandGate::new(default_blocklist());

        // Destructive
        assert!(matches!(
            gate.evaluate("rm -rf /"),
            GateDecision::Blocked { .. }
        ));
        assert!(matches!(
            gate.evaluate("mkfs.ext4 /dev/sda"),
            GateDecision::Blocked { .. }
        ));
        assert!(matches!(
            gate.evaluate("dd if=/dev/zero of=/dev/sda"),
            GateDecision::Blocked { .. }
        ));

        // Privilege escalation
        assert!(matches!(
            gate.evaluate("nsenter -t 1 -m"),
            GateDecision::Blocked { .. }
        ));

        // Sensitive files
        assert!(matches!(
            gate.evaluate("cat /etc/shadow"),
            GateDecision::Blocked { .. }
        ));
        assert!(matches!(
            gate.evaluate("cat ~/.ssh/id_rsa"),
            GateDecision::Blocked { .. }
        ));

        // VM escape
        assert!(matches!(
            gate.evaluate("echo x > /dev/kvm"),
            GateDecision::Blocked { .. }
        ));
    }

    #[test]
    fn test_default_blocklist_approval_patterns() {
        let gate = CommandGate::new(default_blocklist());

        // These should require approval, not block
        assert!(matches!(
            gate.evaluate("unshare -m /bin/sh"),
            GateDecision::RequiresApproval { .. }
        ));
        assert!(matches!(
            gate.evaluate("chroot /newroot"),
            GateDecision::RequiresApproval { .. }
        ));
    }

    #[test]
    fn test_multiple_literal_entries() {
        let gate = CommandGate::new(vec![
            block_entry("pattern_a", "cat_a"),
            block_entry("pattern_b", "cat_b"),
            block_entry("pattern_c", "cat_c"),
        ]);

        assert_eq!(
            gate.evaluate("contains pattern_b here"),
            GateDecision::Blocked {
                pattern: "pattern_b".to_string(),
                reason: "cat_b".to_string(),
            }
        );
        assert_eq!(gate.evaluate("no match here"), GateDecision::Allow);
    }
}
