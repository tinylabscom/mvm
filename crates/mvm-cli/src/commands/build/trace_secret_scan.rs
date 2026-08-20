//! Host-side secret scan over a runtime recording.
//!
//! A recording is the Tier-0 promotion input; a raw secret embedded
//! in it (an env literal, a command argument, or the bytes of a
//! written file) would ride into the workload definition and defeat
//! the host-substitution posture where raw secrets never reach the
//! guest. This walks every place raw bytes can hide — decoding the
//! base64 of each `FilesWrite` so a secret written to a config file
//! is caught, not just env vars — and reports findings. `SecretRef`
//! values are skipped: they carry a reference, never a raw value.

use base64::Engine;
use mvm_contract::ir::EnvValue;
use mvm_hostd::supervisor::secrets_scanner::SecretsScanner;
use mvm_sdk::runtime::{RecordedOp, RuntimeRecording};
use std::collections::BTreeMap;

/// One location in a recording carrying raw secret-shaped material.
pub(in crate::commands) struct SecretFinding {
    /// Human-pointable location, e.g. `create env[AWS_ACCESS_KEY_ID]`,
    /// `op#2 argv[1]`, `op#3 file /app/.env`.
    pub location: String,
    /// Names of the `SecretsScanner` rules that matched.
    pub rules: Vec<String>,
}

/// Scan a recording for embedded **raw** secret material — env
/// literals, command argv, and the decoded bytes of every
/// `FilesWrite`. `SecretRef` values are skipped (they carry no raw
/// value). A non-empty result refuses promotion; the fix is to use a
/// `SecretRef`, not to acknowledge.
pub(in crate::commands) fn scan_recording_for_secrets(
    rec: &RuntimeRecording,
    scanner: &SecretsScanner,
) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    scan_env(scanner, "create", &rec.create.env, &mut out);
    // create.tags is intentionally not scanned: tags are best-effort
    // metadata that the lowering never carries into the Workload (env,
    // entrypoint, hooks) or the guest, so a value there cannot reach a
    // running workload.
    for (idx, op) in rec.ops.iter().enumerate() {
        match op {
            RecordedOp::CommandStart { argv, env } => {
                for (i, arg) in argv.iter().enumerate() {
                    push_if_hit(
                        scanner,
                        format!("op#{idx} argv[{i}]"),
                        arg.as_bytes(),
                        &mut out,
                    );
                }
                scan_env(scanner, &format!("op#{idx}"), env, &mut out);
            }
            RecordedOp::FilesWrite { path, bytes_b64 } => {
                // Decode so a secret written to a file is caught; a
                // malformed b64 is the lowering's problem, skip here.
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(bytes_b64) {
                    push_if_hit(scanner, format!("op#{idx} file {path}"), &decoded, &mut out);
                }
            }
            RecordedOp::Kill => {}
        }
    }
    out
}

/// Scan the `Literal` values of an env map; `SecretRef` values are
/// skipped by design.
fn scan_env(
    scanner: &SecretsScanner,
    ctx: &str,
    env: &BTreeMap<String, EnvValue>,
    out: &mut Vec<SecretFinding>,
) {
    for (key, val) in env {
        if let EnvValue::Literal { value } = val {
            push_if_hit(scanner, format!("{ctx} env[{key}]"), value.as_bytes(), out);
        }
    }
}

/// Run the scanner over `body`; push a finding only when it matches.
fn push_if_hit(
    scanner: &SecretsScanner,
    location: String,
    body: &[u8],
    out: &mut Vec<SecretFinding>,
) {
    let hits = scanner.scan(body);
    if !hits.is_empty() {
        out.push(SecretFinding {
            location,
            rules: hits.into_iter().map(|s| s.to_string()).collect(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::ir::{AuthType, SecretMount, SecretRef};
    use mvm_sdk::runtime::SandboxCreate;

    fn scanner() -> SecretsScanner {
        SecretsScanner::with_default_rules()
    }

    fn lit(v: &str) -> EnvValue {
        EnvValue::Literal {
            value: v.to_string(),
        }
    }

    fn empty_create() -> SandboxCreate {
        SandboxCreate {
            template: Some("minimal".to_string()),
            image: None,
            env: BTreeMap::new(),
            include: Vec::new(),
            tags: BTreeMap::new(),
            ttl_seconds: None,
            resources: None,
            network: None,
        }
    }

    fn rec(create: SandboxCreate, ops: Vec<RecordedOp>) -> RuntimeRecording {
        RuntimeRecording {
            workload_id: "wl".to_string(),
            create,
            ops,
        }
    }

    fn start(argv: &[&str], env: BTreeMap<String, EnvValue>) -> RecordedOp {
        RecordedOp::CommandStart {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            env,
        }
    }

    // A realistic-shaped fake AWS key (AKIA + 16 upper/digits) and
    // OpenAI key (sk- + 48 alnum). These are not real credentials —
    // they match the DEFAULT_RULES regex shapes.
    const FAKE_AWS: &str = "AKIAIOSFODNN7EXAMPLE";
    const FAKE_OPENAI: &str = "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV";

    #[test]
    fn clean_recording_has_no_findings() {
        let r = rec(empty_create(), vec![start(&["/bin/true"], BTreeMap::new())]);
        assert!(scan_recording_for_secrets(&r, &scanner()).is_empty());
    }

    #[test]
    fn create_env_literal_secret_is_flagged() {
        let mut env = BTreeMap::new();
        env.insert("AWS_ACCESS_KEY_ID".to_string(), lit(FAKE_AWS));
        let r = rec(
            SandboxCreate {
                env,
                ..empty_create()
            },
            vec![start(&["/bin/true"], BTreeMap::new())],
        );
        let f = scan_recording_for_secrets(&r, &scanner());
        assert_eq!(f.len(), 1);
        assert!(f[0].location.contains("AWS_ACCESS_KEY_ID"));
        assert!(f[0].rules.iter().any(|r| r == "aws_access_key_id"));
    }

    #[test]
    fn argv_secret_is_flagged() {
        let r = rec(
            empty_create(),
            vec![start(
                &["/bin/run", &format!("--key={FAKE_OPENAI}")],
                BTreeMap::new(),
            )],
        );
        let f = scan_recording_for_secrets(&r, &scanner());
        assert_eq!(f.len(), 1);
        assert!(f[0].location.contains("argv"));
        assert!(f[0].rules.iter().any(|r| r == "openai_api_key"));
    }

    #[test]
    fn files_write_decoded_secret_is_flagged() {
        // The secret is base64-encoded inside the recording — proving
        // the scan must decode, not scan the b64 surface.
        let body = format!("OPENAI_API_KEY={FAKE_OPENAI}\n");
        let b64 = base64::engine::general_purpose::STANDARD.encode(body.as_bytes());
        let r = rec(
            empty_create(),
            vec![
                RecordedOp::FilesWrite {
                    path: "/app/.env".to_string(),
                    bytes_b64: b64,
                },
                start(&["/bin/true"], BTreeMap::new()),
            ],
        );
        let f = scan_recording_for_secrets(&r, &scanner());
        assert_eq!(f.len(), 1, "decoded file content secret must be caught");
        assert!(f[0].location.contains("/app/.env"));
    }

    #[test]
    fn secret_ref_value_is_not_flagged() {
        // A SecretRef carries a reference, not raw bytes — it is the
        // CORRECT way to use a secret and must never be flagged.
        let mut env = BTreeMap::new();
        env.insert("TOKEN".to_string(), secret_ref_env());
        let r = rec(
            SandboxCreate {
                env,
                ..empty_create()
            },
            vec![start(&["/bin/true"], BTreeMap::new())],
        );
        assert!(scan_recording_for_secrets(&r, &scanner()).is_empty());
    }

    #[test]
    fn op_env_literal_secret_reports_op_index() {
        let mut env = BTreeMap::new();
        env.insert(
            "GH".to_string(),
            lit("ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
        );
        let r = rec(empty_create(), vec![start(&["/bin/true"], env)]);
        let f = scan_recording_for_secrets(&r, &scanner());
        assert_eq!(f.len(), 1);
        assert!(f[0].location.contains("op#0"));
    }

    fn secret_ref_env() -> EnvValue {
        EnvValue::SecretRef {
            reference: SecretRef {
                name: "my-token".to_string(),
                mount: SecretMount::Env {
                    var: "TOKEN".to_string(),
                },
                auth_type: AuthType::Bearer,
                allowed_hosts: vec!["api.example.com".to_string()],
                sigv4: None,
            },
        }
    }
}
