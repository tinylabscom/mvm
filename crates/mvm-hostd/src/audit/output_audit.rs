//! `plan.outputs`: what one output grant's collection produced.
//!
//! Recorded after a transient workload exits and the host has read its output
//! disk. The entry binds the result to the plan that granted it without
//! carrying a path or a byte the guest chose.

use anyhow::Result;
use mvm_core::plan::ExecutionPlan;

use super::emitter::AuditEmitter;

/// One output grant's collection, as `plan.outputs` records it.
#[derive(Debug, Clone, Copy)]
pub struct OutputRecord<'a> {
    /// The granted guest path, which the signed plan already names.
    pub guest_path: &'a str,
    pub outcome: OutputOutcome<'a>,
}

/// How an output collection ended.
#[derive(Debug, Clone, Copy)]
pub enum OutputOutcome<'a> {
    Collected {
        /// Canonical digest over the sorted (path, size, sha256) manifest.
        manifest_sha256: &'a str,
        entry_count: u64,
        total_bytes: u64,
        /// The content identity `--asset` records for the destination tree.
        tree_sha256: &'a str,
    },
    /// The stable tag of the rule that refused the collection.
    Refused { reason: &'a str },
}

impl AuditEmitter {
    /// Emit `plan.outputs` — the result of collecting one output grant after
    /// the workload exited. A collected result records the canonical manifest
    /// digest, its entry count and byte total, and the tree digest `--asset`
    /// would compute for the destination, so a later run that consumes these
    /// files names them by the same identity. A refusal records only the rule
    /// that fired. Neither carries a path or a byte the guest chose: the full
    /// per-file manifest is written beside the outputs, not into the chain.
    pub fn emit_outputs(&self, plan: &ExecutionPlan, record: &OutputRecord<'_>) -> Result<()> {
        let mut labels = vec![("guest_path".to_string(), record.guest_path.to_string())];
        match record.outcome {
            OutputOutcome::Collected {
                manifest_sha256,
                entry_count,
                total_bytes,
                tree_sha256,
            } => {
                labels.push(("outcome".to_string(), "collected".to_string()));
                labels.push(("manifest_sha256".to_string(), manifest_sha256.to_string()));
                labels.push(("entry_count".to_string(), entry_count.to_string()));
                labels.push(("total_bytes".to_string(), total_bytes.to_string()));
                labels.push(("tree_sha256".to_string(), tree_sha256.to_string()));
            }
            OutputOutcome::Refused { reason } => {
                labels.push(("outcome".to_string(), "refused".to_string()));
                labels.push(("reason".to_string(), reason.to_string()));
            }
        }
        self.emit(plan, "plan.outputs", labels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const MANIFEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const TREE: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn read_only_entry(dir: &std::path::Path) -> serde_json::Value {
        let content = std::fs::read_to_string(dir.join("local.jsonl")).expect("read the chain");
        let mut lines = content.lines();
        let line = lines.next().expect("one entry");
        assert!(lines.next().is_none(), "exactly one entry");
        let envelope: serde_json::Value = serde_json::from_str(line).expect("envelope json");
        envelope["entry"].clone()
    }

    #[test]
    fn a_collected_output_records_its_manifest_digest_count_and_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let emitter =
            AuditEmitter::with_dir(SigningKey::from_bytes(&[51; 32]), dir.path()).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-outputs-collected")
            .build();

        emitter
            .emit_outputs(
                &plan,
                &OutputRecord {
                    guest_path: "/data/out",
                    outcome: OutputOutcome::Collected {
                        manifest_sha256: MANIFEST,
                        entry_count: 3,
                        total_bytes: 16,
                        tree_sha256: TREE,
                    },
                },
            )
            .unwrap();

        let entry = read_only_entry(dir.path());
        assert_eq!(entry["event"], "plan.outputs");
        let labels = entry["labels"].as_object().expect("labels");
        assert_eq!(labels["guest_path"], "/data/out");
        assert_eq!(labels["outcome"], "collected");
        assert_eq!(labels["manifest_sha256"], MANIFEST);
        assert_eq!(labels["entry_count"], "3");
        assert_eq!(labels["total_bytes"], "16");
        assert_eq!(labels["tree_sha256"], TREE);
        assert!(!labels.contains_key("reason"));
    }

    #[test]
    fn a_refused_output_records_the_rule_and_no_digest() {
        let dir = tempfile::tempdir().unwrap();
        let emitter =
            AuditEmitter::with_dir(SigningKey::from_bytes(&[52; 32]), dir.path()).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-outputs-refused")
            .build();

        emitter
            .emit_outputs(
                &plan,
                &OutputRecord {
                    guest_path: "/data/out",
                    outcome: OutputOutcome::Refused { reason: "symlink" },
                },
            )
            .unwrap();

        let labels = read_only_entry(dir.path())["labels"].clone();
        assert_eq!(labels["outcome"], "refused");
        assert_eq!(labels["reason"], "symlink");
        assert!(labels.get("manifest_sha256").is_none());
    }
}
