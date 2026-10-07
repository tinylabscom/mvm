//! Safe audit labels for refused workload input.

use super::stream_audit as k;
use crate::stream::InputRefusal;

/// Keep the binding and actionable reason without copying workload bytes.
pub(super) fn input_refused_labels(vm_name: &str, refusal: &InputRefusal) -> Vec<(String, String)> {
    let mut labels = vec![
        (k::LABEL_VM_NAME.to_string(), vm_name.to_string()),
        (k::LABEL_REASON.to_string(), refusal.reason().to_string()),
    ];
    match refusal {
        // An unauditable refusal can be recorded only if a later attempt
        // succeeds after the signing failure was transient.
        InputRefusal::NotGranted | InputRefusal::LeaseExpired | InputRefusal::Unauditable => {}
        InputRefusal::LeaseHeld { holder } => {
            labels.push((k::LABEL_HOLDER.to_string(), holder.clone()));
        }
        InputRefusal::SecretMaterial { category } => {
            labels.push((
                k::LABEL_SECRET_CATEGORY.to_string(),
                (*category).to_string(),
            ));
        }
        InputRefusal::OutOfOrder { seq, after } => {
            labels.push((k::LABEL_SEQ.to_string(), seq.to_string()));
            labels.push((k::LABEL_AFTER_SEQ.to_string(), after.to_string()));
        }
    }
    labels
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every refusal variant reaches the chain under its own reason word, and
    /// no variant's labels can grow a key outside this allow-list.
    #[test]
    fn every_input_refusal_variant_is_labelled_with_its_reason_and_nothing_more() {
        let allowed = [
            k::LABEL_VM_NAME,
            k::LABEL_REASON,
            k::LABEL_HOLDER,
            k::LABEL_SECRET_CATEGORY,
            k::LABEL_SEQ,
            k::LABEL_AFTER_SEQ,
        ];
        for refusal in [
            InputRefusal::NotGranted,
            InputRefusal::Unauditable,
            InputRefusal::LeaseExpired,
            InputRefusal::LeaseHeld {
                holder: "plan-1#0".to_string(),
            },
            InputRefusal::SecretMaterial {
                category: "host-secret",
            },
            InputRefusal::OutOfOrder { seq: 3, after: 9 },
        ] {
            let labels = input_refused_labels("vm-1", &refusal);
            let by_key: std::collections::BTreeMap<&str, &str> = labels
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            assert_eq!(by_key.len(), labels.len(), "no duplicate keys: {labels:?}");
            assert_eq!(by_key.get(k::LABEL_VM_NAME), Some(&"vm-1"));
            assert_eq!(by_key.get(k::LABEL_REASON), Some(&refusal.reason()));
            for key in by_key.keys() {
                assert!(
                    allowed.contains(key),
                    "unexpected label {key} on {refusal:?}"
                );
            }
        }

        let ordered = input_refused_labels("vm-1", &InputRefusal::OutOfOrder { seq: 3, after: 9 });
        assert!(ordered.contains(&(k::LABEL_SEQ.to_string(), "3".to_string())));
        assert!(ordered.contains(&(k::LABEL_AFTER_SEQ.to_string(), "9".to_string())));
    }
}
