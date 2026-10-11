/// A deterministic partition of the full scenario inventory for long live runs.
/// Every shard must run against the same checkout and the same capability tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioShard {
    index: u64,
    total: u64,
}

impl ScenarioShard {
    /// Parse a zero-based `index/total` selection. Invalid selections fail
    /// before the suite starts so they cannot silently report green coverage.
    pub fn parse(value: &str) -> Result<Self, String> {
        let (index, total) = value
            .split_once('/')
            .ok_or_else(|| format!("invalid scenario shard {value:?}: expected index/total"))?;
        let index = index
            .parse::<u64>()
            .map_err(|_| format!("invalid scenario shard {value:?}: index is not an integer"))?;
        let total = total
            .parse::<u64>()
            .map_err(|_| format!("invalid scenario shard {value:?}: total is not an integer"))?;
        if total == 0 || index >= total {
            return Err(format!(
                "invalid scenario shard {value:?}: require 0 <= index < total"
            ));
        }
        Ok(Self { index, total })
    }

    /// Stable across separate CI jobs: the feature, optional rule, and
    /// scenario identity always select one and only one member of a complete
    /// `0/total` through `(total - 1)/total` matrix.
    #[must_use]
    pub fn contains(self, feature: &str, rule: Option<&str>, scenario: &str) -> bool {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for part in [feature, rule.unwrap_or(""), scenario] {
            for byte in part.bytes().chain(std::iter::once(0xff)) {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        hash % self.total == self.index
    }

    #[must_use]
    pub fn label(self) -> String {
        format!("{}/{}", self.index, self.total)
    }
}

#[cfg(test)]
mod tests {
    use super::ScenarioShard;

    #[test]
    fn two_shards_cover_every_scenario_exactly_once() {
        let first = ScenarioShard::parse("0/2").expect("valid first shard");
        let second = ScenarioShard::parse("1/2").expect("valid second shard");
        for (feature, rule, scenario) in [
            ("Workload lifecycle", None, "A transient run exits"),
            (
                "Pack registry",
                Some("Signed pull"),
                "Tampered descriptor is refused",
            ),
            ("Tool policy", None, "A guest-origin tool is mediated"),
            ("Page merge", Some("Scope"), "same-name outline row"),
        ] {
            assert_ne!(
                first.contains(feature, rule, scenario),
                second.contains(feature, rule, scenario),
                "{feature}: {scenario} must be assigned to exactly one shard"
            );
        }
    }

    #[test]
    fn assignment_is_stable_for_the_same_identity() {
        let shard = ScenarioShard::parse("0/2").expect("valid shard");
        let first = shard.contains("Lifecycle", Some("Transient"), "success");
        assert_eq!(
            first,
            shard.contains("Lifecycle", Some("Transient"), "success")
        );
    }

    #[test]
    fn malformed_or_out_of_range_shards_are_rejected() {
        for value in ["", "0", "0/0", "2/2", "-1/2", "0/-2", "0/2/3", "a/b"] {
            assert!(ScenarioShard::parse(value).is_err(), "{value:?} must fail");
        }
    }
}
