//! A set of host CPU IDs in the kernel's list format (`0-3,6`).
//!
//! The same spelling the kernel uses in `cpuset.cpus.effective`,
//! `/sys/devices/system/cpu/online` and `/sys/devices/system/cpu/isolated`, and
//! the one systemd accepts for `AllowedCPUs=`. Parsed into a set so two
//! spellings of the same cores (`0,1,2` and `0-2`) compare equal, and printed
//! back in its shortest canonical form.

use alloc::collections::BTreeSet;
use alloc::string::String;
use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::plan::topology::CoreId;

/// Why a CPU list did not parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CpuSetParseError {
    #[error("{0:?} is not a CPU ID or a range of them")]
    BadElement(String),
    #[error("range {first}-{last} runs backwards")]
    InvertedRange { first: u32, last: u32 },
}

/// A set of host CPU IDs. Empty is a valid value: it is what the kernel prints
/// for a cgroup with no CPUs and what `isolated` holds on most hosts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct CpuSet(BTreeSet<u32>);

impl CpuSet {
    /// Parse a kernel CPU list. Surrounding whitespace, a trailing newline and
    /// the empty string are accepted, since that is how the kernel writes one.
    ///
    /// # Errors
    ///
    /// An element that is not an ID or an ascending `first-last` range.
    pub fn parse(list: &str) -> Result<Self, CpuSetParseError> {
        let mut cpus = BTreeSet::new();
        for element in list.trim().split(',').filter(|e| !e.is_empty()) {
            let bad = || CpuSetParseError::BadElement(String::from(element));
            let (first, last) = match element.split_once('-') {
                Some((first, last)) => (
                    first.parse::<u32>().map_err(|_| bad())?,
                    last.parse::<u32>().map_err(|_| bad())?,
                ),
                None => {
                    let cpu = element.parse::<u32>().map_err(|_| bad())?;
                    (cpu, cpu)
                }
            };
            if last < first {
                return Err(CpuSetParseError::InvertedRange { first, last });
            }
            cpus.extend(first..=last);
        }
        Ok(Self(cpus))
    }

    /// The set naming exactly `cores`.
    #[must_use]
    pub fn from_cores(cores: &[CoreId]) -> Self {
        Self(cores.iter().map(|core| core.0).collect())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn contains(&self, cpu: u32) -> bool {
        self.0.contains(&cpu)
    }

    /// The CPUs in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.iter().copied()
    }

    /// The CPUs of `self` not in `other`.
    #[must_use]
    pub fn difference(&self, other: &Self) -> Self {
        Self(self.0.difference(&other.0).copied().collect())
    }

    /// Every CPU in either set.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        Self(self.0.union(&other.0).copied().collect())
    }

    /// The lowest CPU in both sets, if any.
    #[must_use]
    pub fn first_shared(&self, other: &Self) -> Option<u32> {
        self.0.intersection(&other.0).next().copied()
    }
}

impl fmt::Display for CpuSet {
    /// Ascending, with every run of two or more consecutive IDs as a range.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut cpus = self.0.iter().copied().peekable();
        let mut first_element = true;
        while let Some(start) = cpus.next() {
            let mut end = start;
            while let Some(next) = end.checked_add(1)
                && cpus.peek() == Some(&next)
            {
                cpus.next();
                end = next;
            }
            if !first_element {
                f.write_str(",")?;
            }
            first_element = false;
            if start == end {
                write!(f, "{start}")?;
            } else {
                write!(f, "{start}-{end}")?;
            }
        }
        Ok(())
    }
}

impl Serialize for CpuSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for CpuSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let list = String::deserialize(deserializer)?;
        Self::parse(&list).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn a_kernel_list_parses_and_prints_canonically() {
        let set = CpuSet::parse("0-3,6\n").unwrap();
        assert_eq!(set.iter().collect::<alloc::vec::Vec<_>>(), [0, 1, 2, 3, 6]);
        assert_eq!(set.to_string(), "0-3,6");
        assert_eq!(CpuSet::parse("2,0,1,7,8").unwrap().to_string(), "0-2,7-8");
        assert_eq!(CpuSet::parse("5").unwrap().to_string(), "5");
    }

    #[test]
    fn two_spellings_of_the_same_cores_are_equal() {
        assert_eq!(
            CpuSet::parse("0,1,2").unwrap(),
            CpuSet::parse("0-2").unwrap()
        );
    }

    #[test]
    fn an_empty_list_is_the_empty_set() {
        assert!(CpuSet::parse("").unwrap().is_empty());
        assert!(CpuSet::parse("\n").unwrap().is_empty());
        assert_eq!(CpuSet::default().to_string(), "");
    }

    #[test]
    fn malformed_lists_are_refused() {
        assert_eq!(
            CpuSet::parse("3-1"),
            Err(CpuSetParseError::InvertedRange { first: 3, last: 1 })
        );
        for bad in ["a", "1-", "-1", "1-2-3", "1;2", "0x1"] {
            assert!(CpuSet::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_highest_id_prints_without_overflow() {
        let set = CpuSet::parse("4294967294-4294967295").unwrap();
        assert_eq!(set.to_string(), "4294967294-4294967295");
    }

    #[test]
    fn set_operations_and_serde() {
        let all = CpuSet::parse("0-7").unwrap();
        let taken = CpuSet::from_cores(&[CoreId(2), CoreId(3)]);
        assert_eq!(all.difference(&taken).to_string(), "0-1,4-7");
        assert_eq!(
            taken.union(&CpuSet::parse("6").unwrap()).to_string(),
            "2-3,6"
        );
        assert_eq!(all.first_shared(&taken), Some(2));
        assert_eq!(taken.first_shared(&CpuSet::parse("4").unwrap()), None);
        let json = serde_json::to_string(&all).unwrap();
        assert_eq!(json, "\"0-7\"");
        assert_eq!(serde_json::from_str::<CpuSet>(&json).unwrap(), all);
        assert!(serde_json::from_str::<CpuSet>("\"7-1\"").is_err());
    }
}
