use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

/// A guest-agent control-verb identifier: the stable `kind_name()` token
/// (non-empty kebab-case). Validated at construction so an `agent_verbs`
/// grant can never carry an unparseable verb.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct VerbId(String);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerbIdError {
    #[error("verb id is empty")]
    Empty,
    #[error("verb id '{0}' is not lowercase kebab-case ([a-z][a-z0-9-]*)")]
    Shape(String),
}

impl VerbId {
    pub fn new(s: &str) -> Result<Self, VerbIdError> {
        if s.is_empty() {
            return Err(VerbIdError::Empty);
        }
        let mut chars = s.chars();
        let first_ok = chars.next().is_some_and(|c| c.is_ascii_lowercase());
        let rest_ok = s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !first_ok || !rest_ok {
            return Err(VerbIdError::Shape(s.to_string()));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VerbId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for VerbId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        VerbId::new(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_id_accepts_kebab_and_rejects_junk() {
        assert_eq!(
            VerbId::new("run-entrypoint").unwrap().as_str(),
            "run-entrypoint"
        );
        assert_eq!(VerbId::new("ping").unwrap().as_str(), "ping");
        assert!(VerbId::new("").is_err());
        assert!(VerbId::new("Run_Entrypoint").is_err()); // caps + underscore
        assert!(VerbId::new("-lead").is_err());
        assert!(VerbId::new("has space").is_err());
    }

    #[test]
    fn verb_id_serde_is_transparent_string() {
        let v = VerbId::new("worker-status").unwrap();
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, "\"worker-status\"");
        let back: VerbId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn verb_id_deserialize_rejects_invalid() {
        assert!(serde_json::from_str::<VerbId>("\"BAD\"").is_err());
    }
}
