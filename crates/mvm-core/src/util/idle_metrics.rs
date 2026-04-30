use serde::{Deserialize, Serialize};

/// Per-instance idle metrics used by sleep policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdleMetrics {
    pub idle_secs: u64,
    pub cpu_pct: f32,
    pub net_bytes: u64,
    pub last_updated: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idle_metrics_default() {
        let m = IdleMetrics::default();
        assert_eq!(m.idle_secs, 0);
        assert_eq!(m.cpu_pct, 0.0);
        assert_eq!(m.net_bytes, 0);
        assert!(m.last_updated.is_none());
    }

    #[test]
    fn test_idle_metrics_roundtrip() {
        let m = IdleMetrics {
            idle_secs: 300,
            cpu_pct: 2.5,
            net_bytes: 4096,
            last_updated: Some("2025-01-01T00:00:00Z".to_string()),
        };
        let json = serde_json::to_string(&m).unwrap();
        let parsed: IdleMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.idle_secs, 300);
        assert_eq!(parsed.cpu_pct, 2.5);
    }
}
