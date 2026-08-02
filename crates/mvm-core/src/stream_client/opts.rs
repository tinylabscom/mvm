//! What a consumer asks for: which kinds, from which sequence, and whether
//! to keep reading after the producer goes quiet.

use mvm_protocol::stream::{StreamKind, StreamRecord};
use serde::{Deserialize, Serialize};

/// Which [`StreamKind`]s a consumer wants delivered.
///
/// One flag per kind rather than a set, so "all" and "none" are both
/// expressible and an unhandled kind cannot be silently forgotten when a
/// new one is added — the struct stops compiling instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KindFilter {
    /// Deliver [`StreamKind::Stdout`] records.
    pub stdout: bool,
    /// Deliver [`StreamKind::Stderr`] records.
    pub stderr: bool,
    /// Deliver [`StreamKind::Trace`] records.
    pub trace: bool,
}

impl KindFilter {
    /// Everything. The default: a consumer that did not choose sees the
    /// whole stream rather than a silently narrowed one.
    pub const fn all() -> Self {
        Self {
            stdout: true,
            stderr: true,
            trace: true,
        }
    }

    /// Nothing. Useful as a base to switch single kinds on.
    pub const fn none() -> Self {
        Self {
            stdout: false,
            stderr: false,
            trace: false,
        }
    }

    /// Exactly one kind.
    pub const fn only(kind: StreamKind) -> Self {
        let mut filter = Self::none();
        match kind {
            StreamKind::Stdout => filter.stdout = true,
            StreamKind::Stderr => filter.stderr = true,
            StreamKind::Trace => filter.trace = true,
        }
        filter
    }

    /// Turn one kind on, leaving the rest as they are.
    #[must_use]
    pub const fn with(mut self, kind: StreamKind) -> Self {
        match kind {
            StreamKind::Stdout => self.stdout = true,
            StreamKind::Stderr => self.stderr = true,
            StreamKind::Trace => self.trace = true,
        }
        self
    }

    /// Whether this filter admits `kind`.
    pub const fn matches(&self, kind: StreamKind) -> bool {
        match kind {
            StreamKind::Stdout => self.stdout,
            StreamKind::Stderr => self.stderr,
            StreamKind::Trace => self.trace,
        }
    }
}

impl Default for KindFilter {
    fn default() -> Self {
        Self::all()
    }
}

/// How a consumer wants to read one VM's stream.
///
/// Every field is applied *after* chain verification — see the module docs.
/// Built through [`StreamOpts::builder`] rather than positionally: two of the
/// three fields are optional and a bare constructor of three unrelated values
/// is the shape that gets transposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamOpts {
    /// Keep reading after the producer is momentarily quiet. `false`
    /// terminates once the broker reports the reader caught up.
    pub follow: bool,
    /// Drop records below this sequence number. The resume point after a
    /// consumer stops and reconnects.
    pub from_seq: Option<u64>,
    /// Which kinds to deliver.
    pub kinds: KindFilter,
}

impl StreamOpts {
    /// Start building. Defaults: do not follow, no resume point, all kinds.
    pub fn builder() -> StreamOptsBuilder {
        StreamOptsBuilder::default()
    }

    /// Whether `record` survives this consumer's filters. Sequence first —
    /// it is the cheaper test and the one that skips whole resumed prefixes.
    pub fn accepts(&self, record: &StreamRecord) -> bool {
        self.from_seq.is_none_or(|from| record.seq >= from) && self.kinds.matches(record.kind)
    }
}

/// Builder for [`StreamOpts`].
#[derive(Debug, Clone, Copy, Default)]
pub struct StreamOptsBuilder {
    follow: bool,
    from_seq: Option<u64>,
    kinds: Option<KindFilter>,
}

impl StreamOptsBuilder {
    /// Keep reading past the current end of the stream.
    #[must_use]
    pub fn follow(mut self, follow: bool) -> Self {
        self.follow = follow;
        self
    }

    /// Resume at `seq`, dropping everything below it.
    #[must_use]
    pub fn from_seq(mut self, seq: u64) -> Self {
        self.from_seq = Some(seq);
        self
    }

    /// Restrict delivery to `kinds`.
    #[must_use]
    pub fn kinds(mut self, kinds: KindFilter) -> Self {
        self.kinds = Some(kinds);
        self
    }

    /// Finish. An unset filter means every kind.
    pub fn build(self) -> StreamOpts {
        StreamOpts {
            follow: self.follow,
            from_seq: self.from_seq,
            kinds: self.kinds.unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_protocol::stream::StreamSource;

    fn record(seq: u64, kind: StreamKind) -> StreamRecord {
        StreamRecord {
            seq,
            source: StreamSource::Entrypoint,
            kind,
            host_unix_nanos: 1_000 + seq,
            prev_hash: [0u8; 32],
            payload: b"x".to_vec(),
        }
    }

    #[test]
    fn the_default_filter_admits_every_kind() {
        let filter = KindFilter::default();
        for kind in [StreamKind::Stdout, StreamKind::Stderr, StreamKind::Trace] {
            assert!(filter.matches(kind), "{kind:?}");
        }
    }

    #[test]
    fn only_admits_exactly_one_kind() {
        let filter = KindFilter::only(StreamKind::Stderr);
        assert!(filter.matches(StreamKind::Stderr));
        assert!(!filter.matches(StreamKind::Stdout));
        assert!(!filter.matches(StreamKind::Trace));
    }

    #[test]
    fn with_accumulates_kinds() {
        let filter = KindFilter::only(StreamKind::Stdout).with(StreamKind::Trace);
        assert!(filter.matches(StreamKind::Stdout));
        assert!(filter.matches(StreamKind::Trace));
        assert!(!filter.matches(StreamKind::Stderr));
    }

    #[test]
    fn default_opts_read_everything_once() {
        let opts = StreamOpts::default();
        assert!(!opts.follow);
        assert_eq!(opts.from_seq, None);
        assert!(opts.accepts(&record(0, StreamKind::Stdout)));
    }

    #[test]
    fn from_seq_drops_everything_below_the_resume_point() {
        let opts = StreamOpts::builder().from_seq(5).build();
        assert!(!opts.accepts(&record(4, StreamKind::Stdout)));
        assert!(opts.accepts(&record(5, StreamKind::Stdout)));
        assert!(opts.accepts(&record(6, StreamKind::Stdout)));
    }

    #[test]
    fn the_two_filters_compose() {
        let opts = StreamOpts::builder()
            .from_seq(5)
            .kinds(KindFilter::only(StreamKind::Stderr))
            .build();
        assert!(!opts.accepts(&record(9, StreamKind::Stdout)));
        assert!(!opts.accepts(&record(1, StreamKind::Stderr)));
        assert!(opts.accepts(&record(9, StreamKind::Stderr)));
    }

    #[test]
    fn opts_round_trip_through_serde() {
        let opts = StreamOpts::builder()
            .follow(true)
            .from_seq(12)
            .kinds(KindFilter::only(StreamKind::Trace))
            .build();
        let json = serde_json::to_string(&opts).expect("opts serialize");
        let back: StreamOpts = serde_json::from_str(&json).expect("opts deserialize");
        assert_eq!(opts, back);
    }

    #[test]
    fn opts_reject_an_unknown_field() {
        let json = r#"{"follow":false,"from_seq":null,"kinds":{"stdout":true,"stderr":true,"trace":true},"surprise":1}"#;
        assert!(serde_json::from_str::<StreamOpts>(json).is_err());
    }
}
