use std::sync::Mutex as StdMutex;

use chrono::TimeZone;

use super::*;

/// Keeps every entry it is asked to write.
#[derive(Default)]
struct Recorder(StdMutex<Vec<(LifecycleEvent, &'static str, LifecycleLabels)>>);

impl RefusalAudit for Recorder {
    fn record_refusal(
        &self,
        _tenant: &TenantId,
        event: LifecycleEvent,
        kind: &'static str,
        labels: LifecycleLabels,
    ) -> Result<()> {
        self.0.lock().unwrap().push((event, kind, labels));
        Ok(())
    }
}

struct TestClock(StdMutex<DateTime<Utc>>);

impl Clock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

struct Fixture {
    recorder: Arc<Recorder>,
    clock: Arc<TestClock>,
    throttle: ThrottledRefusals,
}

impl Fixture {
    fn new() -> Self {
        let recorder = Arc::new(Recorder::default());
        let clock = Arc::new(TestClock(StdMutex::new(
            Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap(),
        )));
        let throttle = ThrottledRefusals::new(recorder.clone(), clock.clone());
        Self {
            recorder,
            clock,
            throttle,
        }
    }

    fn advance(&self, by: chrono::Duration) {
        *self.clock.0.lock().unwrap() += by;
    }

    fn cell(&self, kind: &'static str, cell: &str) {
        self.throttle
            .record_refusal(
                &TenantId("acme".into()),
                LifecycleEvent::StateCellRefused,
                kind,
                LifecycleLabels::from([
                    (LifecycleLabel::Operation, "write".to_string()),
                    (LifecycleLabel::Cell, cell.to_string()),
                ]),
            )
            .unwrap();
    }

    fn entries(&self) -> Vec<(LifecycleEvent, &'static str, LifecycleLabels)> {
        self.recorder.0.lock().unwrap().clone()
    }
}

fn suppressed(labels: &LifecycleLabels) -> Option<&str> {
    labels.get(&LifecycleLabel::Suppressed).map(String::as_str)
}

#[test]
fn a_burst_is_one_entry_then_one_per_interval_with_the_count() {
    let f = Fixture::new();
    for _ in 0..100 {
        f.cell("not_writer", "setpoint");
    }
    assert_eq!(f.entries().len(), 1);
    assert_eq!(suppressed(&f.entries()[0].2), None);

    f.advance(REFUSAL_AUDIT_INTERVAL - chrono::Duration::milliseconds(1));
    f.cell("not_writer", "setpoint");
    assert_eq!(f.entries().len(), 1, "still inside the interval");

    f.advance(chrono::Duration::milliseconds(1));
    f.cell("not_writer", "setpoint");
    let entries = f.entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(suppressed(&entries[1].2), Some("100"));

    f.advance(REFUSAL_AUDIT_INTERVAL);
    f.cell("not_writer", "setpoint");
    assert_eq!(f.entries().len(), 3);
    assert_eq!(
        suppressed(&f.entries()[2].2),
        None,
        "nothing was dropped since"
    );
}

#[test]
fn each_distinct_kind_gets_its_first_entry_at_once() {
    let f = Fixture::new();
    f.cell("not_writer", "a");
    f.cell("unknown_cell", "a");
    f.cell("not_writer", "b");
    f.throttle
        .record_refusal(
            &TenantId("acme".into()),
            LifecycleEvent::LivenessSignalRefused,
            "no_period",
            LifecycleLabels::new(),
        )
        .unwrap();
    assert_eq!(f.entries().len(), 4);
}

#[test]
fn invented_cell_names_fold_into_one_kind_past_the_cap() {
    let f = Fixture::new();
    for n in 0..1000 {
        f.cell("unknown_cell", &format!("c{n}"));
    }
    // One entry per tracked kind, plus the first of the folded kind.
    assert_eq!(f.entries().len(), MAX_TRACKED_REFUSAL_KINDS + 1);
    assert_eq!(
        f.throttle.kinds.lock().unwrap().len(),
        MAX_TRACKED_REFUSAL_KINDS + 1
    );
    f.advance(REFUSAL_AUDIT_INTERVAL);
    f.cell("unknown_cell", "yet-another");
    let entries = f.entries();
    assert_eq!(entries.len(), MAX_TRACKED_REFUSAL_KINDS + 2);
    let folded = 1000 - MAX_TRACKED_REFUSAL_KINDS - 1;
    assert_eq!(
        suppressed(&entries.last().unwrap().2),
        Some(folded.to_string().as_str())
    );
}

#[test]
fn a_failed_write_is_retried_by_the_next_refusal() {
    struct Failing;
    impl RefusalAudit for Failing {
        fn record_refusal(
            &self,
            _: &TenantId,
            _: LifecycleEvent,
            _: &'static str,
            _: LifecycleLabels,
        ) -> Result<()> {
            bail!("signer down")
        }
    }
    let f = Fixture::new();
    let throttle = ThrottledRefusals::new(Arc::new(Failing), f.clock.clone());
    let refuse = || {
        throttle.record_refusal(
            &TenantId("acme".into()),
            LifecycleEvent::LivenessSignalRefused,
            "epoch",
            LifecycleLabels::new(),
        )
    };
    assert!(refuse().is_err());
    assert!(
        refuse().is_err(),
        "nothing was written, so nothing is suppressed"
    );
}
