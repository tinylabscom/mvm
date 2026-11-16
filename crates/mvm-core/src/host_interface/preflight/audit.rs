//! Launch-time audit check, performed against the endpoint's actual bound sink.
//!
//! Policy admission happens before the endpoint exists. This check belongs to
//! the later enforcement-readiness boundary; a policy-time boolean cannot
//! substitute for successfully appending through the sink that will serve.

use std::collections::BTreeMap;

use crate::audit_sink::AuditSink;

use super::Denial;

/// Require a usable bound audit sink before exposing an endpoint's readiness.
///
/// # Errors
///
/// Missing sinks and failed journal appends both refuse the launch.
pub fn check(sink: Option<&dyn AuditSink>) -> Result<(), Denial> {
    let sink = sink.ok_or(Denial::CheckMissing("audit-sink"))?;
    sink.record("host.audit.ready", BTreeMap::new())
        .map_err(|_| Denial::AuditUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::Mutex;

    struct Sink {
        fails: bool,
        events: Mutex<Vec<String>>,
    }

    impl AuditSink for Sink {
        fn record(&self, event: &str, _labels: BTreeMap<String, String>) -> io::Result<()> {
            self.events.lock().unwrap().push(event.into());
            if self.fails {
                Err(io::Error::other("journal unavailable"))
            } else {
                Ok(())
            }
        }

        fn suppress_denial(&self) {}

        fn flush_health(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn missing_sink_refuses_instead_of_skipping_the_required_check() {
        assert_eq!(check(None), Err(Denial::CheckMissing("audit-sink")));
    }

    #[test]
    fn a_present_sink_whose_actual_write_fails_is_not_ready() {
        let sink = Sink {
            fails: true,
            events: Mutex::new(Vec::new()),
        };
        assert_eq!(check(Some(&sink)), Err(Denial::AuditUnavailable));
        assert_eq!(*sink.events.lock().unwrap(), ["host.audit.ready"]);
    }

    #[test]
    fn readiness_is_established_through_the_sink_that_will_serve() {
        let sink = Sink {
            fails: false,
            events: Mutex::new(Vec::new()),
        };
        check(Some(&sink)).unwrap();
        assert_eq!(*sink.events.lock().unwrap(), ["host.audit.ready"]);
    }
}
