//! Explicit session completion releases flow owners before flushing audit health.

use super::{
    FlowMuxError, FlowMuxSession, lock_pending_ingress, lock_tcp_streams, lock_udp_associations,
};

impl FlowMuxSession {
    pub(super) fn finish_session(
        &mut self,
        result: Result<(), FlowMuxError>,
    ) -> Result<(), FlowMuxError> {
        self.session_closed
            .store(true, std::sync::atomic::Ordering::Release);
        // Wake a relay blocked writing to a peer that stopped reading.
        if let Err(error) = self.reader.stream().shutdown(std::net::Shutdown::Both) {
            tracing::debug!(%error, "FlowMux transport already closed at completion");
        }
        lock_pending_ingress(&self.pending_ingress).clear();
        // An in-progress open can install a relay; wait for it before draining.
        let activity = std::sync::Arc::clone(&self.ingress_activity);
        let _activity = activity.lock().expect("ingress owner poisoned");
        let cancellations = std::mem::take(
            &mut *self
                .http_cancellations
                .lock()
                .expect("HTTP cancellation owner poisoned"),
        );
        for (_, sender) in cancellations {
            let _ = sender.send(true);
        }
        self.http_flows.clear();
        let tcp_ids: Vec<_> = lock_tcp_streams(&self.streams).keys().copied().collect();
        for id in tcp_ids {
            self.remove_stream(id);
        }
        let mut associations = std::mem::take(&mut *lock_udp_associations(&self.udp_associations));
        for owner in associations.values_mut() {
            owner.cancel();
        }
        for (stream_id, mut owner) in associations {
            owner.join(stream_id);
            let _ = super::lock_registry(&self.registry).retire(stream_id);
        }
        self.audit_sink.flush_health().map_err(|error| {
            tracing::warn!(%error, "FlowMux audit health flush failed at session completion");
            FlowMuxError::Audit(error)
        })?;
        result
    }
}
