//! Tool-invocation bindings on a FlowMux session: ending the streams an
//! invocation opened once its binding is released, and keeping datagrams off
//! a tool's routes.

use std::net::IpAddr;

use mvm_contract::protocol::network_flow::attribution::ToolInvocationBinding;

use super::{FlowMuxError, FlowMuxSession, registry};

/// A TCP stream opened under an invocation's binding.
pub(super) struct BoundStream {
    pub(super) binding: ToolInvocationBinding,
    pub(super) target: String,
}

impl FlowMuxSession {
    /// Tear down a stream whose invocation binding has been released.
    /// `Ok(true)` means the stream is gone and the frame must be dropped.
    pub(super) fn end_released_binding(&mut self, stream_id: u32) -> Result<bool, FlowMuxError> {
        let Some(bound) = self.bound_streams.get(&stream_id) else {
            return Ok(false);
        };
        let live = self.substitution.as_ref().is_some_and(|service| {
            service
                .attribute(Some(bound.binding.clone()))
                .tool()
                .is_some()
        });
        if live {
            return Ok(false);
        }
        let target = bound.target.clone();
        self.bound_streams.remove(&stream_id);
        self.reset_host_stream(stream_id, "tool invocation ended")?;
        self.deny_unrouted_flow(
            stream_id,
            registry::FlowClass::Tcp,
            &target,
            "tool_binding_released",
        );
        Ok(true)
    }

    /// Whether a datagram to `ip:port` would use a tool's route. A datagram
    /// carries no invocation binding, so it is never one tool's flow; the
    /// decision fails closed when the rules declare routes and cannot be run.
    pub(super) fn udp_reaches_tool_route(&self, ip: IpAddr, port: u16) -> bool {
        let Some(service) = self
            .substitution
            .as_ref()
            .filter(|s| s.declares_tool_routes())
        else {
            return false;
        };
        let Some(runtime) = &self.runtime_handle else {
            return true;
        };
        let unattributed = crate::supervisor::network_endpoint_proxy::FlowAttribution::default();
        !matches!(
            runtime.block_on(service.tool_route_scope(&ip.to_string(), port, &unattributed)),
            mvm_contract::policy::tool_rules::RouteScope::Unscoped
        )
    }
}
