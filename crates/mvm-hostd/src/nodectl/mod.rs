//! The node-control surface: what a fleet control plane may ask *this* host
//! about its own networking.
//!
//! Strictly node-local. Everything here is answered from state this node
//! owns and can verify: which machines are registered on it, under which
//! signed lease, and what its selected forwarding backend can actually
//! carry. Nothing here decides where a workload should run, allocates
//! anything fleet-wide, or answers a question about another node — those
//! are control-plane decisions and they live in the control plane.
//!
//! Two rules shape the whole module:
//!
//! - **The caller is identified by the kernel, not by the message.** A uid
//!   read off the connection is the only identity a Unix transport can
//!   prove, and a self-asserted one is not an identity at all.
//! - **A machine the caller does not own is answered as absent.** Not
//!   "forbidden": a refusal that distinguishes the two tells anyone who can
//!   connect which machines exist here.
//!
//! No shipped binary hosts this yet. The surface is per-node and the
//! daemons that exist are per-VM (`mvm-netd`) and per-tenant
//! (`mvm-host-agent`); hosting it in either would put it at the wrong
//! granularity. Everything below is exercised over real sockets, and the
//! listener's lifetime is the piece deliberately left to the process that
//! will own the node's state.

pub mod caller;
pub mod limits;
pub mod registry;
pub mod server;
pub mod service;
pub mod wire;

pub use caller::{CallerIdentity, peer_identity};
pub use limits::{MAX_REQUEST_FRAME_BYTES, MAX_RESPONSE_FRAME_BYTES, MEMORY_CEILING_BYTES};
pub use registry::{MAX_REGISTERED_MACHINES, MachineRecord, NodeRegistry, RegistryError};
pub use server::serve_connection;
pub use service::NodeControl;
pub use wire::{
    DescribeMachine, DescribeNode, ListMachines, MachineDescription, MachineList,
    NODE_CONTROL_VERSION, NodeControlEnvelope, NodeControlRequest, NodeControlResponse,
    NodeDescription, Refusal, RefusalReason, Unserved,
};
