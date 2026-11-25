//! Retired untyped full-VM restore dispatch surface.
//!
//! The active module is explicitly mapped to `retained_vm_full.rs`, where an
//! authenticated retained source is bound to a fresh child admission and one
//! concrete Firecracker or HVF implementation. This path remains in the source
//! footprint inventory to prevent an unreviewed generic restore module from
//! being reintroduced.
