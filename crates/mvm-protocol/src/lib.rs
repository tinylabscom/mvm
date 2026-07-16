#![no_std]
#![forbid(unsafe_code)]
//! no_std + alloc core for mvm. Currently the chain-signed audit-log
//! verifier; the Workload IR, wire protocol, and policy DTOs land here
//! incrementally. Builds on wasm32 so the same logic runs in a browser.

extern crate alloc;

pub mod verify;
