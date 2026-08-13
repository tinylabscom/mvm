//! CPU quota scheduling for vCPUs.
//!
//! A pure policy layer, a thread CPU clock, and a controller that drives the
//! run loop's throttle hold. All policy arithmetic is integer-only; no floating
//! point appears in any signed or serialized payload.

pub mod policy;

pub use policy::{PeriodVerdict, QuotaConfig, QuotaPolicy};
