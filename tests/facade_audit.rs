//! Facade audit — pin the `mvmctl::*` paths the `mvmd`
//! consumer contract relies on.
//!
//! Architectural invariant #2 (cross-repo plan
//! `~/.claude/plans/what-do-we-need-deep-dolphin.md`): mvmd depends on
//! the `mvmctl` facade, not on internal mvm crates. Moving a symbol
//! out from under one of these paths is a contract break that must be
//! caught here — not by a downstream `cargo check` in `../mvmd`.
//!
//! Drift surfaces as a compile error pointing at the missing path; the
//! fix is a re-export on the facade (preferred) or a coordinated rename
//! on both sides — never a dual-export.
//!
//! Spot-check list sourced from
//! `../mvmd/specs/plans/31-mvmd-sandbox-management-kickoff.md` §Track A.

use mvmctl::core::agent::{AgentRequest, AgentResponse, DesiredState};
use mvmctl::core::config::is_production_mode;
use mvmctl::core::instance::{InstanceState, InstanceStatus};
use mvmctl::core::observability::metrics;
use mvmctl::core::pool::{DesiredCounts, RuntimePolicy};
use mvmctl::core::protocol::{HostdRequest, HostdResponse};
use mvmctl::core::tenant::TenantQuota;
use mvmctl::runtime::shell;

#[test]
fn plan31_track_a_facade_paths_resolve() {
    // The use-statements above are the assertion; this body keeps each
    // import alive against dead-code lints and pins a representative
    // item from every module path.
    let _ = std::mem::size_of::<AgentRequest>();
    let _ = std::mem::size_of::<AgentResponse>();
    let _ = std::mem::size_of::<DesiredState>();
    let _ = std::mem::size_of::<InstanceState>();
    let _ = std::mem::size_of::<InstanceStatus>();
    let _ = std::mem::size_of::<DesiredCounts>();
    let _ = std::mem::size_of::<RuntimePolicy>();
    let _ = std::mem::size_of::<TenantQuota>();
    let _ = std::mem::size_of::<HostdRequest>();
    let _ = std::mem::size_of::<HostdResponse>();

    let _: fn() -> bool = is_production_mode;
    let _: fn() -> &'static metrics::Metrics = metrics::global;
    let _: fn(&str) -> String = shell::shell_quote;
}
