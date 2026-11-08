//! Live interaction-latency gate. Boots one real VM, measures cold + warm Ping
//! RTT over vsock, and asserts the steady-interaction invariants. Runs only
//! under `libkrun-live` on a host where libkrun boots; excluded from stock
//! builds, so it never fabricates a number.

#![cfg(feature = "libkrun-live")]

use mvm_cli::bench::interaction::{InteractionRunCfg, WARM_RPC_P50_BUDGET_MS, run_instant_loop};
use mvm_cli::bench::write_report_with_latest;
