use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::Mutex;
use tracing::{debug, error, info, instrument, warn};

use mvm_core::agent::{
    AgentRequest, AgentResponse, DesiredPool, DesiredState, DesiredTenant, DesiredTenantNetwork,
    MAX_DESIRED_PER_STATE, ReconcileReport,
};
use mvm_core::config::is_production_mode;
use mvm_core::instance::InstanceStatus;
use mvm_core::naming;
use mvm_core::observability::metrics;
use mvm_core::pool::{DesiredCounts, Role};
use mvm_core::tenant::TenantNet;
use mvm_runtime::security::{audit, certs, signing};
use mvm_runtime::shell;
use mvm_runtime::vm::instance::health;
use mvm_runtime::vm::instance::lifecycle::{
    instance_create, instance_list, instance_sleep, instance_start, instance_stop, instance_wake,
    instance_warm,
};
use mvm_runtime::vm::pool::lifecycle::{pool_create, pool_list, pool_load};
use mvm_runtime::vm::tenant::lifecycle::{
    tenant_create, tenant_destroy, tenant_exists, tenant_list, tenant_load,
};

use crate::sleep::policy;

// ============================================================================
// Constants
// ============================================================================

/// Default listen address for the QUIC API.
const DEFAULT_LISTEN: &str = "0.0.0.0:4433";

/// Maximum request frame size (1 MiB).
const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// Default rate limit: requests per second per connection.
const DEFAULT_RATE_LIMIT_RPS: u32 = 10;

/// Default maximum burst (token bucket capacity).
const DEFAULT_RATE_LIMIT_BURST: u32 = 20;

/// Default maximum concurrent connections.
const DEFAULT_MAX_CONNECTIONS: u32 = 100;

// ============================================================================
// Rate limiter
// ============================================================================

/// Token-bucket rate limiter for per-connection request throttling.
struct RateLimiter {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: tokio::time::Instant,
}

impl RateLimiter {
    fn new(rps: u32, burst: u32) -> Self {
        Self {
            tokens: burst as f64,
            max_tokens: burst as f64,
            refill_rate: rps as f64,
            last_refill: tokio::time::Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate-limited.
    fn try_acquire(&mut self) -> bool {
        let now = tokio::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Connection gate
// ============================================================================

/// Shared connection counter for global connection limits.
struct ConnectionGate {
    active: u32,
    max: u32,
}

impl ConnectionGate {
    fn new(max: u32) -> Self {
        Self { active: 0, max }
    }

    fn try_accept(&mut self) -> bool {
        if self.active < self.max {
            self.active += 1;
            true
        } else {
            false
        }
    }

    fn release(&mut self) {
        self.active = self.active.saturating_sub(1);
    }
}

// ============================================================================
// Frame protocol: length-prefixed JSON over QUIC bi-directional streams
// ============================================================================

/// Read a length-prefixed JSON frame from a QUIC recv stream.
async fn read_frame(recv: &mut quinn::RecvStream) -> Result<Vec<u8>> {
    // Read 4-byte big-endian length prefix
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .with_context(|| "Failed to read frame length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_FRAME_SIZE {
        anyhow::bail!("Frame too large: {} bytes (max {})", len, MAX_FRAME_SIZE);
    }

    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .with_context(|| "Failed to read frame body")?;

    Ok(buf)
}

/// Write a length-prefixed JSON frame to a QUIC send stream.
async fn write_frame(send: &mut quinn::SendStream, data: &[u8]) -> Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    send.write_all(&len)
        .await
        .with_context(|| "Failed to write frame length")?;
    send.write_all(data)
        .await
        .with_context(|| "Failed to write frame body")?;
    send.finish().with_context(|| "Failed to finish stream")?;
    Ok(())
}

// ============================================================================
// Request handler
// ============================================================================

/// Handle a single typed request and produce a response.
///
/// API surface is strictly: Reconcile, NodeInfo, NodeStats, TenantList,
/// InstanceList, WakeInstance. The typed enum prevents any imperative
/// or command-execution requests — unknown variants fail deserialization.
fn handle_request(request: AgentRequest) -> AgentResponse {
    let m = metrics::global();
    m.requests_total.fetch_add(1, Ordering::Relaxed);

    let request_type = match &request {
        AgentRequest::Reconcile(_) => "Reconcile",
        AgentRequest::NodeInfo => "NodeInfo",
        AgentRequest::NodeStats => "NodeStats",
        AgentRequest::TenantList => "TenantList",
        AgentRequest::InstanceList { .. } => "InstanceList",
        AgentRequest::WakeInstance { .. } => "WakeInstance",
        AgentRequest::ReconcileSigned(_) => "ReconcileSigned",
    };
    debug!(request_type, "Handling agent request");

    match request {
        AgentRequest::Reconcile(desired) => {
            m.requests_reconcile.fetch_add(1, Ordering::Relaxed);

            // In production mode, reject unsigned reconcile requests.
            if is_production_mode() {
                m.requests_failed.fetch_add(1, Ordering::Relaxed);
                warn!("Rejected unsigned Reconcile request in production mode");
                return AgentResponse::Error {
                    code: 403,
                    message: "Production mode requires signed desired state (use ReconcileSigned)"
                        .to_string(),
                };
            }

            info!(node_id = %desired.node_id, tenants = desired.tenants.len(), "Processing reconcile request");

            let validation_errors = validate_desired_state(&desired);
            if !validation_errors.is_empty() {
                m.requests_failed.fetch_add(1, Ordering::Relaxed);
                return AgentResponse::Error {
                    code: 400,
                    message: format!("Validation errors: {}", validation_errors.join("; ")),
                };
            }

            match reconcile_desired(&desired, desired.prune_unknown_tenants) {
                Ok(report) => AgentResponse::ReconcileResult(report),
                Err(e) => {
                    m.requests_failed.fetch_add(1, Ordering::Relaxed);
                    error!(error = %e, "Reconcile failed");
                    AgentResponse::Error {
                        code: 500,
                        message: format!("Reconcile failed: {}", e),
                    }
                }
            }
        }
        AgentRequest::NodeInfo => {
            m.requests_node_info.fetch_add(1, Ordering::Relaxed);
            debug!("Processing NodeInfo request");
            match crate::node::collect_info() {
                Ok(info) => AgentResponse::NodeInfo(info),
                Err(e) => {
                    m.requests_failed.fetch_add(1, Ordering::Relaxed);
                    AgentResponse::Error {
                        code: 500,
                        message: format!("Failed to collect node info: {}", e),
                    }
                }
            }
        }
        AgentRequest::NodeStats => {
            m.requests_node_stats.fetch_add(1, Ordering::Relaxed);
            debug!("Processing NodeStats request");
            match crate::node::collect_stats() {
                Ok(stats) => AgentResponse::NodeStats(stats),
                Err(e) => {
                    m.requests_failed.fetch_add(1, Ordering::Relaxed);
                    AgentResponse::Error {
                        code: 500,
                        message: format!("Failed to collect node stats: {}", e),
                    }
                }
            }
        }
        AgentRequest::TenantList => {
            m.requests_tenant_list.fetch_add(1, Ordering::Relaxed);
            debug!("Processing TenantList request");
            match tenant_list() {
                Ok(tenants) => AgentResponse::TenantList(tenants),
                Err(e) => {
                    m.requests_failed.fetch_add(1, Ordering::Relaxed);
                    AgentResponse::Error {
                        code: 500,
                        message: format!("Failed to list tenants: {}", e),
                    }
                }
            }
        }
        AgentRequest::InstanceList { tenant_id, pool_id } => {
            m.requests_instance_list.fetch_add(1, Ordering::Relaxed);
            debug!(tenant_id = %tenant_id, "Processing InstanceList request");
            let pools = match pool_id {
                Some(pid) => vec![pid],
                None => match pool_list(&tenant_id) {
                    Ok(p) => p,
                    Err(e) => {
                        m.requests_failed.fetch_add(1, Ordering::Relaxed);
                        return AgentResponse::Error {
                            code: 500,
                            message: format!("Failed to list pools: {}", e),
                        };
                    }
                },
            };

            let mut all = Vec::new();
            for pid in &pools {
                if let Ok(instances) = instance_list(&tenant_id, pid) {
                    all.extend(instances);
                }
            }
            AgentResponse::InstanceList(all)
        }
        AgentRequest::WakeInstance {
            tenant_id,
            pool_id,
            instance_id,
        } => {
            m.requests_wake.fetch_add(1, Ordering::Relaxed);
            info!(tenant_id = %tenant_id, pool_id = %pool_id, instance_id = %instance_id, "Processing WakeInstance request");
            match instance_wake(&tenant_id, &pool_id, &instance_id) {
                Ok(_) => AgentResponse::WakeResult { success: true },
                Err(e) => {
                    m.requests_failed.fetch_add(1, Ordering::Relaxed);
                    error!(error = %e, "Wake failed");
                    AgentResponse::Error {
                        code: 500,
                        message: format!("Wake failed: {}", e),
                    }
                }
            }
        }
        AgentRequest::ReconcileSigned(signed) => {
            m.requests_reconcile.fetch_add(1, Ordering::Relaxed);
            info!("Processing signed reconcile request");
            match signing::verify_and_extract::<DesiredState>(&signed) {
                Ok(desired) => match reconcile_desired(&desired, desired.prune_unknown_tenants) {
                    Ok(report) => AgentResponse::ReconcileResult(report),
                    Err(e) => {
                        m.requests_failed.fetch_add(1, Ordering::Relaxed);
                        error!(error = %e, "Signed reconcile failed");
                        AgentResponse::Error {
                            code: 500,
                            message: format!("Reconcile failed: {}", e),
                        }
                    }
                },
                Err(e) => {
                    m.requests_failed.fetch_add(1, Ordering::Relaxed);
                    error!(error = %e, "Signature verification failed");
                    AgentResponse::Error {
                        code: 403,
                        message: format!("Signature verification failed: {}", e),
                    }
                }
            }
        }
    }
}

// ============================================================================
// One-shot reconcile (CLI)
// ============================================================================

/// Run a single reconcile pass against a desired state file.
pub fn reconcile(desired_path: &str, prune: bool) -> Result<()> {
    let json = shell::run_in_vm_stdout(&format!("cat {}", desired_path))
        .with_context(|| format!("Failed to read desired state from {}", desired_path))?;
    let desired: DesiredState =
        serde_json::from_str(&json).with_context(|| "Failed to parse desired state JSON")?;

    let report = reconcile_desired(&desired, prune)?;

    if !report.tenants_created.is_empty() {
        println!("Created tenants: {}", report.tenants_created.join(", "));
    }
    if !report.tenants_pruned.is_empty() {
        println!("Pruned tenants: {}", report.tenants_pruned.join(", "));
    }
    if !report.pools_created.is_empty() {
        println!("Created pools: {}", report.pools_created.join(", "));
    }
    if report.instances_created > 0 {
        println!("Created {} instances", report.instances_created);
    }
    if report.instances_started > 0 {
        println!("Started {} instances", report.instances_started);
    }
    if report.instances_warmed > 0 {
        println!("Warmed {} instances", report.instances_warmed);
    }
    if report.instances_slept > 0 {
        println!("Slept {} instances", report.instances_slept);
    }
    if report.instances_stopped > 0 {
        println!("Stopped {} instances", report.instances_stopped);
    }
    if report.instances_deferred > 0 {
        println!(
            "Deferred {} instances (min-runtime not satisfied)",
            report.instances_deferred
        );
    }
    if !report.errors.is_empty() {
        eprintln!("Reconcile errors:");
        for err in &report.errors {
            eprintln!("  - {}", err);
        }
    }

    Ok(())
}

/// Generate a desired state JSON from existing tenants and pools on this node.
pub fn generate_desired(node_id: &str) -> Result<DesiredState> {
    let tenant_ids = tenant_list()?;
    let mut tenants = Vec::new();

    for tid in &tenant_ids {
        let tc = tenant_load(tid)?;
        let pool_ids = pool_list(tid)?;
        let mut pools = Vec::new();

        for pid in &pool_ids {
            let spec = pool_load(tid, pid)?;
            pools.push(DesiredPool {
                pool_id: spec.pool_id,
                flake_ref: spec.flake_ref,
                profile: spec.profile,
                role: spec.role,
                instance_resources: spec.instance_resources,
                desired_counts: spec.desired_counts,
                runtime_policy: spec.runtime_policy,
                seccomp_policy: spec.seccomp_policy,
                snapshot_compression: spec.snapshot_compression,
                routing_table: None,
                secret_scopes: vec![],
            });
        }

        tenants.push(DesiredTenant {
            tenant_id: tc.tenant_id,
            network: DesiredTenantNetwork {
                tenant_net_id: tc.net.tenant_net_id,
                ipv4_subnet: tc.net.ipv4_subnet,
            },
            quotas: tc.quotas,
            secrets_hash: None,
            pools,
        });
    }

    Ok(DesiredState {
        schema_version: 1,
        node_id: node_id.to_string(),
        tenants,
        prune_unknown_tenants: false,
        prune_unknown_pools: false,
    })
}

// ============================================================================
// Role-based reconcile ordering
// ============================================================================

/// Priority for reconcile ordering: lower = reconciled first.
/// Gateways must be up before workers can route traffic through them.
fn role_priority(role: &Role) -> u8 {
    match role {
        Role::Gateway => 0,
        Role::Builder => 1,
        Role::Worker => 2,
        Role::CapabilityImessage => 3,
    }
}

// ============================================================================
// Reconcile engine
// ============================================================================

/// Core reconcile logic, returns a report of what changed.
#[instrument(skip_all, fields(node_id = %desired.node_id, prune))]
fn reconcile_desired(desired: &DesiredState, prune: bool) -> Result<ReconcileReport> {
    let mut report = ReconcileReport::default();

    // Phase 0a: Detect stale PIDs and auto-transition dead instances to Stopped
    match health::detect_stale_pids() {
        Ok(stale) => {
            for s in &stale {
                warn!(
                    tenant_id = %s.tenant_id,
                    pool_id = %s.pool_id,
                    instance_id = %s.instance_id,
                    pid = s.recorded_pid,
                    "Auto-stopping stale instance (PID dead)"
                );
                if let Err(e) = instance_stop(&s.tenant_id, &s.pool_id, &s.instance_id) {
                    report.errors.push(format!(
                        "Failed to stop stale instance {}/{}/{}: {}",
                        s.tenant_id, s.pool_id, s.instance_id, e
                    ));
                } else {
                    report.instances_stopped += 1;
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "Stale PID detection failed (non-fatal)");
        }
    }

    // Phase 0b: Detect orphaned directories and log warnings
    match health::detect_orphans() {
        Ok(orphans) => {
            for o in &orphans {
                warn!(path = %o.path, reason = %o.reason, "Orphaned directory detected");
            }
        }
        Err(e) => {
            warn!(error = %e, "Orphan detection failed (non-fatal)");
        }
    }

    // Phase 0c: Rotate audit logs for all known tenants
    if let Ok(tids) = tenant_list() {
        for tid in &tids {
            if let Err(e) = audit::rotate_audit_log(tid) {
                warn!(tenant_id = %tid, error = %e, "Audit log rotation failed (non-fatal)");
            }
        }
    }

    // Phase 1: Ensure desired tenants exist
    for dt in &desired.tenants {
        if !tenant_exists(&dt.tenant_id)? {
            let subnet_parts: Vec<&str> = dt.network.ipv4_subnet.split('/').collect();
            let base_ip = subnet_parts.first().unwrap_or(&"10.240.0.0");
            let prefix = base_ip
                .rsplit_once('.')
                .map(|(p, _)| p)
                .unwrap_or("10.240.0");
            let gateway = format!("{}.1", prefix);

            let net = TenantNet::new(dt.network.tenant_net_id, &dt.network.ipv4_subnet, &gateway);

            if let Err(e) = tenant_create(&dt.tenant_id, net, dt.quotas.clone()) {
                report
                    .errors
                    .push(format!("Failed to create tenant {}: {}", dt.tenant_id, e));
                continue;
            }
            report.tenants_created.push(dt.tenant_id.clone());
        }

        // Phase 2: Ensure desired pools exist (sorted: gateways before workers)
        let mut sorted_pools: Vec<&DesiredPool> = dt.pools.iter().collect();
        sorted_pools.sort_by_key(|p| role_priority(&p.role));
        for dp in &sorted_pools {
            let pool_exists = pool_load(&dt.tenant_id, &dp.pool_id).is_ok();
            if !pool_exists {
                if let Err(e) = pool_create(
                    &dt.tenant_id,
                    &dp.pool_id,
                    &dp.flake_ref,
                    &dp.profile,
                    dp.instance_resources.clone(),
                    dp.role.clone(),
                    "",
                ) {
                    report.errors.push(format!(
                        "Failed to create pool {}/{}: {}",
                        dt.tenant_id, dp.pool_id, e
                    ));
                    continue;
                }
                report
                    .pools_created
                    .push(format!("{}/{}", dt.tenant_id, dp.pool_id));
            }

            // Phase 3: Scale instances to match desired counts
            if let Err(e) = reconcile_pool_instances(
                &dt.tenant_id,
                &dp.pool_id,
                &dp.desired_counts,
                &mut report,
            ) {
                report.errors.push(format!(
                    "Failed to reconcile {}/{}: {}",
                    dt.tenant_id, dp.pool_id, e
                ));
            }
        }

        // Phase 4: Prune unknown pools within this tenant
        if prune && desired.prune_unknown_pools {
            let desired_pool_ids: Vec<&str> = dt.pools.iter().map(|p| p.pool_id.as_str()).collect();
            if let Ok(existing_pools) = pool_list(&dt.tenant_id) {
                for pool_id in existing_pools {
                    if !desired_pool_ids.contains(&pool_id.as_str())
                        && let Err(e) = mvm_runtime::vm::pool::lifecycle::pool_destroy(
                            &dt.tenant_id,
                            &pool_id,
                            true,
                        )
                    {
                        report.errors.push(format!(
                            "Failed to prune pool {}/{}: {}",
                            dt.tenant_id, pool_id, e
                        ));
                    }
                }
            }
        }
    }

    // Phase 5: Prune unknown tenants
    if prune && desired.prune_unknown_tenants {
        let desired_tenant_ids: Vec<&str> = desired
            .tenants
            .iter()
            .map(|t| t.tenant_id.as_str())
            .collect();
        if let Ok(existing_tenants) = tenant_list() {
            for tid in existing_tenants {
                if !desired_tenant_ids.contains(&tid.as_str()) {
                    if let Err(e) = tenant_destroy(&tid, true) {
                        report
                            .errors
                            .push(format!("Failed to prune tenant {}: {}", tid, e));
                    } else {
                        report.tenants_pruned.push(tid);
                    }
                }
            }
        }
    }

    // Phase 6: Run sleep policy evaluation for each pool
    // Reverse role order: workers sleep before gateways
    for dt in &desired.tenants {
        let mut sleep_pools: Vec<&DesiredPool> = dt.pools.iter().collect();
        sleep_pools.sort_by_key(|p| std::cmp::Reverse(role_priority(&p.role)));
        for dp in &sleep_pools {
            if let Ok(decisions) = policy::evaluate_pool(&dt.tenant_id, &dp.pool_id) {
                for decision in decisions {
                    // Track deferrals (decisions that would have acted but min-runtime blocked)
                    if decision.action == policy::SleepAction::None
                        && decision.reason.contains("min_running_seconds")
                        || decision.reason.contains("min_warm_seconds")
                    {
                        report.instances_deferred += 1;
                        let m = metrics::global();
                        m.instances_deferred.fetch_add(1, Ordering::Relaxed);
                        let _ = audit::log_event(
                            &dt.tenant_id,
                            Some(&dp.pool_id),
                            Some(&decision.instance_id),
                            audit::AuditAction::TransitionDeferred,
                            Some(&decision.reason),
                        );
                        continue;
                    }

                    let result = match decision.action {
                        policy::SleepAction::Warm => {
                            instance_warm(&dt.tenant_id, &dp.pool_id, &decision.instance_id)
                                .map(|_| report.instances_warmed += 1)
                        }
                        policy::SleepAction::Sleep => {
                            instance_sleep(&dt.tenant_id, &dp.pool_id, &decision.instance_id, false)
                                .map(|_| report.instances_slept += 1)
                        }
                        policy::SleepAction::None => Ok(()),
                    };
                    if let Err(e) = result {
                        report.errors.push(format!(
                            "Sleep policy action failed for {}: {}",
                            decision.instance_id, e
                        ));
                    }
                }
            }
        }
    }

    Ok(report)
}

/// Reconcile instances within a pool to match desired counts.
fn reconcile_pool_instances(
    tenant_id: &str,
    pool_id: &str,
    desired: &DesiredCounts,
    report: &mut ReconcileReport,
) -> Result<()> {
    let instances = instance_list(tenant_id, pool_id)?;

    let mut running = Vec::new();
    let mut warm = Vec::new();
    let mut sleeping = Vec::new();
    let mut stopped = Vec::new();

    for inst in &instances {
        match inst.status {
            InstanceStatus::Running => running.push(inst.instance_id.clone()),
            InstanceStatus::Warm => warm.push(inst.instance_id.clone()),
            InstanceStatus::Sleeping => sleeping.push(inst.instance_id.clone()),
            InstanceStatus::Stopped => stopped.push(inst.instance_id.clone()),
            _ => {}
        }
    }

    // Scale up running instances
    let running_count = running.len() as u32;
    if running_count < desired.running {
        let needed = desired.running - running_count;

        // First, try to start stopped instances
        for id in stopped.iter().take(needed as usize) {
            match instance_start(tenant_id, pool_id, id) {
                Ok(_) => report.instances_started += 1,
                Err(e) => report.errors.push(format!("Failed to start {}: {}", id, e)),
            }
        }

        // If still need more, create new instances
        let started_from_stopped = needed.min(stopped.len() as u32);
        let still_needed = needed - started_from_stopped;
        for _ in 0..still_needed {
            match instance_create(tenant_id, pool_id) {
                Ok(id) => {
                    report.instances_created += 1;
                    match instance_start(tenant_id, pool_id, &id) {
                        Ok(_) => report.instances_started += 1,
                        Err(e) => report
                            .errors
                            .push(format!("Failed to start new {}: {}", id, e)),
                    }
                }
                Err(e) => report
                    .errors
                    .push(format!("Failed to create instance: {}", e)),
            }
        }
    }

    // Scale down running instances (stop excess)
    if running_count > desired.running {
        let excess = running_count - desired.running;
        for id in running.iter().rev().take(excess as usize) {
            match instance_stop(tenant_id, pool_id, id) {
                Ok(_) => report.instances_stopped += 1,
                Err(e) => report.errors.push(format!("Failed to stop {}: {}", id, e)),
            }
        }
    }

    Ok(())
}

/// Validate a desired state document.
///
/// Checks: schema version, ID format (via naming::validate_id), non-zero resources,
/// desired count caps (max 100 per pool per state).
pub fn validate_desired_state(desired: &DesiredState) -> Vec<String> {
    let mut errors = Vec::new();

    if desired.schema_version != 1 {
        errors.push(format!(
            "Unsupported schema version: {} (expected 1)",
            desired.schema_version
        ));
    }

    for tenant in &desired.tenants {
        if let Err(e) = naming::validate_id(&tenant.tenant_id, "Tenant") {
            errors.push(format!("Invalid tenant ID: {}", e));
        }
        for pool in &tenant.pools {
            if let Err(e) = naming::validate_id(&pool.pool_id, "Pool") {
                errors.push(format!(
                    "Invalid pool ID in tenant {}: {}",
                    tenant.tenant_id, e
                ));
            }
            if pool.instance_resources.vcpus == 0 {
                errors.push(format!(
                    "Pool {}/{} has 0 vCPUs",
                    tenant.tenant_id, pool.pool_id
                ));
            }
            // Cap desired counts to prevent resource exhaustion
            if pool.desired_counts.running > MAX_DESIRED_PER_STATE {
                errors.push(format!(
                    "Pool {}/{} running count {} exceeds max {}",
                    tenant.tenant_id,
                    pool.pool_id,
                    pool.desired_counts.running,
                    MAX_DESIRED_PER_STATE
                ));
            }
            if pool.desired_counts.warm > MAX_DESIRED_PER_STATE {
                errors.push(format!(
                    "Pool {}/{} warm count {} exceeds max {}",
                    tenant.tenant_id, pool.pool_id, pool.desired_counts.warm, MAX_DESIRED_PER_STATE
                ));
            }
            if pool.desired_counts.sleeping > MAX_DESIRED_PER_STATE {
                errors.push(format!(
                    "Pool {}/{} sleeping count {} exceeds max {}",
                    tenant.tenant_id,
                    pool.pool_id,
                    pool.desired_counts.sleeping,
                    MAX_DESIRED_PER_STATE
                ));
            }
        }
    }

    errors
}

// ============================================================================
// Agent daemon (tokio + QUIC + periodic reconcile)
// ============================================================================

/// Start the agent daemon with QUIC API server and periodic reconcile.
///
/// Spawns a tokio runtime with:
/// - QUIC mTLS server accepting typed requests
/// - Periodic reconcile task (reads desired state from file)
/// - SIGTERM handler for graceful shutdown
pub fn serve(
    interval_secs: u64,
    desired_path: Option<&str>,
    listen_addr: Option<&str>,
) -> Result<()> {
    // In production mode, refuse to start without TLS certs
    if is_production_mode() {
        let cert_missing = certs::load_server_config().is_err();
        if cert_missing {
            anyhow::bail!(
                "Production mode (MVM_PRODUCTION=1) requires mTLS certificates. \
                 Run 'mvm agent certs init' or provide --tls-cert/--tls-key/--tls-ca."
            );
        }
    }

    let addr: SocketAddr = listen_addr
        .unwrap_or(DEFAULT_LISTEN)
        .parse()
        .with_context(|| "Invalid listen address")?;

    let desired_file = desired_path.map(|s| s.to_string());

    // Build tokio runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .with_context(|| "Failed to create tokio runtime")?;

    runtime.block_on(async move { run_daemon(addr, interval_secs, desired_file).await })
}

/// Main daemon loop: QUIC server + periodic reconcile + shutdown handler.
async fn run_daemon(
    addr: SocketAddr,
    interval_secs: u64,
    desired_file: Option<String>,
) -> Result<()> {
    // Load mTLS server config
    let server_config = certs::load_server_config()
        .with_context(|| "Failed to load TLS certificates. Run 'mvm agent certs init' first.")?;

    let endpoint = quinn::Endpoint::server(server_config, addr)
        .with_context(|| format!("Failed to bind QUIC endpoint on {}", addr))?;

    info!(addr = %addr, "Agent listening");

    // Connection gate for global connection limits
    let conn_gate = Arc::new(Mutex::new(ConnectionGate::new(DEFAULT_MAX_CONNECTIONS)));

    // Shutdown signal
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    // Periodic reconcile task
    let reconcile_handle = if let Some(path) = desired_file.clone() {
        let handle = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;
                info!("Running periodic reconcile");
                let m = metrics::global();
                m.reconcile_runs.fetch_add(1, Ordering::Relaxed);
                let start = std::time::Instant::now();

                // Reconcile is synchronous (shell commands), run on blocking thread
                let path = path.clone();
                let result = tokio::task::spawn_blocking(move || reconcile(&path, true)).await;

                let duration_ms = start.elapsed().as_millis() as u64;
                m.reconcile_duration_ms
                    .store(duration_ms, Ordering::Relaxed);

                match result {
                    Ok(Ok(())) => info!(duration_ms, "Reconcile complete"),
                    Ok(Err(e)) => {
                        m.reconcile_errors.fetch_add(1, Ordering::Relaxed);
                        error!(error = %e, duration_ms, "Reconcile error");
                    }
                    Err(e) => {
                        m.reconcile_errors.fetch_add(1, Ordering::Relaxed);
                        error!(error = %e, "Reconcile task panicked");
                    }
                }
            }
        });
        Some(handle)
    } else {
        None
    };

    // Accept QUIC connections
    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                match incoming {
                    Some(conn) => {
                        let gate = conn_gate.clone();
                        if !gate.lock().await.try_accept() {
                            let m = metrics::global();
                            m.connections_rejected.fetch_add(1, Ordering::Relaxed);
                            warn!(max = DEFAULT_MAX_CONNECTIONS, "Connection rejected: limit reached");
                            conn.refuse();
                            continue;
                        }
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(conn, gate.clone()).await {
                                warn!(error = %e, "Connection error");
                            }
                            gate.lock().await.release();
                        });
                    }
                    None => break,
                }
            }
            _ = &mut shutdown => {
                info!("Received shutdown signal, stopping");
                break;
            }
        }
    }

    // Graceful shutdown
    endpoint.close(quinn::VarInt::from_u32(0), b"shutdown");
    if let Some(handle) = reconcile_handle {
        handle.abort();
    }
    info!("Agent stopped");
    Ok(())
}

/// Handle a single QUIC connection (may have multiple bi-directional streams).
#[instrument(skip_all)]
async fn handle_connection(
    incoming: quinn::Incoming,
    _conn_gate: Arc<Mutex<ConnectionGate>>,
) -> Result<()> {
    let m = metrics::global();
    m.connections_accepted.fetch_add(1, Ordering::Relaxed);

    let connection = incoming
        .await
        .with_context(|| "Failed to accept connection")?;

    debug!(remote = %connection.remote_address(), "Connection established");

    // Per-connection rate limiter
    let limiter = Arc::new(Mutex::new(RateLimiter::new(
        DEFAULT_RATE_LIMIT_RPS,
        DEFAULT_RATE_LIMIT_BURST,
    )));

    loop {
        let stream = connection.accept_bi().await;
        match stream {
            Ok((send, recv)) => {
                let limiter = limiter.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(send, recv, limiter).await {
                        warn!(error = %e, "Stream error");
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => break,
            Err(e) => {
                return Err(anyhow::anyhow!("Connection error: {}", e));
            }
        }
    }

    Ok(())
}

/// Handle a single bi-directional QUIC stream: read request, dispatch, write response.
#[instrument(skip_all)]
async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    limiter: Arc<Mutex<RateLimiter>>,
) -> Result<()> {
    let m = metrics::global();

    // Check rate limit before processing
    if !limiter.lock().await.try_acquire() {
        m.requests_rate_limited.fetch_add(1, Ordering::Relaxed);
        warn!("Request rate-limited");
        let response = AgentResponse::Error {
            code: 429,
            message: "Rate limit exceeded".to_string(),
        };
        let response_bytes = serde_json::to_vec(&response)?;
        write_frame(&mut send, &response_bytes).await?;
        return Ok(());
    }

    let frame = read_frame(&mut recv).await?;

    let request: AgentRequest =
        serde_json::from_slice(&frame).with_context(|| "Failed to parse request")?;

    // Dispatch to handler on blocking thread (reconcile calls shell commands)
    let response = tokio::task::spawn_blocking(move || handle_request(request))
        .await
        .with_context(|| "Handler task failed")?;

    let response_bytes =
        serde_json::to_vec(&response).with_context(|| "Failed to serialize response")?;

    write_frame(&mut send, &response_bytes).await?;

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::pool::{DesiredCounts, InstanceResources};

    #[test]
    fn test_desired_state_roundtrip() {
        let state = DesiredState {
            schema_version: 1,
            node_id: "node-1".to_string(),
            tenants: vec![DesiredTenant {
                tenant_id: "acme".to_string(),
                network: DesiredTenantNetwork {
                    tenant_net_id: 3,
                    ipv4_subnet: "10.240.3.0/24".to_string(),
                },
                quotas: Default::default(),
                secrets_hash: Some("abc123".to_string()),
                pools: vec![DesiredPool {
                    pool_id: "workers".to_string(),
                    flake_ref: "github:org/repo".to_string(),
                    profile: "minimal".to_string(),
                    role: Default::default(),
                    instance_resources: InstanceResources {
                        vcpus: 2,
                        mem_mib: 1024,
                        data_disk_mib: 0,
                    },
                    desired_counts: DesiredCounts {
                        running: 3,
                        warm: 1,
                        sleeping: 2,
                    },
                    runtime_policy: Default::default(),
                    seccomp_policy: "baseline".to_string(),
                    snapshot_compression: "zstd".to_string(),
                    routing_table: None,
                    secret_scopes: vec![],
                }],
            }],
            prune_unknown_tenants: true,
            prune_unknown_pools: true,
        };

        let json = serde_json::to_string_pretty(&state).unwrap();
        let parsed: DesiredState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_version, 1);
        assert_eq!(parsed.tenants.len(), 1);
        assert_eq!(parsed.tenants[0].pools[0].desired_counts.running, 3);
    }

    #[test]
    fn test_validate_desired_state_valid() {
        let state = DesiredState {
            schema_version: 1,
            node_id: "node-1".to_string(),
            tenants: vec![DesiredTenant {
                tenant_id: "acme".to_string(),
                network: DesiredTenantNetwork {
                    tenant_net_id: 3,
                    ipv4_subnet: "10.240.3.0/24".to_string(),
                },
                quotas: Default::default(),
                secrets_hash: None,
                pools: vec![DesiredPool {
                    pool_id: "workers".to_string(),
                    flake_ref: ".".to_string(),
                    profile: "minimal".to_string(),
                    role: Default::default(),
                    instance_resources: InstanceResources {
                        vcpus: 2,
                        mem_mib: 512,
                        data_disk_mib: 0,
                    },
                    desired_counts: DesiredCounts::default(),
                    runtime_policy: Default::default(),
                    seccomp_policy: "baseline".to_string(),
                    snapshot_compression: "none".to_string(),
                    routing_table: None,
                    secret_scopes: vec![],
                }],
            }],
            prune_unknown_tenants: false,
            prune_unknown_pools: false,
        };

        let errors = validate_desired_state(&state);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_desired_state_bad_version() {
        let state = DesiredState {
            schema_version: 99,
            node_id: "node-1".to_string(),
            tenants: vec![],
            prune_unknown_tenants: false,
            prune_unknown_pools: false,
        };

        let errors = validate_desired_state(&state);
        assert!(!errors.is_empty());
        assert!(errors[0].contains("schema version"));
    }

    #[test]
    fn test_validate_desired_state_empty_tenant_id() {
        let state = DesiredState {
            schema_version: 1,
            node_id: "node-1".to_string(),
            tenants: vec![DesiredTenant {
                tenant_id: "".to_string(),
                network: DesiredTenantNetwork {
                    tenant_net_id: 1,
                    ipv4_subnet: "10.240.1.0/24".to_string(),
                },
                quotas: Default::default(),
                secrets_hash: None,
                pools: vec![],
            }],
            prune_unknown_tenants: false,
            prune_unknown_pools: false,
        };

        let errors = validate_desired_state(&state);
        assert!(!errors.is_empty());
    }

    #[test]
    fn test_reconcile_report_default() {
        let report = ReconcileReport::default();
        assert_eq!(report.instances_created, 0);
        assert!(report.errors.is_empty());
    }

    #[test]
    fn test_agent_request_roundtrip() {
        let req = AgentRequest::NodeInfo;
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, AgentRequest::NodeInfo));
    }

    #[test]
    fn test_agent_request_reconcile_roundtrip() {
        let state = DesiredState {
            schema_version: 1,
            node_id: "n1".to_string(),
            tenants: vec![],
            prune_unknown_tenants: false,
            prune_unknown_pools: false,
        };
        let req = AgentRequest::Reconcile(state);
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, AgentRequest::Reconcile(_)));
    }

    #[test]
    fn test_agent_request_wake_roundtrip() {
        let req = AgentRequest::WakeInstance {
            tenant_id: "acme".to_string(),
            pool_id: "workers".to_string(),
            instance_id: "i-abc".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::WakeInstance {
                tenant_id,
                pool_id,
                instance_id,
            } => {
                assert_eq!(tenant_id, "acme");
                assert_eq!(pool_id, "workers");
                assert_eq!(instance_id, "i-abc");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_agent_response_roundtrip() {
        let resp = AgentResponse::Error {
            code: 404,
            message: "not found".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::Error { code, message } => {
                assert_eq!(code, 404);
                assert_eq!(message, "not found");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_agent_response_wake_result() {
        let resp = AgentResponse::WakeResult { success: true };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: AgentResponse = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentResponse::WakeResult { success } => assert!(success),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_all_request_variants_serialize() {
        let variants: Vec<AgentRequest> = vec![
            AgentRequest::Reconcile(DesiredState {
                schema_version: 1,
                node_id: "n".to_string(),
                tenants: vec![],
                prune_unknown_tenants: false,
                prune_unknown_pools: false,
            }),
            AgentRequest::NodeInfo,
            AgentRequest::NodeStats,
            AgentRequest::TenantList,
            AgentRequest::InstanceList {
                tenant_id: "t".to_string(),
                pool_id: None,
            },
            AgentRequest::WakeInstance {
                tenant_id: "t".to_string(),
                pool_id: "p".to_string(),
                instance_id: "i".to_string(),
            },
            AgentRequest::ReconcileSigned(mvm_core::signing::SignedPayload {
                payload: b"{}".to_vec(),
                signature: vec![0u8; 64],
                signer_id: "test".to_string(),
            }),
        ];

        for req in &variants {
            let json = serde_json::to_string(req).unwrap();
            let _: AgentRequest = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_all_response_variants_serialize() {
        let variants: Vec<AgentResponse> = vec![
            AgentResponse::ReconcileResult(ReconcileReport::default()),
            AgentResponse::NodeInfo(mvm_core::node::NodeInfo {
                node_id: "n".to_string(),
                hostname: "h".to_string(),
                arch: "aarch64".to_string(),
                total_vcpus: 4,
                total_mem_mib: 8192,
                lima_status: None,
                firecracker_version: None,
                jailer_available: false,
                cgroup_v2: false,
                attestation_provider: "none".to_string(),
            }),
            AgentResponse::NodeStats(mvm_core::node::NodeStats::default()),
            AgentResponse::TenantList(vec!["t1".to_string()]),
            AgentResponse::InstanceList(vec![]),
            AgentResponse::WakeResult { success: false },
            AgentResponse::Error {
                code: 500,
                message: "err".to_string(),
            },
        ];

        for resp in &variants {
            let json = serde_json::to_string(resp).unwrap();
            let _: AgentResponse = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_default_listen_addr() {
        let addr: SocketAddr = DEFAULT_LISTEN.parse().unwrap();
        assert_eq!(addr.port(), 4433);
    }

    #[test]
    fn test_max_frame_size() {
        assert_eq!(MAX_FRAME_SIZE, 1024 * 1024);
    }

    #[test]
    fn test_rate_limiter_allows_within_burst() {
        let mut limiter = RateLimiter::new(10, 5);
        // Should allow up to burst size
        for _ in 0..5 {
            assert!(limiter.try_acquire());
        }
        // Should reject after burst exhausted
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn test_rate_limiter_refills_over_time() {
        let mut limiter = RateLimiter::new(10, 5);
        // Exhaust all tokens
        for _ in 0..5 {
            limiter.try_acquire();
        }
        assert!(!limiter.try_acquire());

        // Simulate time passing by manipulating last_refill
        limiter.last_refill -= tokio::time::Duration::from_secs(1);

        // After 1 second at 10 rps, should have ~10 tokens (capped at burst=5)
        assert!(limiter.try_acquire());
    }

    #[test]
    fn test_connection_gate_accepts_within_limit() {
        let mut gate = ConnectionGate::new(3);
        assert!(gate.try_accept());
        assert!(gate.try_accept());
        assert!(gate.try_accept());
        assert!(!gate.try_accept());
    }

    #[test]
    fn test_connection_gate_release() {
        let mut gate = ConnectionGate::new(2);
        assert!(gate.try_accept());
        assert!(gate.try_accept());
        assert!(!gate.try_accept());
        gate.release();
        assert!(gate.try_accept());
    }

    #[test]
    fn test_rate_limit_constants() {
        assert_eq!(DEFAULT_RATE_LIMIT_RPS, 10);
        assert_eq!(DEFAULT_RATE_LIMIT_BURST, 20);
        assert_eq!(DEFAULT_MAX_CONNECTIONS, 100);
    }

    #[test]
    fn test_reconcile_creates_tenant_and_pool() {
        let (_guard, _fs) = mvm_runtime::shell_mock::mock_fs().install();

        let desired = DesiredState {
            schema_version: 1,
            node_id: "node-1".to_string(),
            tenants: vec![DesiredTenant {
                tenant_id: "acme".to_string(),
                network: DesiredTenantNetwork {
                    tenant_net_id: 3,
                    ipv4_subnet: "10.240.3.0/24".to_string(),
                },
                quotas: Default::default(),
                secrets_hash: None,
                pools: vec![DesiredPool {
                    pool_id: "workers".to_string(),
                    flake_ref: ".".to_string(),
                    profile: "minimal".to_string(),
                    role: Default::default(),
                    instance_resources: InstanceResources {
                        vcpus: 2,
                        mem_mib: 1024,
                        data_disk_mib: 0,
                    },
                    desired_counts: DesiredCounts {
                        running: 1,
                        warm: 0,
                        sleeping: 0,
                    },
                    runtime_policy: Default::default(),
                    seccomp_policy: "baseline".to_string(),
                    snapshot_compression: "none".to_string(),
                    routing_table: None,
                    secret_scopes: vec![],
                }],
            }],
            prune_unknown_tenants: false,
            prune_unknown_pools: false,
        };

        let report = reconcile_desired(&desired, false).unwrap();

        assert_eq!(report.tenants_created, vec!["acme"]);
        assert_eq!(report.pools_created, vec!["acme/workers"]);
        // Instance created but start fails (pool not built — no artifacts symlink)
        assert_eq!(report.instances_created, 1);
        assert!(report.errors.iter().any(|e| e.contains("not been built")));
    }

    #[test]
    fn test_reconcile_prunes_unknown_tenants() {
        let tenant_json =
            mvm_runtime::shell_mock::tenant_fixture("old-tenant", 5, "10.240.5.0/24", "10.240.5.1");
        let (_guard, _fs) = mvm_runtime::shell_mock::mock_fs()
            .with_file("/var/lib/mvm/tenants/old-tenant/tenant.json", &tenant_json)
            .install();

        let desired = DesiredState {
            schema_version: 1,
            node_id: "node-1".to_string(),
            tenants: vec![],
            prune_unknown_tenants: true,
            prune_unknown_pools: false,
        };

        let report = reconcile_desired(&desired, true).unwrap();
        assert_eq!(report.tenants_pruned, vec!["old-tenant"]);
    }

    #[test]
    fn test_reconcile_idempotent_existing_tenant() {
        let tenant_json =
            mvm_runtime::shell_mock::tenant_fixture("acme", 3, "10.240.3.0/24", "10.240.3.1");
        let pool_json = mvm_runtime::shell_mock::pool_fixture("acme", "workers");
        let (_guard, _fs) = mvm_runtime::shell_mock::mock_fs()
            .with_file("/var/lib/mvm/tenants/acme/tenant.json", &tenant_json)
            .with_file(
                "/var/lib/mvm/tenants/acme/pools/workers/pool.json",
                &pool_json,
            )
            .install();

        let desired = DesiredState {
            schema_version: 1,
            node_id: "node-1".to_string(),
            tenants: vec![DesiredTenant {
                tenant_id: "acme".to_string(),
                network: DesiredTenantNetwork {
                    tenant_net_id: 3,
                    ipv4_subnet: "10.240.3.0/24".to_string(),
                },
                quotas: Default::default(),
                secrets_hash: None,
                pools: vec![DesiredPool {
                    pool_id: "workers".to_string(),
                    flake_ref: ".".to_string(),
                    profile: "minimal".to_string(),
                    role: Default::default(),
                    instance_resources: InstanceResources {
                        vcpus: 2,
                        mem_mib: 1024,
                        data_disk_mib: 0,
                    },
                    desired_counts: DesiredCounts::default(),
                    runtime_policy: Default::default(),
                    seccomp_policy: "baseline".to_string(),
                    snapshot_compression: "none".to_string(),
                    routing_table: None,
                    secret_scopes: vec![],
                }],
            }],
            prune_unknown_tenants: false,
            prune_unknown_pools: false,
        };

        let report = reconcile_desired(&desired, false).unwrap();

        // Tenant already exists, should NOT be created
        assert!(report.tenants_created.is_empty());
        // Pool already exists, should NOT be created
        assert!(report.pools_created.is_empty());
        // No instances desired (counts all 0), none created
        assert_eq!(report.instances_created, 0);
    }

    #[test]
    fn test_production_rejects_unsigned_reconcile() {
        // Set production mode
        unsafe { std::env::set_var("MVM_PRODUCTION", "1") };

        let state = DesiredState {
            schema_version: 1,
            node_id: "n".to_string(),
            tenants: vec![],
            prune_unknown_tenants: false,
            prune_unknown_pools: false,
        };

        let resp = handle_request(AgentRequest::Reconcile(state));

        // Clean up before asserting
        unsafe { std::env::remove_var("MVM_PRODUCTION") };

        match resp {
            AgentResponse::Error { code, message } => {
                assert_eq!(code, 403);
                assert!(message.contains("signed"));
            }
            _ => panic!("Expected 403 error for unsigned reconcile in production mode"),
        }
    }

    #[test]
    fn test_reconcile_signed_roundtrip() {
        let signed = mvm_core::signing::SignedPayload {
            payload: b"test-payload".to_vec(),
            signature: vec![0u8; 64],
            signer_id: "coord-1".to_string(),
        };
        let req = AgentRequest::ReconcileSigned(signed);
        let json = serde_json::to_string(&req).unwrap();
        let parsed: AgentRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            AgentRequest::ReconcileSigned(s) => {
                assert_eq!(s.payload, b"test-payload");
                assert_eq!(s.signature.len(), 64);
                assert_eq!(s.signer_id, "coord-1");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_role_priority_ordering() {
        use mvm_core::pool::Role;
        assert!(role_priority(&Role::Gateway) < role_priority(&Role::Builder));
        assert!(role_priority(&Role::Builder) < role_priority(&Role::Worker));
        assert!(role_priority(&Role::Worker) < role_priority(&Role::CapabilityImessage));
    }

    #[test]
    fn test_reconcile_sorts_pools_by_role() {
        use mvm_core::pool::Role;
        let pools = [
            DesiredPool {
                pool_id: "workers".to_string(),
                flake_ref: ".".to_string(),
                profile: "minimal".to_string(),
                role: Role::Worker,
                instance_resources: InstanceResources {
                    vcpus: 1,
                    mem_mib: 512,
                    data_disk_mib: 0,
                },
                desired_counts: DesiredCounts::default(),
                runtime_policy: Default::default(),
                seccomp_policy: "baseline".to_string(),
                snapshot_compression: "none".to_string(),
                routing_table: None,
                secret_scopes: vec![],
            },
            DesiredPool {
                pool_id: "gateways".to_string(),
                flake_ref: ".".to_string(),
                profile: "minimal".to_string(),
                role: Role::Gateway,
                instance_resources: InstanceResources {
                    vcpus: 1,
                    mem_mib: 512,
                    data_disk_mib: 0,
                },
                desired_counts: DesiredCounts::default(),
                runtime_policy: Default::default(),
                seccomp_policy: "baseline".to_string(),
                snapshot_compression: "none".to_string(),
                routing_table: None,
                secret_scopes: vec![],
            },
        ];

        // Sort by role priority (same as reconcile does)
        let mut sorted: Vec<&DesiredPool> = pools.iter().collect();
        sorted.sort_by_key(|p| role_priority(&p.role));
        assert_eq!(sorted[0].pool_id, "gateways");
        assert_eq!(sorted[1].pool_id, "workers");

        // Reverse for sleep ordering
        let mut sleep_sorted: Vec<&DesiredPool> = pools.iter().collect();
        sleep_sorted.sort_by_key(|p| std::cmp::Reverse(role_priority(&p.role)));
        assert_eq!(sleep_sorted[0].pool_id, "workers");
        assert_eq!(sleep_sorted[1].pool_id, "gateways");
    }

    #[test]
    fn test_quickstart_desired_json() {
        let json = r#"{
            "schema_version": 1,
            "node_id": "node-1",
            "tenants": [
                {
                    "tenant_id": "acme",
                    "network": {
                        "tenant_net_id": 3,
                        "ipv4_subnet": "10.240.3.0/24"
                    },
                    "quotas": {
                        "max_vcpus": 16,
                        "max_mem_mib": 32768,
                        "max_running": 8,
                        "max_warm": 4,
                        "max_pools": 10,
                        "max_instances_per_pool": 32,
                        "max_disk_gib": 500
                    },
                    "pools": [
                        {
                            "pool_id": "workers",
                            "flake_ref": "github:org/app",
                            "profile": "minimal",
                            "instance_resources": {
                                "vcpus": 2,
                                "mem_mib": 1024,
                                "data_disk_mib": 0
                            },
                            "desired_counts": {
                                "running": 3,
                                "warm": 1,
                                "sleeping": 0
                            }
                        }
                    ]
                }
            ],
            "prune_unknown_tenants": false,
            "prune_unknown_pools": false
        }"#;
        let state: DesiredState = serde_json::from_str(json).unwrap();
        assert_eq!(state.schema_version, 1);
        assert_eq!(state.node_id, "node-1");
        assert_eq!(state.tenants.len(), 1);
        assert_eq!(state.tenants[0].tenant_id, "acme");
        assert_eq!(state.tenants[0].network.tenant_net_id, 3);
        assert_eq!(state.tenants[0].quotas.max_running, 8);
        assert_eq!(state.tenants[0].quotas.max_warm, 4);
        assert_eq!(state.tenants[0].pools.len(), 1);
        assert_eq!(state.tenants[0].pools[0].pool_id, "workers");
        assert_eq!(state.tenants[0].pools[0].desired_counts.running, 3);
        assert_eq!(state.tenants[0].pools[0].desired_counts.warm, 1);
    }
}
