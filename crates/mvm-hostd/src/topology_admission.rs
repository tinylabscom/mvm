//! Host admission of a signed topology generation.
//!
//! A topology names a whole deployment, so it is admitted once, before any of
//! its units boots from its own plan. Admission runs, in order: the signature
//! against the signers a plan may carry (the host's own key and the operator's
//! pinned plan signers), the tenant, the validity window against the caller's
//! clock, the generation against the last one admitted for the tenant, the
//! backend's enforcement of every stated requirement, the host's cores against
//! every exclusive placement, and the host budget over
//! the sum of the units. Every state cell the topology declares is then
//! reserved at full size in the host's cell store. Only then is the generation sealed into a record and
//! `topology.admitted` written to the tenant's chain.
//!
//! Every refusal writes `topology.admission_refused` with the stage and the
//! reason, and persists nothing. Before the signature verifies, the body is an
//! unauthenticated claim, so a refusal at that stage records only the hash of
//! the bytes presented, never a digest or generation read out of them.
//!
//! Re-admitting the generation already on record with the same digest is
//! idempotent: every check runs again, but nothing is rewritten and no second
//! `topology.admitted` is written, because nothing new was authorized.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;
use mvm_contract::assurance::Sha256Digest;
use mvm_contract::grants::budget::MachineCharge;
use mvm_contract::plan::topology::{
    MeasuredFailoverMs, SignedTopology, Topology, check_requirements, sign_topology,
    verify_topology,
};
use mvm_contract::protocol::resource_controls::ResourceControls;
use mvm_contract::protocol::vm_backend::BackendKind;
use mvm_core::plan::TenantId;
use mvm_core::time::Clock;

use crate::audit::emitter::AuditEmitter;
use crate::audit::host_keypair::host_signer_id;

pub(crate) mod placement;
mod record;
pub use placement::{
    HostCpus, HostPlacementRefusal, LiveMachine, PlacementOwner, exclusive_cores_held_on_host,
};
pub use record::AdmittedTopologyRecord;

/// Chain event for an admitted topology generation.
pub const TOPOLOGY_ADMITTED_EVENT: &str = "topology.admitted";
/// Chain event for a refused topology generation.
pub const TOPOLOGY_ADMISSION_REFUSED_EVENT: &str = "topology.admission_refused";

/// Name the transient budget hold is taken under. It is released before
/// admission returns: each unit reserves its own capacity when its plan is
/// admitted, so the topology only proves that the whole system fits now.
const BUDGET_PROBE_NAME: &str = "topology-admission";

/// Where admission stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalStage {
    Tenant,
    Signature,
    Window,
    Generation,
    Requirements,
    Budget,
    StateCells,
    Record,
}

impl RefusalStage {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Signature => "signature",
            Self::Window => "validity_window",
            Self::Generation => "generation",
            Self::Requirements => "requirements",
            Self::Budget => "budget",
            Self::StateCells => "state_cells",
            Self::Record => "record",
        }
    }
}

impl std::fmt::Display for RefusalStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A topology the host refused. The returned error's root cause, so a caller
/// can `downcast_ref` it even when the refusal's own audit write failed.
#[derive(Debug, thiserror::Error)]
#[error("topology admission refused at {stage}: {reason}")]
pub struct TopologyRefused {
    pub stage: RefusalStage,
    pub reason: String,
}

fn refused(stage: RefusalStage, reason: impl std::fmt::Display) -> TopologyRefused {
    TopologyRefused {
        stage,
        reason: reason.to_string(),
    }
}

/// What to admit and against what.
pub struct TopologyAdmissionRequest<'a> {
    /// The tenant the caller is admitting for. The topology must name the
    /// same one, and every entry goes to this tenant's chain.
    pub tenant: &'a TenantId,
    pub signed: &'a SignedTopology,
    /// The backend the units will run on; its declared controls decide which
    /// requirements are enforced.
    pub backend: BackendKind,
    /// The failover time measured on this host and backend, if any.
    pub measured_failover: Option<MeasuredFailoverMs>,
    /// This host's cores and whether its spawn scope can carry an
    /// allowed-CPU set, its isolated cores and its running machines;
    /// [`HostCpus::probe`] outside tests.
    pub host_cpus: &'a HostCpus,
    pub clock: &'a dyn Clock,
    /// Where the host signer lives; `None` for the default keys directory.
    pub host_signer_keys_dir: Option<&'a Path>,
    pub emitter: &'a AuditEmitter,
}

/// An admitted generation and where its sealed record lives.
#[derive(Debug, Clone)]
pub struct AdmittedTopology {
    pub topology: Topology,
    pub digest: Sha256Digest,
    pub signer_id: String,
    pub record_path: PathBuf,
}

/// How an admission succeeded.
#[derive(Debug, Clone)]
pub enum TopologyAdmission {
    /// A new generation, sealed and audited.
    Admitted(AdmittedTopology),
    /// The generation on record, with the same digest. Nothing was written.
    AlreadyAdmitted(AdmittedTopology),
}

/// The signers a topology may be signed by: the host's own key, which signs
/// locally, and the operator's pinned plan signers, which sign in managed
/// mode. The same two sets plan admission trusts, read from the same places.
pub fn trusted_topology_signers(
    host_signer_keys_dir: Option<&Path>,
) -> Result<Vec<(String, VerifyingKey)>> {
    let host = load_host_signer(host_signer_keys_dir)?;
    let mut trusted = vec![(host_signer_id(), host.verifying)];
    trusted.extend(mvm_core::user_config::load(None).trusted_plan_signer_keys()?);
    Ok(trusted)
}

/// Sign `topology` with the host signer, as a local deployment does.
pub fn sign_topology_as_host(
    topology: &Topology,
    host_signer_keys_dir: Option<&Path>,
) -> Result<SignedTopology> {
    let host = load_host_signer(host_signer_keys_dir)?;
    sign_topology(topology, &host.signing, &host_signer_id()).context("signing the topology")
}

/// The highest generation admitted for `tenant` under `home`, verified again
/// against the trusted signers, or `None` when none has been admitted.
///
/// # Errors
///
/// A tenant that is not one path component, whose topology store cannot be
/// named; a record that cannot be read, does not verify, or whose digest is
/// not the one it was sealed with.
pub(crate) fn last_admitted_topology(
    home: &Path,
    tenant: &TenantId,
    host_signer_keys_dir: Option<&Path>,
) -> Result<Option<Topology>> {
    crate::audit::prune_pins::validate_tenant(&tenant.0).with_context(|| {
        format!(
            "tenant {:?} is not a single path component, so no topology store can be named",
            tenant.0
        )
    })?;
    let Some(last) = record::last_admitted(home, &tenant.0)? else {
        return Ok(None);
    };
    let trusted = trusted_topology_signers(host_signer_keys_dir)?;
    let trusted_refs: Vec<(&str, &VerifyingKey)> =
        trusted.iter().map(|(id, key)| (id.as_str(), key)).collect();
    let topology = verify_topology(&last.signed, &trusted_refs)
        .with_context(|| format!("verifying admitted topology generation {}", last.generation))?;
    anyhow::ensure!(
        topology.digest() == last.digest,
        "admitted topology generation {} does not have the digest it was sealed with",
        last.generation
    );
    Ok(Some(topology))
}

fn load_host_signer(dir: Option<&Path>) -> Result<crate::audit::host_keypair::HostSigner> {
    match dir {
        Some(dir) => crate::audit::host_keypair::load_or_init_at(dir),
        None => crate::audit::host_keypair::load_or_init(),
    }
}

/// Admit one signed topology generation. See the module docs for the order
/// and the outcomes.
///
/// # Errors
///
/// A [`TopologyRefused`] for every refusal, audited. If the refusal's audit
/// write fails too, the refusal still stands and the error says both. If the
/// admitted entry cannot be written, the new record is withdrawn and the
/// admission fails: no generation is admitted without its entry.
pub fn admit_topology(request: &TopologyAdmissionRequest<'_>) -> Result<TopologyAdmission> {
    // A tenant that is not one path component names no chain this host could
    // write to, so this one refusal cannot be audited.
    if crate::audit::prune_pins::validate_tenant(&request.tenant.0).is_err() {
        return Err(refused(
            RefusalStage::Tenant,
            "the tenant is not a single path component, so no audit chain can be named",
        )
        .into());
    }
    let mut known = None;
    match decide(request, &mut known) {
        Ok(Decision::Same(admitted)) => Ok(TopologyAdmission::AlreadyAdmitted(admitted)),
        Ok(Decision::New {
            admitted,
            reserved,
            lock,
        }) => {
            let audited = audit_admitted(request, &admitted);
            let result = match audited {
                Ok(()) => Ok(TopologyAdmission::Admitted(admitted)),
                Err(audit) => {
                    crate::state_cells::release(&reserved);
                    Err(withdraw(&admitted.record_path, audit))
                }
            };
            drop(lock);
            result
        }
        Err(refusal) => Err(audit_refusal(request, known.as_ref(), refusal)),
    }
}

enum Decision {
    New {
        admitted: AdmittedTopology,
        /// Cells this admission created, removed again if it fails.
        reserved: Vec<PathBuf>,
        lock: mvm_core::atomic_io::FileLock,
    },
    Same(AdmittedTopology),
}

/// The digest and generation of a topology whose signature verified.
struct Known {
    digest: Sha256Digest,
    generation: u64,
}

fn decide(
    request: &TopologyAdmissionRequest<'_>,
    known: &mut Option<Known>,
) -> Result<Decision, TopologyRefused> {
    let tenant = request.tenant.0.as_str();
    let (topology, signer_id) = verify(request)?;
    let digest = topology.digest();
    *known = Some(Known {
        digest: digest.clone(),
        generation: topology.generation,
    });
    if topology.tenant != *request.tenant {
        return Err(refused(
            RefusalStage::Tenant,
            format_args!(
                "the topology names tenant {} but admission is for {tenant}",
                topology.tenant.0
            ),
        ));
    }
    check_window(&topology, request.clock.now())?;

    let home = mvm_core::config::mvm_home_strict().map_err(|e| {
        refused(
            RefusalStage::Record,
            format_args!("resolving the mvm home: {e}"),
        )
    })?;
    let lock =
        record::lock(&home).map_err(|e| refused(RefusalStage::Record, format_args!("{e:#}")))?;
    let last = record::last_admitted(&home, tenant)
        .map_err(|e| refused(RefusalStage::Record, format_args!("{e:#}")))?;
    let same = check_generation(&topology, &digest, last.as_ref())?;

    check_requirements(
        &topology,
        ResourceControls::on_host(request.backend, request.host_cpus.scope_cpuset),
        request.measured_failover,
    )
    .map_err(|unmet| refused(RefusalStage::Requirements, unmet))?;
    check_placement(request, &home, &topology)?;
    check_budget(&topology)?;

    if let Some(last) = same.then_some(last).flatten() {
        return Ok(Decision::Same(AdmittedTopology {
            topology,
            digest,
            signer_id: last.signer_id,
            record_path: record::record_path(&home, tenant, last.generation),
        }));
    }
    let new = AdmittedTopologyRecord {
        generation: topology.generation,
        digest: digest.clone(),
        signer_id: signer_id.clone(),
        admitted_at: request.clock.now(),
        signed: request.signed.clone(),
    };
    let reserved = crate::state_cells::reserve(&home, &topology)
        .map_err(|e| refused(RefusalStage::StateCells, format_args!("{e:#}")))?;
    let record_path = record::persist(&home, tenant, &new).map_err(|e| {
        crate::state_cells::release(&reserved);
        refused(RefusalStage::Record, format_args!("{e:#}"))
    })?;
    Ok(Decision::New {
        admitted: AdmittedTopology {
            topology,
            digest,
            signer_id,
            record_path,
        },
        reserved,
        lock,
    })
}

fn verify(request: &TopologyAdmissionRequest<'_>) -> Result<(Topology, String), TopologyRefused> {
    let trusted = trusted_topology_signers(request.host_signer_keys_dir).map_err(|e| {
        refused(
            RefusalStage::Signature,
            format_args!("loading the trusted signers: {e:#}"),
        )
    })?;
    let trusted_refs: Vec<(&str, &VerifyingKey)> =
        trusted.iter().map(|(id, key)| (id.as_str(), key)).collect();
    let topology = verify_topology(request.signed, &trusted_refs)
        .map_err(|e| refused(RefusalStage::Signature, e))?;
    Ok((topology, request.signed.signed.signer_id.clone()))
}

fn check_window(
    topology: &Topology,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), TopologyRefused> {
    if now < topology.valid_from {
        return Err(refused(
            RefusalStage::Window,
            format_args!("not valid until {}; now is {now}", topology.valid_from),
        ));
    }
    if now >= topology.valid_until {
        return Err(refused(
            RefusalStage::Window,
            format_args!("expired at {}; now is {now}", topology.valid_until),
        ));
    }
    Ok(())
}

/// Returns whether this is the generation already on record.
fn check_generation(
    topology: &Topology,
    digest: &Sha256Digest,
    last: Option<&AdmittedTopologyRecord>,
) -> Result<bool, TopologyRefused> {
    let Some(last) = last else {
        return Ok(false);
    };
    match topology.generation.cmp(&last.generation) {
        std::cmp::Ordering::Greater => Ok(false),
        std::cmp::Ordering::Less => Err(refused(
            RefusalStage::Generation,
            format_args!(
                "generation {} is lower than the last admitted generation {}",
                topology.generation, last.generation
            ),
        )),
        std::cmp::Ordering::Equal if last.digest == *digest => Ok(true),
        std::cmp::Ordering::Equal => Err(refused(
            RefusalStage::Generation,
            format_args!(
                "generation {} was admitted with digest {}; this topology's digest is {digest}",
                last.generation, last.digest
            ),
        )),
    }
}

/// Refuse an exclusive core the host lacks or another tenant holds. Skipped
/// for a topology holding no core, so an ordinary admission reads no other
/// tenant's records.
fn check_placement(
    request: &TopologyAdmissionRequest<'_>,
    home: &Path,
    topology: &Topology,
) -> Result<(), TopologyRefused> {
    if placement::exclusive_cores(topology).is_empty() {
        return Ok(());
    }
    let admitted = placement::admitted_topologies(home, request.host_signer_keys_dir)
        .map_err(|e| refused(RefusalStage::Record, format_args!("{e:#}")))?;
    placement::check_host_placement(request.tenant, topology, request.host_cpus, &admitted)
        .map_err(|e| refused(RefusalStage::Requirements, e))
}

/// What the whole topology would charge the host if every unit ran at once.
/// A unit's vCPUs count as whole host cores, since a critical unit is sized
/// to the cores it may use rather than to a share.
fn topology_charge(topology: &Topology) -> Option<MachineCharge> {
    topology
        .units
        .iter()
        .try_fold(MachineCharge::default(), |sum, unit| {
            Some(MachineCharge {
                memory_mib: sum.memory_mib.checked_add(unit.resources.mem_mib)?,
                cpu_millicores: sum
                    .cpu_millicores
                    .checked_add(unit.resources.cpus.checked_mul(1000)?)?,
            })
        })
}

fn check_budget(topology: &Topology) -> Result<(), TopologyRefused> {
    let charge = topology_charge(topology)
        .ok_or_else(|| refused(RefusalStage::Budget, "the units' resources overflow"))?;
    let probe =
        crate::admission_budget::HostBudgetPermit::reserve_ordinary(BUDGET_PROBE_NAME, charge)
            .map_err(|e| refused(RefusalStage::Budget, format_args!("{e:#}")))?;
    probe.release_pre_dispatch().map_err(|e| {
        refused(
            RefusalStage::Budget,
            format_args!("releasing the probe: {e:#}"),
        )
    })
}

fn authorizer() -> (String, String) {
    ("authorizer_principal".to_string(), host_signer_id())
}

fn audit_admitted(
    request: &TopologyAdmissionRequest<'_>,
    admitted: &AdmittedTopology,
) -> Result<()> {
    request.emitter.emit_topology_decision(
        request.tenant,
        TOPOLOGY_ADMITTED_EVENT,
        [
            ("topology_digest".to_string(), admitted.digest.to_string()),
            (
                "generation".to_string(),
                admitted.topology.generation.to_string(),
            ),
            ("signer_id".to_string(), admitted.signer_id.clone()),
            ("backend".to_string(), request.backend.as_str().to_string()),
            authorizer(),
        ],
    )
}

fn withdraw(record_path: &Path, audit: anyhow::Error) -> anyhow::Error {
    let audit = audit.context("writing topology.admitted; the new generation is withdrawn");
    match std::fs::remove_file(record_path) {
        Ok(()) => audit,
        Err(e) => audit.context(format!(
            "and the record at {} could not be removed: {e}",
            record_path.display()
        )),
    }
}

fn audit_refusal(
    request: &TopologyAdmissionRequest<'_>,
    known: Option<&Known>,
    refusal: TopologyRefused,
) -> anyhow::Error {
    let mut labels = vec![
        ("stage".to_string(), refusal.stage.as_str().to_string()),
        ("reason".to_string(), refusal.reason.clone()),
        (
            "payload_sha256".to_string(),
            Sha256Digest::from_bytes(&sha256(&request.signed.signed.payload)).to_string(),
        ),
        ("backend".to_string(), request.backend.as_str().to_string()),
        authorizer(),
    ];
    if let Some(known) = known {
        labels.push(("topology_digest".to_string(), known.digest.to_string()));
        labels.push(("generation".to_string(), known.generation.to_string()));
    }
    let audit = request.emitter.emit_topology_decision(
        request.tenant,
        TOPOLOGY_ADMISSION_REFUSED_EVENT,
        labels,
    );
    match audit {
        Ok(()) => refusal.into(),
        Err(e) => anyhow::Error::new(refusal).context(format!(
            "the refusal could not be written to the audit chain: {e:#}"
        )),
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests;
