# Workload Grants Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every workload one signed, declarable permission set — outbound
destinations, CPU, and wall clock — resolvable from a config file, JSON, the
CLI, or a library, and enforced by whichever mechanism the running backend
actually has.

**Architecture:** A `Grants` type in `mvm-contract` is the single declaration.
One resolver collapses the four surfaces into it; one projection derives the
existing `NetworkPolicy` from it so claim-10 keeps exactly one gate. A
`GrantCeiling` with a separate trust root bounds what may be asked for.
Enforcement hangs off the existing `VmBackend` capability seam: backends
declare which controls they have, apply what they can, and report back what
they actually achieved by reading it off the system rather than assuming.

**Tech Stack:** Rust (14-crate workspace), `serde`, `schemars` (behind the
`schema` feature), cgroup v2 on Linux, `wasmtime` for the wasm tier,
`cucumber-rs` for BDD, `cargo nextest` as the test runner.

**Design spec:** `specs/plans/308-workload-grants.md`. Read it before Task 1;
it carries the reasoning this plan only implements.

## Global Constraints

- **Worktree:** `/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-308-grants`,
  branch `feat/308-workload-grants`. All work happens there, never in the main
  checkout.
- **`mvm-contract` is `#![no_std]` + alloc and must keep building for
  `wasm32-unknown-unknown`.** Use `alloc::vec::Vec`, `alloc::string::String`,
  `core::num::NonZeroU32`. No `std::`, no `f32`/`f64` in any signed payload.
- **No floating point in the signed plan.** CPU share is `u32` millicores
  (1500 = 1.5 cores). Float canonicalization is not stable across
  serializers and the plan is content-addressed and signed.
- **`#[serde(deny_unknown_fields)]` on every new type.** A grant silently
  dropped by a typo is a security control disabled by a spelling mistake.
- **New fields on `ExecutionPlan` are `Option<T>` with
  `#[serde(default, skip_serializing_if = "Option::is_none")]`.** The field is
  inside the signed payload; emitting `null` invalidates every existing
  signature and frozen test vector.
- **No `#[allow(clippy::...)]`, ever.** If a function trips
  `too_many_arguments`, introduce a params struct with a builder.
- **No plan/PR/ADR references in code comments** — `xtask
  check-no-spec-refs-in-comments` fails the build. Explain *why*, not which
  plan asked for it.
- **Never `sudo`.** cgroup work uses unprivileged v2 user delegation.
- **Scratch files go in `/tmp`**, never in the repo tree.
- **Gate before every push:** `cargo fmt --all -- --check` (nightly rustfmt —
  CI's lint lane uses it), `cargo nextest run --workspace`, `cargo test
  --workspace --doc`, `cargo clippy --workspace --all-targets -- -D warnings`.
  `just ci` wraps these.

## File Structure

**New:**

| File | Responsibility |
| --- | --- |
| `crates/mvm-contract/src/grants/mod.rs` | `Grants`, `CpuGrant`, `WallClockGrant`, `EgressGrant` — the declaration |
| `crates/mvm-contract/src/grants/ceiling.rs` | `GrantCeiling` + `CeilingViolation` — what may be asked for |
| `crates/mvm-contract/src/grants/projection.rs` | The one `Grants` → `NetworkPolicy` projection |
| `crates/mvm-contract/src/protocol/resource_controls.rs` | `ResourceControls`, `CpuControl`, `WallClockControl`, `EnforcedGrants`, `EnforcedTier` |
| `crates/mvm-core/src/grants_resolve.rs` | The four-surface precedence resolver |
| `crates/mvm-hostd/src/cgroup.rs` | Unprivileged cgroup v2 leaf: create, born-into, read back |
| `crates/mvm-hostd/src/grants_budget.rs` | Host admission budget from live liveness |
| `xtask/src/check_single_grants_projection.rs` | Exactly one projection function exists |
| `xtask/src/check_backend_resource_controls.rs` | Every `BackendKind` declares its controls |
| `features/suites/s12_grants/grants.feature` | BDD scenarios |

**Modified:** `crates/mvm-contract/src/lib.rs` (module decl),
`crates/mvm-contract/src/plan/execution_plan.rs` (the `grants` field),
`crates/mvm-contract/src/protocol/vm_backend.rs` (`VmCapabilities`),
`crates/mvm-contract/src/protocol/capability_negotiation.rs` (the
`Share`→`Fuel` alternative), `crates/mvm-core/src/protocol/vm_backend.rs`
(`apply_grants`), `crates/mvm-core/src/client/dto.rs` (`MachineSpec.grants`),
`crates/mvm-core/src/domain/manifest.rs` (`[grants]`),
`crates/mvm-core/src/user_config.rs` (ceiling + headroom keys),
`crates/mvm-runtime/src/wasm_backend.rs`,
`crates/mvm-runtime/src/checkpoint/mod.rs`,
`crates/mvm-cli/src/commands/machine/mod.rs`, `xtask/src/main.rs`.

## Task Dependency Order

Tasks 1–5 are the contract and seam; they touch no enforcement and can land
independently. **Task 6 is a spike that gates Tasks 7–8.** Tasks 9–14 are
surfaces and can proceed in parallel with 7–8 once Task 5 lands.

---

### Task 1: The `Grants` type

**Files:**
- Create: `crates/mvm-contract/src/grants/mod.rs`
- Modify: `crates/mvm-contract/src/lib.rs` (add `pub mod grants;` next to `pub mod policy;` at line 45)

**Interfaces:**
- Consumes: `crate::policy::network_policy::HostPort` (already exists at `crates/mvm-contract/src/policy/network_policy.rs:47`, constructor `HostPort::new(host: impl Into<String>, port: u16)`)
- Produces: `Grants { cpu: Option<CpuGrant>, wall_clock: Option<WallClockGrant>, egress: Option<EgressGrant> }`; `CpuGrant::Share { millicores: u32 }` / `CpuGrant::Fuel { instructions: u64 }`; `WallClockGrant::Unbounded` / `WallClockGrant::Secs { secs: NonZeroU32 }`; `EgressGrant { allow: Vec<HostPort> }`

- [ ] **Step 1: Write the failing tests**

Create `crates/mvm-contract/src/grants/mod.rs` with only the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn default_grants_serialize_to_an_empty_object() {
        let g = Grants::default();
        let json = serde_json::to_string(&g).expect("serializes");
        assert_eq!(json, "{}", "absent grants must not emit null fields");
    }

    #[test]
    fn unknown_field_is_refused_not_ignored() {
        // A typo must not silently disable a cap.
        let err = serde_json::from_str::<Grants>(r#"{"cpu_limt":{"unit":"share","millicores":1500}}"#)
            .expect_err("unknown field must be refused");
        assert!(
            err.to_string().contains("unknown field"),
            "expected an unknown-field error, got: {err}"
        );
    }

    #[test]
    fn wall_clock_zero_is_not_expressible() {
        // exec_secs == 0 means *unbounded* in the legacy encoding. The grant
        // must not inherit that trap: zero has to be unrepresentable, so
        // "no time allowed" can never parse as "no limit".
        let err = serde_json::from_str::<WallClockGrant>(r#"{"kind":"secs","secs":0}"#)
            .expect_err("zero seconds must not parse");
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn grants_round_trip_through_json() {
        let g = Grants {
            cpu: Some(CpuGrant::Share { millicores: 1500 }),
            wall_clock: Some(WallClockGrant::Secs {
                secs: NonZeroU32::new(600).expect("nonzero"),
            }),
            egress: Some(EgressGrant {
                allow: vec![HostPort::new("api.example.com", 443)],
            }),
        };
        let json = serde_json::to_string(&g).expect("serializes");
        let back: Grants = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(g, back);
    }

    #[test]
    fn cpu_share_carries_no_floating_point() {
        let json = serde_json::to_string(&CpuGrant::Share { millicores: 1500 }).expect("serializes");
        assert!(
            !json.contains('.'),
            "a signed payload must not carry a float: {json}"
        );
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p mvm-contract grants`
Expected: FAIL — `cannot find type Grants in this scope`.

- [ ] **Step 3: Write the implementation**

Prepend to the same file, above the test module:

```rust
//! What a workload is permitted to consume or reach.
//!
//! Named `Grants` rather than `Capabilities` because `VmCapabilities` already
//! means "what a VMM backend supports", and `capability` additionally collides
//! with Linux `capabilities(7)`, which this project drops via bounding-set.

use alloc::vec::Vec;
use core::num::NonZeroU32;
use serde::{Deserialize, Serialize};

use crate::policy::network_policy::HostPort;

pub mod ceiling;
pub mod projection;

/// A workload's permission set. Every field is optional: absent means
/// "unspecified", which each dimension resolves differently — an absent
/// `egress` is deny-all, an absent `cpu` is uncapped.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grants {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_clock: Option<WallClockGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressGrant>,
}

/// CPU bound. The two variants are different units, not different precisions,
/// and no conversion between them is offered: a share is a fraction of host
/// wall-clock CPU, fuel is a count of executed instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "unit", rename_all = "snake_case", deny_unknown_fields)]
pub enum CpuGrant {
    /// Thousandths of one host core. 1500 = 1.5 cores. Integer because the
    /// value lands in a signed, content-addressed payload and float
    /// canonicalization is not stable across serializers.
    Share { millicores: u32 },
    /// A deterministic executed-instruction budget. Reproducible across hosts
    /// in a way no share-based bound is.
    Fuel { instructions: u64 },
}

/// Wall-clock bound.
///
/// `Unbounded` is a named variant rather than a sentinel value. The legacy
/// `TimeoutSpec::exec_secs` encodes unbounded as `0`, so a user writing `0` to
/// mean "no time allowed" would get "no limit" — the exact inversion of their
/// intent. `NonZeroU32` makes that unrepresentable here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WallClockGrant {
    Unbounded,
    Secs { secs: NonZeroU32 },
}

/// Outbound destinations. An empty `allow` is "no egress" and is distinct from
/// an absent `EgressGrant`, which is also deny-all — both are closed, so the
/// distinction never opens anything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressGrant {
    pub allow: Vec<HostPort>,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p mvm-contract grants`
Expected: PASS, 5 tests.

Then confirm the `no_std` constraint still holds:

Run: `cargo build -p mvm-contract --target wasm32-unknown-unknown`
Expected: success. If the target is missing: `rustup target add wasm32-unknown-unknown`.

- [ ] **Step 5: Commit**

```bash
cd /Users/auser/work/tinylabs/mvmco/.worktrees/mvm-308-grants
git add crates/mvm-contract/src/grants/mod.rs crates/mvm-contract/src/lib.rs
git commit -m "feat(contract): add the Grants declaration type"
```

---

### Task 2: `GrantCeiling`

A grant says what a workload asks for. The ceiling says what it may ask for.
They are separate types because they have separate trust roots: the grant is
signed by whoever launches the workload, the ceiling is resolved at admission
from host or fleet config and never from the plan. Without this, a plan signer
who is also the grant author can grant itself the machine.

**Files:**
- Create: `crates/mvm-contract/src/grants/ceiling.rs`

**Interfaces:**
- Consumes: `Grants`, `CpuGrant`, `WallClockGrant` from Task 1
- Produces: `GrantCeiling { max_cpu_millicores: Option<u32>, max_memory_mib: Option<u64>, max_wall_clock_secs: Option<u32> }`; `GrantCeiling::admits(&self, grants: &Grants, memory_mib: u64) -> Result<(), CeilingViolation>`; `CeilingViolation { dimension: &'static str, requested: u64, ceiling: u64 }`

- [ ] **Step 1: Write the failing tests**

Create `crates/mvm-contract/src/grants/ceiling.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::{CpuGrant, Grants, WallClockGrant};
    use core::num::NonZeroU32;

    fn ceiling() -> GrantCeiling {
        GrantCeiling {
            max_cpu_millicores: Some(4000),
            max_memory_mib: Some(8192),
            max_wall_clock_secs: Some(3600),
        }
    }

    #[test]
    fn a_grant_within_the_ceiling_is_admitted() {
        let g = Grants {
            cpu: Some(CpuGrant::Share { millicores: 1500 }),
            ..Default::default()
        };
        assert!(ceiling().admits(&g, 512).is_ok());
    }

    #[test]
    fn a_cpu_grant_exceeding_the_ceiling_is_refused() {
        let g = Grants {
            cpu: Some(CpuGrant::Share { millicores: 64_000 }),
            ..Default::default()
        };
        let v = ceiling().admits(&g, 512).expect_err("must refuse");
        assert_eq!(v.dimension, "cpu.share_millicores");
        assert_eq!(v.requested, 64_000);
        assert_eq!(v.ceiling, 4000);
    }

    #[test]
    fn memory_is_checked_even_though_it_is_not_a_grant_field() {
        // Memory is fixed at VM creation rather than granted, but the ceiling
        // still has to bound it or a caller could reserve the whole host.
        let v = ceiling()
            .admits(&Grants::default(), 65_536)
            .expect_err("must refuse");
        assert_eq!(v.dimension, "memory_mib");
    }

    #[test]
    fn an_unbounded_wall_clock_is_refused_under_a_wall_clock_ceiling() {
        let g = Grants {
            wall_clock: Some(WallClockGrant::Unbounded),
            ..Default::default()
        };
        let v = ceiling().admits(&g, 512).expect_err("must refuse");
        assert_eq!(v.dimension, "wall_clock.secs");
    }

    #[test]
    fn an_absent_ceiling_dimension_admits_anything_in_that_dimension() {
        let open = GrantCeiling {
            max_cpu_millicores: None,
            max_memory_mib: None,
            max_wall_clock_secs: None,
        };
        let g = Grants {
            cpu: Some(CpuGrant::Share { millicores: 999_999 }),
            wall_clock: Some(WallClockGrant::Unbounded),
            ..Default::default()
        };
        assert!(open.admits(&g, u64::MAX).is_ok());
    }

    #[test]
    fn a_fuel_grant_is_not_bounded_by_a_share_ceiling() {
        // Fuel and share are different units; a share ceiling says nothing
        // about an instruction budget and must not be applied to one.
        let g = Grants {
            cpu: Some(CpuGrant::Fuel {
                instructions: u64::MAX,
            }),
            ..Default::default()
        };
        assert!(ceiling().admits(&g, 512).is_ok());
    }

    #[test]
    fn wall_clock_within_the_ceiling_is_admitted() {
        let g = Grants {
            wall_clock: Some(WallClockGrant::Secs {
                secs: NonZeroU32::new(600).expect("nonzero"),
            }),
            ..Default::default()
        };
        assert!(ceiling().admits(&g, 512).is_ok());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p mvm-contract ceiling`
Expected: FAIL — `cannot find type GrantCeiling in this scope`.

- [ ] **Step 3: Write the implementation**

Prepend to `ceiling.rs`:

```rust
//! The bound on what a grant may ask for.
//!
//! Separate from [`Grants`](crate::grants::Grants) because the two have
//! different trust roots. A grant is signed by whoever launches the workload;
//! a ceiling is resolved at admission from host or fleet configuration and
//! never read out of the plan. Collapsing them would let a plan signer who is
//! also the grant author grant itself the whole machine.

use serde::{Deserialize, Serialize};

use crate::grants::{CpuGrant, Grants, WallClockGrant};

/// A dimension in which a grant exceeded what it was allowed to ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeilingViolation {
    /// Dotted path of the offending dimension, for the refusal message.
    pub dimension: &'static str,
    pub requested: u64,
    pub ceiling: u64,
}

/// The per-host or per-tenant bound. `None` in a dimension means unbounded
/// *in that dimension*; it does not open the others.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantCeiling {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cpu_millicores: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_mib: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_wall_clock_secs: Option<u32>,
}

impl GrantCeiling {
    /// Check `grants` and the separately-supplied `memory_mib` against this
    /// ceiling. Memory is a parameter rather than a grant field because it is
    /// fixed at VM creation rather than granted, but it still has to be
    /// bounded or a caller could reserve the entire host.
    pub fn admits(&self, grants: &Grants, memory_mib: u64) -> Result<(), CeilingViolation> {
        self.admits_cpu(grants)?;
        self.admits_memory(memory_mib)?;
        self.admits_wall_clock(grants)
    }

    fn admits_cpu(&self, grants: &Grants) -> Result<(), CeilingViolation> {
        // Only `Share` is comparable to a millicore ceiling. `Fuel` is an
        // instruction count in a different unit, so a share ceiling says
        // nothing about it and must not be applied.
        let (Some(max), Some(CpuGrant::Share { millicores })) = (self.max_cpu_millicores, grants.cpu)
        else {
            return Ok(());
        };
        if millicores > max {
            return Err(CeilingViolation {
                dimension: "cpu.share_millicores",
                requested: u64::from(millicores),
                ceiling: u64::from(max),
            });
        }
        Ok(())
    }

    fn admits_memory(&self, memory_mib: u64) -> Result<(), CeilingViolation> {
        let Some(max) = self.max_memory_mib else {
            return Ok(());
        };
        if memory_mib > max {
            return Err(CeilingViolation {
                dimension: "memory_mib",
                requested: memory_mib,
                ceiling: max,
            });
        }
        Ok(())
    }

    fn admits_wall_clock(&self, grants: &Grants) -> Result<(), CeilingViolation> {
        let Some(max) = self.max_wall_clock_secs else {
            return Ok(());
        };
        // An unbounded request under a bounded ceiling is a refusal, not a
        // silent clamp: the caller asked for something the host forbids and
        // has to learn that rather than get a different answer than requested.
        let requested = match grants.wall_clock {
            None => return Ok(()),
            Some(WallClockGrant::Unbounded) => u64::MAX,
            Some(WallClockGrant::Secs { secs }) => u64::from(secs.get()),
        };
        if requested > u64::from(max) {
            return Err(CeilingViolation {
                dimension: "wall_clock.secs",
                requested,
                ceiling: u64::from(max),
            });
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p mvm-contract ceiling`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-contract/src/grants/ceiling.rs
git commit -m "feat(contract): bound grants with a separately-rooted ceiling"
```

---

### Task 3: The one projection, failing closed

Claim 10 holds because `EgressGate` is the sole egress decision point. If
`Grants.egress` and `plan.network_policy` were independently settable they
could disagree, and reading the wrong one is a policy bypass. So the policy is
*derived* here and nowhere else.

**Files:**
- Create: `crates/mvm-contract/src/grants/projection.rs`

**Interfaces:**
- Consumes: `Grants`, `EgressGrant` from Task 1; `crate::policy::network_policy::{NetworkPolicy, HostPort}` (`NetworkPolicy::deny_all()`, `NetworkPolicy::allow_list(Vec<HostPort>)`, `NetworkPolicy::resolve_rules() -> Option<Vec<HostPort>>` at `crates/mvm-contract/src/policy/network_policy.rs:239-336`)
- Produces: `network_policy_from_grants(grants: &Grants) -> NetworkPolicy`

- [ ] **Step 1: Write the failing tests**

Create `crates/mvm-contract/src/grants/projection.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::{EgressGrant, Grants};
    use alloc::vec;

    #[test]
    fn absent_egress_projects_to_deny_all() {
        let p = network_policy_from_grants(&Grants::default());
        assert_eq!(
            p.resolve_rules().as_deref(),
            Some(&[][..]),
            "an unspecified egress grant must be deny-all, never permissive"
        );
    }

    #[test]
    fn an_empty_allow_list_projects_to_deny_all() {
        let g = Grants {
            egress: Some(EgressGrant { allow: vec![] }),
            ..Default::default()
        };
        let p = network_policy_from_grants(&g);
        assert_eq!(p.resolve_rules().as_deref(), Some(&[][..]));
    }

    #[test]
    fn an_allow_list_projects_to_those_rules() {
        let g = Grants {
            egress: Some(EgressGrant {
                allow: vec![
                    HostPort::new("api.example.com", 443),
                    HostPort::new("db.internal", 5432),
                ],
            }),
            ..Default::default()
        };
        let rules = network_policy_from_grants(&g)
            .resolve_rules()
            .expect("an allow-list resolves to rules");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0], HostPort::new("api.example.com", 443));
        assert_eq!(rules[1], HostPort::new("db.internal", 5432));
    }

    #[test]
    fn no_projection_ever_yields_unrestricted() {
        // Unrestricted is reachable only by an explicit operator opt-in
        // elsewhere. No grant, however shaped, may produce it here.
        for g in [
            Grants::default(),
            Grants {
                egress: Some(EgressGrant { allow: vec![] }),
                ..Default::default()
            },
            Grants {
                egress: Some(EgressGrant {
                    allow: vec![HostPort::new("example.com", 80)],
                }),
                ..Default::default()
            },
        ] {
            assert!(
                !network_policy_from_grants(&g).is_unrestricted(),
                "projection must never open the network"
            );
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p mvm-contract projection`
Expected: FAIL — `cannot find function network_policy_from_grants`.

- [ ] **Step 3: Write the implementation**

Prepend to `projection.rs`:

```rust
//! The single `Grants` -> `NetworkPolicy` projection.
//!
//! Egress policy is *derived* from grants and never supplied alongside them.
//! Two independently-settable representations of the same decision can
//! disagree, and whichever one the enforcement path happens to read becomes
//! the real policy — so there is exactly one function here, and
//! `xtask check-single-grants-projection` fails the build if a second appears.
//!
//! Every path through this function is closed. There is no input that yields
//! an unrestricted policy.

use crate::grants::Grants;
use crate::policy::network_policy::{HostPort, NetworkPolicy};

/// Derive the egress policy a set of grants authorizes.
///
/// An absent `egress` grant and an empty allow-list both mean deny-all: the
/// distinction between "unspecified" and "explicitly nothing" never opens
/// anything, so collapsing them is safe.
#[must_use]
pub fn network_policy_from_grants(grants: &Grants) -> NetworkPolicy {
    match grants.egress.as_ref() {
        None => NetworkPolicy::deny_all(),
        Some(egress) => {
            let rules: alloc::vec::Vec<HostPort> = egress.allow.clone();
            if rules.is_empty() {
                NetworkPolicy::deny_all()
            } else {
                NetworkPolicy::allow_list(rules)
            }
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p mvm-contract projection`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-contract/src/grants/projection.rs
git commit -m "feat(contract): derive egress policy from grants at one fail-closed seam"
```

---

### Task 4: `xtask check-single-grants-projection`

The projection is only a chokepoint if it stays the only one. This is the
same discipline `check-uniform-vsock-egress` applies to the egress gate.

**Files:**
- Create: `xtask/src/check_single_grants_projection.rs`
- Modify: `xtask/src/main.rs` (module decl near line 56; dispatch arm near line 175; the help string at line 323)

**Interfaces:**
- Produces: `run(workspace: &Path) -> anyhow::Result<()>`

- [ ] **Step 1: Write the gate**

Create `xtask/src/check_single_grants_projection.rs`:

```rust
//! `xtask check-single-grants-projection`
//!
//! Egress policy must be derivable from grants in exactly one place. A second
//! derivation is a second policy decision point, and two decision points can
//! disagree — at which point the enforced policy is whichever one the
//! enforcement path happened to read.

use anyhow::{Result, bail};
use std::path::Path;

/// The sole file permitted to construct a `NetworkPolicy` from `Grants`.
const PROJECTION_FILE: &str = "crates/mvm-contract/src/grants/projection.rs";

pub fn run(workspace: &Path) -> Result<()> {
    let projection = workspace.join(PROJECTION_FILE);
    if !projection.is_file() {
        bail!("the grants projection is missing at {PROJECTION_FILE}");
    }

    // The rule: outside the projection file, no function signature may both
    // take a `Grants` and return a `NetworkPolicy`. Keying on the signature
    // rather than on fixed marker strings is what makes the gate survive the
    // refactors that would otherwise slip past it — a renamed parameter, a
    // by-value `Grants`, or a `Result`/`Option`-wrapped return are all still
    // the same second decision point.
    //
    // Visibility is deliberately not part of the rule. Even a private
    // delegating wrapper is a second name for the one decision, and it belongs
    // in the projection file. Testing visibility file-wide (rather than per
    // declaration) is also what would make this gate fire on unrelated code.
    let mut offenders = Vec::new();
    let roots = ["crates", "src", "tests"];
    for root in roots {
        let dir = workspace.join(root);
        if !dir.is_dir() {
            continue;
        }
        crate::fs_walk::for_each_file(&dir, Some("rs"), &mut |path| {
            let rel = path
                .strip_prefix(workspace)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");
            if rel == PROJECTION_FILE {
                return Ok(());
            }
            let body = std::fs::read_to_string(path)?;
            // Scan whole signatures, not lines. rustfmt wraps any signature
            // past its width limit, which puts the parameters and the return
            // type on different lines — the single most likely shape a real
            // second projection would take, and invisible to a line-based
            // check. Comments are stripped first so prose quoting a signature
            // is not mistaken for one.
            for signature in fn_signatures(&strip_line_comments(&body)) {
                let Some((params, ret)) = signature.rsplit_once("->") else {
                    continue;
                };
                if params.contains("Grants") && ret.contains("NetworkPolicy") {
                    offenders.push(format!("{rel}: {}", signature.trim()));
                    break;
                }
            }
            Ok(())
        })?;
    }

    if !offenders.is_empty() {
        bail!(
            "a second Grants -> NetworkPolicy projection exists in:\n  {}\n\
             Egress policy must be derived only in {PROJECTION_FILE}.",
            offenders.join("\n  ")
        );
    }
    Ok(())
}

/// Drop `//`-style comments so prose quoting a signature is not read as one.
/// Block comments are left alone: a `/* */` containing a full signature is
/// rare enough that the false positive is cheaper than a comment parser.
fn strip_line_comments(body: &str) -> String {
    body.lines()
        .map(|line| match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every function signature in `body`, each flattened to one line.
///
/// A signature runs from `fn ` to the `{` opening its body (or the `;` ending
/// a trait method), so a rustfmt-wrapped signature is returned whole rather
/// than in fragments.
fn fn_signatures(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find("fn ") {
        rest = &rest[start..];
        let end = rest
            .find('{')
            .into_iter()
            .chain(rest.find(';'))
            .min()
            .unwrap_or(rest.len());
        out.push(rest[..end].split_whitespace().collect::<Vec<_>>().join(" "));
        rest = &rest[end.min(rest.len())..];
        if rest.is_empty() {
            break;
        }
        rest = &rest[1.min(rest.len())..];
    }
    out
}
```

- [ ] **Step 2: Wire it into `main.rs`**

Add the module declaration alongside the others (near line 56):

```rust
mod check_single_grants_projection;
```

Add the dispatch arm alongside `check-two-surfaces` (near line 175):

```rust
        Some("check-single-grants-projection") => {
            check_single_grants_projection::run(&workspace)
        }
```

In the unknown-xtask help string at line 323, append
`, check-single-grants-projection` to the list.

- [ ] **Step 3: Run the gate — it must pass on a clean tree**

Run: `cargo run -p xtask -- check-single-grants-projection`
Expected: exit 0, no output.

- [ ] **Step 4: Prove the gate goes red — against every evasion shape**

A gate that has never failed is not known to work, and a gate proven against
only one shape is not known to hold. Probe each of these in turn by
temporarily adding it to `crates/mvm-core/src/lib.rs` (with whatever `use`
lines it needs to compile), running the gate, confirming it fails and names
the file, then removing it:

```rust
pub fn sneaky(grants: &Grants) -> NetworkPolicy { unimplemented!() }
pub fn policy_for(g: &Grants) -> NetworkPolicy { unimplemented!() }
pub fn derive(grants: Grants) -> NetworkPolicy { unimplemented!() }
fn private_wrapper(grants: &Grants) -> NetworkPolicy { unimplemented!() }
pub fn try_policy(grants: &Grants) -> Result<NetworkPolicy, ()> { unimplemented!() }
```

All five must be caught. After the last one, confirm `git status --short` is
clean and the gate exits 0.

Known and accepted limit, to be stated in the gate's doc comment rather than
papered over: a method on a struct that holds `Grants` (`fn policy(&self) ->
NetworkPolicy`) names neither type in its signature and is not detectable by
a text gate. Say so, so the next reader knows the boundary.

- [ ] **Step 5: Commit**

```bash
git add xtask/src/check_single_grants_projection.rs xtask/src/main.rs
git commit -m "test(xtask): fail the build on a second grants projection"
```

---

### Task 5: The backend seam

Backends declare what they can enforce; `apply_grants` enforces it and reports
what was *achieved*, read back off the system rather than assumed. The default
implementation is honest-but-unenforcing, so a backend that ignores grants
says so instead of silently dropping them.

**Files:**
- Create: `crates/mvm-contract/src/protocol/resource_controls.rs`
- Modify: `crates/mvm-contract/src/protocol/mod.rs` (module decl)
- Modify: `crates/mvm-contract/src/protocol/vm_backend.rs` (`VmCapabilities`, line 425)
- Modify: `crates/mvm-core/src/protocol/vm_backend.rs` (`VmBackend`, line 349)

**Interfaces:**
- Consumes: `Grants` (Task 1); `BackendKind` (`crates/mvm-contract/src/protocol/vm_backend.rs:1274`, variants `Firecracker | Libkrun | Qemu | Mock | Hvf | Wasm | Docker | AppleContainer`)
- Produces: `ResourceControls { cpu: CpuControl, wall_clock: WallClockControl }`; `CpuControl::{None, CgroupShare, WasmFuel}`; `WallClockControl::{None, SupervisorTimer, WasmEpoch}`; `EnforcedGrants { cpu: EnforcedTier, wall_clock: EnforcedTier }`; `EnforcedTier { mechanism: &'static str }`; `VmCapabilities::resource_controls`; `VmBackend::apply_grants`

- [ ] **Step 1: Write the failing tests**

Create `crates/mvm-contract/src/protocol/resource_controls.rs` with the tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::vm_backend::BackendKind;

    #[test]
    fn every_backend_kind_declares_its_controls() {
        // Exhaustive by construction: adding a BackendKind variant without
        // answering here is a compile error, not a silent default.
        for kind in [
            BackendKind::Firecracker,
            BackendKind::Libkrun,
            BackendKind::Qemu,
            BackendKind::Mock,
            BackendKind::Hvf,
            BackendKind::Wasm,
            BackendKind::Docker,
            BackendKind::AppleContainer,
        ] {
            let _ = ResourceControls::for_backend(kind);
        }
    }

    #[test]
    fn the_wasm_tier_uses_fuel_and_epoch() {
        let c = ResourceControls::for_backend(BackendKind::Wasm);
        assert_eq!(c.cpu, CpuControl::WasmFuel);
        assert_eq!(c.wall_clock, WallClockControl::WasmEpoch);
    }

    #[test]
    fn the_hvf_tier_cannot_bound_cpu() {
        // macOS has no cgroup equivalent. Thread QoS is a scheduling priority,
        // not a quota, so claiming it would overstate the enforcement.
        let c = ResourceControls::for_backend(BackendKind::Hvf);
        assert_eq!(c.cpu, CpuControl::None);
        assert_eq!(c.wall_clock, WallClockControl::SupervisorTimer);
    }

    #[test]
    fn a_share_grant_is_unenforceable_on_the_wasm_tier() {
        let c = ResourceControls::for_backend(BackendKind::Wasm);
        assert!(!c.cpu.serves_share());
    }

    #[test]
    fn a_declared_tier_reports_itself_as_unenforced() {
        assert!(!EnforcedTier::Declared.is_enforced());
        assert_eq!(EnforcedTier::Declared.label(), "declared");
    }

    #[test]
    fn every_enforced_tier_names_its_mechanism() {
        assert!(EnforcedTier::Cgroup2CpuMax.is_enforced());
        assert_eq!(EnforcedTier::Cgroup2CpuMax.label(), "cgroup2:cpu.max");
        assert_eq!(EnforcedTier::WasmFuel.label(), "wasmtime:fuel");
        assert_eq!(EnforcedTier::WasmEpoch.label(), "wasmtime:epoch");
        assert_eq!(EnforcedTier::SupervisorTimer.label(), "supervisor:timer");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p mvm-contract resource_controls`
Expected: FAIL — `cannot find type ResourceControls`.

- [ ] **Step 3: Write the implementation**

Prepend to `resource_controls.rs`:

```rust
//! Which resource dimensions a backend can actually bound, and what it
//! achieved when asked to.
//!
//! Declaring the mechanism separately from applying it is what keeps a receipt
//! honest: `EnforcedTier` is built from reading the control back off the
//! system, so a label can never assert an enforcement that did not happen.

use serde::{Deserialize, Serialize};

use crate::protocol::vm_backend::BackendKind;

/// How a backend bounds CPU, if it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CpuControl {
    /// No CPU bound is available on this tier.
    None,
    /// cgroup v2 `cpu.max` on the per-VM supervisor process.
    CgroupShare,
    /// A deterministic wasmtime instruction budget.
    WasmFuel,
}

impl CpuControl {
    /// Whether this control can serve a `CpuGrant::Share`. Fuel cannot: an
    /// instruction count and a fraction of a host core are different units
    /// with no conversion between them.
    #[must_use]
    pub const fn serves_share(self) -> bool {
        matches!(self, Self::CgroupShare)
    }

    /// Whether this control can serve a `CpuGrant::Fuel`.
    #[must_use]
    pub const fn serves_fuel(self) -> bool {
        matches!(self, Self::WasmFuel)
    }
}

/// How a backend bounds wall-clock runtime, if it can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WallClockControl {
    None,
    /// A host-side timer owned by the supervisor.
    SupervisorTimer,
    /// wasmtime epoch interruption, which preempts a module that a fuel
    /// budget alone would never stop.
    WasmEpoch,
}

/// The controls one backend offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceControls {
    pub cpu: CpuControl,
    pub wall_clock: WallClockControl,
}

impl ResourceControls {
    /// The controls each backend has. Exhaustive on purpose: a new
    /// `BackendKind` must answer this question rather than inherit a default
    /// that might silently claim or silently drop enforcement.
    #[must_use]
    pub const fn for_backend(kind: BackendKind) -> Self {
        match kind {
            // A cgroup can bound any Linux process, so on Linux these tiers
            // carry a real CPU quota. libkrun is *not* Linux-only — it is the
            // macOS 13-25 workload default — and macOS has no cgroup, so the
            // answer has to depend on the host rather than the kind alone.
            // Declaring `CgroupShare` on a Mac would let a share grant be
            // accepted and then fail at apply time, which is precisely the
            // overstatement the macOS arm below exists to avoid.
            //
            // `cfg!` is the right test because mvm runs on the host it was
            // built for; there is no cross-host execution to disagree with it.
            BackendKind::Firecracker | BackendKind::Libkrun | BackendKind::Qemu => Self {
                cpu: if cfg!(target_os = "linux") {
                    CpuControl::CgroupShare
                } else {
                    CpuControl::None
                },
                wall_clock: WallClockControl::SupervisorTimer,
            },
            // macOS has no cgroup equivalent; thread QoS is priority, not quota.
            BackendKind::Hvf | BackendKind::AppleContainer => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::SupervisorTimer,
            },
            // Fuel bounds instructions; epoch preempts a module parked in a
            // host call, which fuel alone would never stop.
            BackendKind::Wasm => Self {
                cpu: CpuControl::WasmFuel,
                wall_clock: WallClockControl::WasmEpoch,
            },
            // Shares the host kernel; a cgroup here is the container runtime's
            // to own, not ours.
            BackendKind::Docker => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::SupervisorTimer,
            },
            BackendKind::Mock => Self {
                cpu: CpuControl::None,
                wall_clock: WallClockControl::None,
            },
        }
    }
}

/// What actually bounded one dimension. Constructed from a read-back of the
/// live control, never from the value that was written.
///
/// An enum rather than a string: a receipt label is a security-relevant
/// assertion, and a typo in a free-form mechanism string would be
/// indistinguishable from a real tier. `label()` renders for display; nothing
/// dispatches on the rendered text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcedTier {
    /// Nothing bounded this dimension; the value is a declaration only.
    Declared,
    Cgroup2CpuMax,
    WasmFuel,
    WasmEpoch,
    SupervisorTimer,
}

impl EnforcedTier {
    /// Whether a mechanism actually bounded this dimension.
    #[must_use]
    pub const fn is_enforced(self) -> bool {
        !matches!(self, Self::Declared)
    }

    /// Display rendering for receipts and `doctor` output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Cgroup2CpuMax => "cgroup2:cpu.max",
            Self::WasmFuel => "wasmtime:fuel",
            Self::WasmEpoch => "wasmtime:epoch",
            Self::SupervisorTimer => "supervisor:timer",
        }
    }
}

/// What a backend achieved across every dimension for one VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcedGrants {
    pub cpu: EnforcedTier,
    pub wall_clock: EnforcedTier,
}

impl EnforcedGrants {
    /// The honest answer for a backend that enforces nothing.
    #[must_use]
    pub const fn all_declared() -> Self {
        Self {
            cpu: EnforcedTier::Declared,
            wall_clock: EnforcedTier::Declared,
        }
    }
}
```

Add to `crates/mvm-contract/src/protocol/mod.rs`:

```rust
pub mod resource_controls;
```

- [ ] **Step 4: Add the field and the trait method**

In `crates/mvm-contract/src/protocol/vm_backend.rs`, add to `VmCapabilities`
(the struct at line 425) as the last field:

```rust
    /// Which resource dimensions this backend can actually bound. Declared
    /// separately from what a caller requests so a refusal can name the gap.
    #[serde(default = "default_resource_controls")]
    pub resource_controls: crate::protocol::resource_controls::ResourceControls,
```

And immediately after the struct, the default used by `#[derive(Default)]`
and by deserializing an older record:

```rust
fn default_resource_controls() -> crate::protocol::resource_controls::ResourceControls {
    use crate::protocol::resource_controls::{CpuControl, ResourceControls, WallClockControl};
    // The safe default is "enforces nothing", so an unset value understates
    // rather than overstates what a backend does.
    ResourceControls {
        cpu: CpuControl::None,
        wall_clock: WallClockControl::None,
    }
}
```

`VmCapabilities` derives `Default`, which requires `ResourceControls: Default`.
Add to `resource_controls.rs`:

```rust
impl Default for ResourceControls {
    /// Enforces nothing — the value that understates rather than overstates.
    fn default() -> Self {
        Self {
            cpu: CpuControl::None,
            wall_clock: WallClockControl::None,
        }
    }
}
```

In `crates/mvm-core/src/protocol/vm_backend.rs`, add to the `VmBackend` trait
(after `negotiate`, around line 372):

```rust
    /// Apply `grants` to a running VM and report what was actually achieved.
    ///
    /// The default enforces nothing and says so. A backend that silently
    /// ignored grants while reporting success would produce a receipt
    /// asserting an enforcement that never happened, which is worse than
    /// having no control at all.
    fn apply_grants(
        &self,
        _id: &VmId,
        _grants: &mvm_contract::grants::Grants,
    ) -> Result<mvm_contract::protocol::resource_controls::EnforcedGrants> {
        Ok(mvm_contract::protocol::resource_controls::EnforcedGrants::all_declared())
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo nextest run -p mvm-contract resource_controls`
Expected: PASS, 6 tests.

Run: `cargo nextest run --workspace`
Expected: PASS. `VmCapabilities` is constructed in many tests; because the new
field has a serde default and `ResourceControls: Default`, struct-update
syntax (`..Default::default()`) keeps compiling. Fix any literal
`VmCapabilities { .. }` construction that names every field by adding
`resource_controls: ResourceControls::for_backend(<kind>)`.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-contract/src/protocol/ crates/mvm-core/src/protocol/vm_backend.rs
git commit -m "feat(backend): declare per-backend resource controls and an apply_grants seam"
```

---

### Task 6: `xtask check-backend-resource-controls`

**Files:**
- Create: `xtask/src/check_backend_resource_controls.rs`
- Modify: `xtask/src/main.rs`

**Interfaces:**
- Produces: `run(workspace: &Path) -> anyhow::Result<()>`

- [ ] **Step 1: Write the gate**

```rust
//! `xtask check-backend-resource-controls`
//!
//! Every `BackendKind` must answer what it can bound. The exhaustive match in
//! `ResourceControls::for_backend` makes that a compile error already; this
//! gate catches the way around it — a wildcard arm, which would let a new
//! backend inherit an answer nobody chose for it.

use anyhow::{Result, bail};
use std::path::Path;

const CONTROLS_FILE: &str = "crates/mvm-contract/src/protocol/resource_controls.rs";

pub fn run(workspace: &Path) -> Result<()> {
    let path = workspace.join(CONTROLS_FILE);
    let body = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("reading {CONTROLS_FILE}: {e}"))?;

    let Some(start) = body.find("pub const fn for_backend") else {
        bail!("{CONTROLS_FILE} no longer defines for_backend");
    };
    let tail = &body[start..];
    let end = tail.find("\n}").unwrap_or(tail.len());
    let arm_body = &tail[..end];

    for wildcard in ["_ =>", "_kind =>"] {
        if arm_body.contains(wildcard) {
            bail!(
                "for_backend has a `{wildcard}` arm. Every BackendKind must state its \
                 controls explicitly — a wildcard silently answers for backends nobody \
                 considered."
            );
        }
    }
    Ok(())
}
```

- [ ] **Step 2: Wire into `main.rs`**

Module decl `mod check_backend_resource_controls;`, dispatch arm
`Some("check-backend-resource-controls") => check_backend_resource_controls::run(&workspace)`,
and append the name to the help string at line 323.

- [ ] **Step 3: Run the gate**

Run: `cargo run -p xtask -- check-backend-resource-controls`
Expected: exit 0.

- [ ] **Step 4: Prove it goes red**

Temporarily replace `BackendKind::Mock => Self {` with `_ => Self {` in
`resource_controls.rs`, run the gate, confirm it fails naming the wildcard,
then restore the explicit arm and confirm exit 0.

- [ ] **Step 5: Commit**

```bash
git add xtask/src/check_backend_resource_controls.rs xtask/src/main.rs
git commit -m "test(xtask): require every backend to state its resource controls"
```

---

### Task 7: The `Share` → `Fuel` capability alternative

`negotiate()` already answers "what do I do instead" for every capability gap.
A share grant on the wasm tier is exactly that shape of question.

**Files:**
- Modify: `crates/mvm-contract/src/protocol/capability_negotiation.rs`

**Interfaces:**
- Consumes: `CapabilityAlternative`, `CapabilityGap` (existing in that file); `CpuControl` (Task 5)
- Produces: `CapabilityAlternative::CpuBudgetAsDeterministicFuel`

- [ ] **Step 1: Write the failing test**

Add to that file's test module:

```rust
    #[test]
    fn a_share_grant_on_the_wasm_tier_names_fuel_as_the_substitute() {
        let gap = CapabilityGap {
            capability: "cpu.share",
            alternative: CapabilityAlternative::CpuBudgetAsDeterministicFuel,
        };
        assert!(
            gap.is_actionable(),
            "a wasm CPU bound exists; it is just a different unit"
        );
    }
```

- [ ] **Step 2: Run it and watch it fail**

Run: `cargo nextest run -p mvm-contract capability_negotiation`
Expected: FAIL — `no variant named CpuBudgetAsDeterministicFuel`.

- [ ] **Step 3: Add the variant**

In the `CapabilityAlternative` enum, alongside the existing variants:

```rust
    /// Bound CPU with a deterministic instruction budget instead of a share of
    /// host CPU time. The wasm tier has no notion of a core fraction; fuel is
    /// its unit, and it is reproducible across hosts in a way a share is not.
    CpuBudgetAsDeterministicFuel,
```

Then extend the exhaustive `is_actionable` match (and any other match over
this enum — the compiler will name them all) with:

```rust
            Self::CpuBudgetAsDeterministicFuel => true,
```

- [ ] **Step 4: Run tests**

Run: `cargo nextest run -p mvm-contract capability_negotiation`
Expected: PASS.

Run: `cargo nextest run --workspace`
Expected: PASS — confirms every exhaustive match over `CapabilityAlternative`
was updated. Per the repo's own experience, a `-p`/`--lib` build can skip
exhaustive-match sites; run the workspace suite here, not a filtered one.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-contract/src/protocol/capability_negotiation.rs
git commit -m "feat(backend): name fuel as the substitute for a share grant"
```

---

### Task 8 (SPIKE — blocks Tasks 9 and 10): cgroup v2 `cpu` delegation

**This task produces a decision and a document, not shipped code.** The `cpu`
controller is historically *not* delegated to user sessions by default, while
`memory` and `pids` generally are. Since "never `sudo`" is a hard constraint,
the primary enforcement mechanism for the primary gap may not exist
unprivileged on a default distro. Finding that out during Task 9 would mean
discarding Task 9.

**Files:**
- Create: `specs/plans/308-cgroup-delegation-findings.md`

- [ ] **Step 1: Probe the host**

On the KVM box (`ssh -i ~/.ssh/hetzner-rvproxy root@88.99.197.234`), noting
that you are root there so the unprivileged case must be tested by dropping to
a normal user with a real systemd session — a root shell would answer the
wrong question:

```bash
# Which controllers reach a user session at all?
cat /sys/fs/cgroup/user.slice/user-$(id -u)/cgroup.controllers
cat /sys/fs/cgroup/user.slice/user-$(id -u)/user@$(id -u).service/cgroup.controllers

# Can a leaf be created and cpu.max written unprivileged?
CG=/sys/fs/cgroup/user.slice/user-$(id -u)/user@$(id -u).service/mvm-probe.scope
mkdir -p "$CG" && echo "150000 100000" > "$CG/cpu.max" && cat "$CG/cpu.max"
```

- [ ] **Step 2: Measure whether the limit binds**

```bash
sleep 999 & PID=$!
echo $PID > "$CG/cgroup.procs"
# Replace the sleep with a spinner and confirm it is throttled to ~1.5 cores.
kill $PID; rmdir "$CG"
```

- [ ] **Step 3: Record the finding**

Write `specs/plans/308-cgroup-delegation-findings.md` containing: the distro
and systemd version, the exact `cgroup.controllers` contents at both levels,
whether `cpu.max` was writable unprivileged, whether the limit measurably
bound a spinner, and a one-line verdict — **"Task 9 proceeds as written"** or
**"Task 9 switches to a systemd transient scope over the session bus"**.

If the verdict is the transient scope, rewrite Task 9's Step 3 to create the
scope via `org.freedesktop.systemd1.Manager.StartTransientUnit` with a
`CPUQuota` property before implementing anything.

- [ ] **Step 4: Commit**

```bash
git add specs/plans/308-cgroup-delegation-findings.md
git commit -m "docs: record cgroup v2 cpu-delegation findings for the grants plan"
```

---

### Task 8b: Wire the seams — the task that makes the rest real

Tasks 1-7 built a ceiling nothing validates against, a seam nothing calls, and
a refusal nobody implements. Until something calls them, this branch ships
types that *describe* security properties without enforcing any of them —
which is the exact defect this plan's own rationale indicts `exec_secs` for.
This task closes that, and it deliberately comes before the Linux CPU
mechanism: `apply_grants` has an honest `Declared` default, so the call sites
can be wired and reviewed while the Linux implementation is still absent.

**Files:**
- Modify: `crates/mvm-hostd/src/plan_admission.rs` (`admit_for_run`, line 191)
- Modify: `crates/mvm-hostd/src/supervisor/aggregate.rs` (`Supervisor::launch`, line 320)
- Modify: `crates/mvm-core/src/user_config.rs` (ceiling keys)

**Interfaces:**
- Consumes: `GrantCeiling::admits` (Task 2), `network_policy_from_grants` (Task 3), `VmBackend::apply_grants` + `ResourceControls` + `EnforcedGrants` (Task 5), `CapabilityAlternative::CpuBudgetAsDeterministicFuel` (Task 7)
- Produces: `AdmittedPlan` carrying the resolved `EnforcedGrants`; `admit_for_run` refusing a grant over ceiling; `--prod` refusing an unenforceable grant

**The four wirings, each with its own witness:**

1. **Ceiling at admission.** `admit_for_run` resolves a `GrantCeiling` from host
   config — never from the plan, since the whole point is a separate trust
   root — and refuses before signing. Refusing *before* the keystore is touched
   matters: it keeps "signed a plan we would not admit" from being a reachable
   state, which is the same ordering `admit_for_run` already uses for synthesis
   failures.

2. **`apply_grants` at launch.** `Supervisor::launch` calls it on the resolved
   backend after the VM exists and records the returned `EnforcedGrants`. The
   returned tiers — not the requested grants — are what any receipt or report
   must carry.

3. **`--prod` refuses an unenforceable grant.** Compare the resolved `Grants`
   against the backend's `ResourceControls` *before* boot. A `cpu` grant on a
   backend whose `CpuControl` is `None` is refused under `--prod` and warned
   about in dev. This is the rule that keeps a `Declared` tier from silently
   becoming the normal outcome — which matters more after Task 8's spike, since
   `systemd-run --user` needs a session bus that a non-interactive `ssh host
   mvmctl ...`, a CI runner, or a `nohup`'d process will not have.

4. **`negotiate()` consulted for the CPU grant.** A `CpuGrant::Share` on the
   wasm tier must come back as a `CapabilityGap` naming
   `CpuBudgetAsDeterministicFuel`, at negotiation rather than at apply time.
   Task 7 added the variant; nothing reaches it. `is_actionable()` currently has
   no production caller at all — its only call site is a test.

**Witnesses (each must fail if its wiring is removed):**
- `admission_refuses_a_grant_over_the_ceiling`
- `admission_refuses_before_signing` — assert no signature is produced on the
  refusal path, not merely that an error is returned
- `launch_records_the_enforced_tier_not_the_requested_grant`
- `prod_refuses_a_cpu_grant_on_a_backend_that_cannot_bound_cpu`
- `dev_warns_and_proceeds_on_the_same_input`
- `share_grant_on_wasm_is_refused_at_negotiation_naming_fuel`

### Task 9: The CPU bound, via a systemd transient scope

**Redesigned after Task 8's spike. Read `specs/plans/308-cgroup-delegation-findings.md`
before starting.** The original design — `mkdir` a leaf under
`user@<uid>.service` and migrate the VMM into it — does not work unprivileged,
and the reason is not the one the plan assumed. The `cpu` controller *is*
delegated and `cpu.max` *is* writable. What fails is the **migration**: cgroup
v2 requires write access to the common ancestor of a process's current cgroup
and its destination, and a login session's `session-N.scope` is `Delegate=no`.
So a process launched from any normal shell cannot move itself into the
delegated subtree.

`systemd-run --user --scope -p CPUQuota=<n>%` sidesteps this because the
user's own `systemd --user` manager performs the placement from *inside* the
delegated tree. Measured on the spike box: 1.495 cores against a 1.5-core
target, with `nr_throttled` confirming the kernel was actively throttling.

This also settles the born-into-the-cgroup requirement for free, and that is
worth stating rather than leaving implicit: systemd creates the scope and
*then* spawns the payload inside it, so there is no interval in which the
workload runs uncapped. The original design needed `CLONE_INTO_CGROUP` to
achieve the same property by hand.

**Files:**
- Create: `crates/mvm-hostd/src/cpu_scope.rs`
- Modify: `crates/mvm-hostd/src/lib.rs` (module decl)

**Interfaces:**
- Consumes: `CpuGrant` (Task 1); `EnforcedTier` (Task 5)
- Produces: `scope_name(machine_id: &str) -> String`; `validate_scope_id(id: &str) -> Result<()>`; `cpu_quota_percent(millicores: u32) -> Result<u32>`; `wrap_spawn(cmd: Command, machine_id: &str, millicores: u32) -> Result<Command>` (returns the `systemd-run`-wrapped command); `read_back_tier(machine_id: &str) -> Result<EnforcedTier>`

**Task 8b left one wiring dead, and this task must finish it.** `apply_grants`
was wired into `Supervisor::launch`, which turns out to have only Noop and
test `BackendLauncher` implementations — `mvmctl up` boots via
`AnyBackend::start` from `admit_and_start`. So no real boot records an
achieved tier today. Add the call at `admit_and_start`, where the backend
instance is already in hand (the same one `RunPosture::on_backend` reads its
kind from), and record the returned `EnforcedGrants`. Without this, the CPU
mechanism below would enforce a bound that nothing reports — the same
declared-but-unwitnessed shape this plan exists to remove.

**Design points the implementer must honour:**

- **Wrap the spawn, do not move the process.** Where a backend spawns its VMM
  today, the argv becomes `systemd-run --user --scope --quiet --unit
  <scope_name> -p CPUQuota=<n>% -- <original argv>`. Shelling out to
  `systemd-run` rather than adding a D-Bus client keeps the dependency budget
  where the project wants it; the same placement is achieved either way.
- **Percent, not millicores, is systemd's unit.** 1500 millicores is
  `CPUQuota=150%`. Refuse a zero quota rather than emitting `0%`, which would
  mean something other than "unbounded".
- **The scope name derives from the validated machine ID**, never a
  user-supplied string — a crafted unit name is the same class of hazard as a
  crafted cgroup path.
- **Fail honestly when the mechanism is absent.** `systemd-run` may be missing,
  and a user session bus (`XDG_RUNTIME_DIR` / `DBUS_SESSION_BUS_ADDRESS`) may
  not exist in a headless daemon context — the spike showed the session is what
  delegation hangs off. Detect both and return `EnforcedTier::Declared` rather
  than failing the boot, except under `--prod`, which refuses an unenforceable
  grant.
- **Read back, do not assume.** Confirm the achieved tier by reading the
  scope's `cpu.max` (resolve its cgroup path via `systemctl --user show
  <scope> -p ControlGroup`), not by trusting that the spawn succeeded. Verify
  the exact property name and path shape on the spike box rather than
  guessing.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_leaf_name_derives_only_from_the_validated_id() {
        // A user-supplied string in a cgroup path is a traversal into a
        // sibling subtree; the id is validated upstream, so it is the only
        // acceptable source.
        assert_eq!(leaf_name("mvm-abc123"), "mvm-abc123.scope");
    }

    #[test]
    fn a_traversing_id_is_refused() {
        for bad in ["../escape", "a/b", "..", "with space", ""] {
            assert!(
                validate_leaf_id(bad).is_err(),
                "{bad:?} must not reach a cgroup path"
            );
        }
    }

    #[test]
    fn a_valid_id_is_accepted() {
        assert!(validate_leaf_id("mvm-abc123").is_ok());
    }

    #[test]
    fn millicores_convert_to_a_quota_period_pair() {
        assert_eq!(cpu_max_line(1500), "150000 100000");
        assert_eq!(cpu_max_line(1000), "100000 100000");
        assert_eq!(cpu_max_line(500), "50000 100000");
    }

    #[test]
    fn a_zero_share_is_refused_rather_than_written_as_unlimited() {
        // cgroup writes "max" for unlimited; a zero share must never
        // round-trip into that.
        assert!(checked_cpu_max_line(0).is_err());
    }
}
```

- [ ] **Step 2: Run and watch fail**

Run: `cargo nextest run -p mvm-hostd cgroup`
Expected: FAIL — `cannot find function leaf_name`.

- [ ] **Step 3: Implement**

```rust
//! Unprivileged cgroup v2 leaves for per-VM CPU bounds.
//!
//! The VMM process is *born* into its leaf rather than moved into it. Moving
//! an already-running process leaves an interval in which it is unbounded, and
//! that interval is exactly when a workload built to burn CPU would do it.

use anyhow::{Result, bail};
use std::path::PathBuf;

/// cgroup v2 quota period, in microseconds. 100 ms is the kernel default and
/// keeps the quota arithmetic exact for whole and half cores.
const PERIOD_US: u64 = 100_000;

/// A leaf id may contain only characters that cannot change the meaning of a
/// path. The machine id is validated upstream; this is the second gate.
pub fn validate_leaf_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("a cgroup leaf id must not be empty");
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("cgroup leaf id {id:?} contains characters that are not path-safe");
    }
    Ok(())
}

/// The leaf directory name for a machine.
#[must_use]
pub fn leaf_name(machine_id: &str) -> String {
    format!("{machine_id}.scope")
}

/// The `cpu.max` line for a share, in thousandths of a core.
#[must_use]
pub fn cpu_max_line(millicores: u32) -> String {
    let quota = u64::from(millicores) * PERIOD_US / 1000;
    format!("{quota} {PERIOD_US}")
}

/// `cpu_max_line` with the zero case refused. cgroup spells "unlimited" as
/// `max`, and a zero quota would be nonsensical rather than restrictive, so
/// neither is an acceptable rendering of a zero share.
pub fn checked_cpu_max_line(millicores: u32) -> Result<String> {
    if millicores == 0 {
        bail!("a zero CPU share is not expressible: use no grant for unbounded");
    }
    Ok(cpu_max_line(millicores))
}

/// A created, delegated cgroup leaf.
pub struct CgroupLeaf {
    dir: PathBuf,
}

impl CgroupLeaf {
    /// Create the leaf under the delegated user subtree.
    pub fn create(machine_id: &str) -> Result<Self> {
        validate_leaf_id(machine_id)?;
        let dir = delegated_root()?.join(leaf_name(machine_id));
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Write the share and report the tier by **reading it back**. The label
    /// must describe what is in effect, not what was attempted, or a receipt
    /// can assert an enforcement that silently failed.
    pub fn set_cpu_share(
        &self,
        millicores: u32,
    ) -> Result<mvm_contract::protocol::resource_controls::EnforcedTier> {
        use mvm_contract::protocol::resource_controls::EnforcedTier;

        let want = checked_cpu_max_line(millicores)?;
        std::fs::write(self.dir.join("cpu.max"), &want)?;
        let got = self.read_cpu_max()?;
        if got.trim() != want {
            bail!("cpu.max read back as {got:?} after writing {want:?}");
        }
        Ok(EnforcedTier::enforced("cgroup2:cpu.max"))
    }

    pub fn read_cpu_max(&self) -> Result<String> {
        Ok(std::fs::read_to_string(self.dir.join("cpu.max"))?)
    }

    /// The directory fd to hand `clone3` as `CLONE_INTO_CGROUP`, so the child
    /// is bounded at its first instruction.
    pub fn open_dir(&self) -> Result<std::fs::File> {
        Ok(std::fs::File::open(&self.dir)?)
    }
}

/// The delegated subtree this user may write to.
fn delegated_root() -> Result<PathBuf> {
    let uid = nix::unistd::getuid().as_raw();
    let root = PathBuf::from(format!(
        "/sys/fs/cgroup/user.slice/user-{uid}.slice/user@{uid}.service"
    ));
    if !root.is_dir() {
        bail!("no delegated cgroup subtree at {}", root.display());
    }
    Ok(root)
}
```

Gate the module to Linux in `crates/mvm-hostd/src/lib.rs`:

```rust
#[cfg(target_os = "linux")]
pub mod cgroup;
```

- [ ] **Step 4: Run tests**

Run: `cargo nextest run -p mvm-hostd cgroup`
Expected: PASS, 5 tests. The pure functions are host-independent; `create` and
`set_cpu_share` are exercised by the live witness in Task 15.

Cross-check the Linux build from macOS:

Run: `just check-linux`
Expected: success.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-hostd/src/cgroup.rs crates/mvm-hostd/src/lib.rs
git commit -m "feat(hostd): unprivileged cgroup v2 leaf with read-back CPU tier"
```

---

### Task 10: The admission budget, from live liveness

A budget summed from inventory *records* refuses every boot forever once a VM
crashes without cleanup — the safety check becomes a permanent lockout. It has
to be summed from processes that are actually alive.

**Files:**
- Create: `crates/mvm-hostd/src/grants_budget.rs`
- Modify: `crates/mvm-hostd/src/lib.rs`

**Interfaces:**
- Produces: `HostBudget { total_cpu_millicores: u32, total_memory_mib: u64, headroom_percent: u8 }`; `HostBudget::admits(&self, live: &[Commitment], want: &Commitment) -> Result<(), BudgetRefusal>`; `Commitment { cpu_millicores: u32, memory_mib: u64 }`

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> HostBudget {
        HostBudget {
            total_cpu_millicores: 8000,
            total_memory_mib: 16_384,
            headroom_percent: 20,
        }
    }

    fn c(cpu: u32, mem: u64) -> Commitment {
        Commitment {
            cpu_millicores: cpu,
            memory_mib: mem,
        }
    }

    #[test]
    fn a_boot_that_fits_is_admitted() {
        assert!(budget().admits(&[c(2000, 4096)], &c(1000, 2048)).is_ok());
    }

    #[test]
    fn a_boot_past_the_memory_headroom_is_refused() {
        let r = budget()
            .admits(&[c(1000, 12_000)], &c(1000, 2048))
            .expect_err("must refuse");
        assert_eq!(r.dimension, "memory_mib");
    }

    #[test]
    fn a_boot_past_the_cpu_headroom_is_refused() {
        let r = budget()
            .admits(&[c(6000, 1024)], &c(1000, 1024))
            .expect_err("must refuse");
        assert_eq!(r.dimension, "cpu_millicores");
    }

    #[test]
    fn an_empty_live_set_admits_a_boot_within_headroom() {
        // The lockout regression: if dead machines were counted, a host that
        // had crashed VMs would refuse everything forever. Only live
        // commitments are passed in, so an empty set must admit.
        assert!(budget().admits(&[], &c(6000, 12_000)).is_ok());
    }

    #[test]
    fn headroom_is_reserved_not_merely_advisory() {
        // 8000 millicores with 20% headroom leaves 6400 usable.
        assert!(budget().admits(&[], &c(6400, 1024)).is_ok());
        assert!(budget().admits(&[], &c(6401, 1024)).is_err());
    }
}
```

- [ ] **Step 2: Run and watch fail**

Run: `cargo nextest run -p mvm-hostd grants_budget`
Expected: FAIL — `cannot find type HostBudget`.

- [ ] **Step 3: Implement**

```rust
//! Admission-time host capacity check.
//!
//! Commitments are counted against each VM's configured *maximum*, not its
//! current usage: the balloon controller moves commitment at runtime under
//! host pressure, so accounting against the live figure would drift away from
//! the ceiling admission actually granted.
//!
//! The caller supplies only commitments whose processes are alive. A budget
//! summed from unreaped records would refuse every subsequent boot once a VM
//! crashed without cleanup — turning the safety check into a lockout.

use anyhow::Result;

/// One VM's committed maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Commitment {
    pub cpu_millicores: u32,
    pub memory_mib: u64,
}

/// Why a boot was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetRefusal {
    pub dimension: &'static str,
    pub committed: u64,
    pub usable: u64,
}

impl core::fmt::Display for BudgetRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "host budget exceeded in {}: {} committed, {} usable",
            self.dimension, self.committed, self.usable
        )
    }
}

/// Host capacity and the fraction held back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostBudget {
    pub total_cpu_millicores: u32,
    pub total_memory_mib: u64,
    /// Percentage of each total reserved for the host itself.
    pub headroom_percent: u8,
}

impl HostBudget {
    /// Whether `want` fits alongside `live`.
    pub fn admits(&self, live: &[Commitment], want: &Commitment) -> Result<(), BudgetRefusal> {
        let cpu: u64 = live
            .iter()
            .map(|c| u64::from(c.cpu_millicores))
            .sum::<u64>()
            + u64::from(want.cpu_millicores);
        let usable_cpu = self.usable(u64::from(self.total_cpu_millicores));
        if cpu > usable_cpu {
            return Err(BudgetRefusal {
                dimension: "cpu_millicores",
                committed: cpu,
                usable: usable_cpu,
            });
        }

        let mem: u64 = live.iter().map(|c| c.memory_mib).sum::<u64>() + want.memory_mib;
        let usable_mem = self.usable(self.total_memory_mib);
        if mem > usable_mem {
            return Err(BudgetRefusal {
                dimension: "memory_mib",
                committed: mem,
                usable: usable_mem,
            });
        }
        Ok(())
    }

    fn usable(&self, total: u64) -> u64 {
        total * u64::from(100 - self.headroom_percent) / 100
    }
}
```

Note the signature uses `Result<(), BudgetRefusal>`; change the `use anyhow::Result;`
line to `use core::result::Result;` or drop it — the file needs no `anyhow`.

- [ ] **Step 4: Run tests**

Run: `cargo nextest run -p mvm-hostd grants_budget`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-hostd/src/grants_budget.rs crates/mvm-hostd/src/lib.rs
git commit -m "feat(hostd): admission budget counted from live commitments only"
```

---

### Task 11: wasm fuel, epoch, and store limits

Fuel and epoch are **jointly** required. A module blocked inside a host call
consumes no fuel, so a fuel budget alone bounds nothing for a module that parks
in `mvm:egress`.

**Files:**
- Modify: `crates/mvm-runtime/src/wasm_backend.rs` (the `Engine`/`Store`
  construction around line 700, and the `VmInfo` at line 431)

**Interfaces:**
- Consumes: `Grants`, `CpuGrant`, `WallClockGrant` (Task 1); `EnforcedGrants`, `EnforcedTier` (Task 5)
- Produces: `WasmBackend::apply_grants` override; and three helpers this task
  must define, because the tests below call them and nothing else in the plan
  creates them:
  - `WasmBackend::pending_grants(&self) -> &Mutex<Option<Grants>>` — grants
    applied before a module runs are stashed here and consumed at
    engine/store construction, since `apply_grants` takes `&self` and the
    store does not exist yet.
  - `WasmBackend::run_module_with_grants(&self, wat: &str, grants: &Grants) -> Result<()>`
    — test-facing entry point: applies grants, builds the engine and store
    with them, instantiates the module, and calls `_start`. Mark it
    `#[cfg(test)]` unless a production caller appears.
  - `validate_wasm_grants(grants: &Grants) -> Result<()>` — the refusal rules
    (share is not a wasm unit; fuel without wall_clock bounds nothing),
    factored out so `apply_grants` and `run_module_with_grants` cannot drift
    apart on what they accept.

- [ ] **Step 1: Write the failing tests**

Add to that file's test module:

```rust
    #[test]
    fn a_fuel_grant_halts_a_runaway_module() {
        // An infinite loop must be stopped by the instruction budget rather
        // than running until the test harness gives up.
        let wat = r#"(module (func (export "_start") (loop br 0)))"#;
        let b = WasmBackend::default();
        let grants = Grants {
            cpu: Some(CpuGrant::Fuel {
                instructions: 10_000,
            }),
            wall_clock: Some(WallClockGrant::Secs {
                secs: NonZeroU32::new(5).expect("nonzero"),
            }),
            ..Default::default()
        };
        let err = b
            .run_module_with_grants(wat, &grants)
            .expect_err("a runaway module must not complete");
        assert!(
            format!("{err}").contains("fuel"),
            "expected fuel exhaustion, got: {err}"
        );
    }

    #[test]
    fn a_fuel_only_grant_is_refused() {
        // Fuel does not tick inside a host call, so fuel without epoch bounds
        // nothing for a module that parks in one. Accepting it would be
        // partial enforcement reported as complete.
        let b = WasmBackend::default();
        let grants = Grants {
            cpu: Some(CpuGrant::Fuel {
                instructions: 10_000,
            }),
            wall_clock: None,
            ..Default::default()
        };
        let err = b
            .apply_grants(&VmId::from("wasm-test"), &grants)
            .expect_err("must refuse");
        assert!(format!("{err}").contains("wall_clock"));
    }

    #[test]
    fn a_share_grant_is_refused_with_fuel_named_as_the_substitute() {
        let b = WasmBackend::default();
        let grants = Grants {
            cpu: Some(CpuGrant::Share { millicores: 1500 }),
            ..Default::default()
        };
        let err = b
            .apply_grants(&VmId::from("wasm-test"), &grants)
            .expect_err("must refuse");
        assert!(format!("{err}").contains("fuel"));
    }

    #[test]
    fn an_enforced_wasm_tier_names_its_mechanisms() {
        let b = WasmBackend::default();
        let grants = Grants {
            cpu: Some(CpuGrant::Fuel {
                instructions: 1_000_000,
            }),
            wall_clock: Some(WallClockGrant::Secs {
                secs: NonZeroU32::new(30).expect("nonzero"),
            }),
            ..Default::default()
        };
        let e = b
            .apply_grants(&VmId::from("wasm-test"), &grants)
            .expect("applies");
        assert_eq!(e.cpu, EnforcedTier::WasmFuel);
        assert_eq!(e.wall_clock, EnforcedTier::WasmEpoch);
    }
```

- [ ] **Step 2: Run and watch fail**

Run: `cargo nextest run -p mvm-runtime wasm_backend`
Expected: FAIL — `no method named run_module_with_grants`.

- [ ] **Step 3: Turn the controls on**

In the engine construction (currently `Engine::default()` near line 703):

```rust
        let mut cfg = wasmtime::Config::new();
        // Fuel bounds executed instructions; epoch preempts a module parked in
        // a host call, where fuel never ticks. Neither alone is a bound.
        cfg.consume_fuel(true);
        cfg.epoch_interruption(true);
        let engine = Engine::new(&cfg)?;
```

Wire a limiter into the store after `Store::new(...)`:

```rust
        store.limiter(|state| &mut state.limits);
```

adding to `WasmHostState`:

```rust
    /// Bounds the linear memory a module may grow into. A wasm memory grows on
    /// demand, so unlike a microVM it has no allocation fixed at creation.
    pub limits: wasmtime::StoreLimits,
```

- [ ] **Step 4: Implement `apply_grants`**

```rust
/// The rules for what the wasm tier will accept. Shared by `apply_grants` and
/// `run_module_with_grants` so the two cannot drift apart on what they admit.
fn validate_wasm_grants(grants: &Grants) -> anyhow::Result<()> {
    // A share is a fraction of host CPU time; this tier counts instructions.
    // Different units, and no conversion between them exists.
    if matches!(grants.cpu, Some(CpuGrant::Share { .. })) {
        anyhow::bail!(
            "the wasm tier cannot bound a CPU share; express it as fuel \
             (a deterministic instruction budget)"
        );
    }
    // Fuel does not tick inside a host call, so a module parked in one is
    // unbounded by fuel alone. Epoch interruption is what preempts it.
    if matches!(grants.cpu, Some(CpuGrant::Fuel { .. }))
        && !matches!(grants.wall_clock, Some(WallClockGrant::Secs { .. }))
    {
        anyhow::bail!(
            "a fuel grant needs a bounded wall_clock grant: fuel does not tick \
             inside a host call, so a module parked in one would be unbounded"
        );
    }
    Ok(())
}

    fn apply_grants(
        &self,
        _id: &VmId,
        grants: &Grants,
    ) -> anyhow::Result<EnforcedGrants> {
        validate_wasm_grants(grants)?;

        // Stash for the engine/store construction: `apply_grants` takes
        // `&self` and the store does not exist yet.
        *self.pending_grants().lock().expect("pending grants lock") = Some(grants.clone());

        let cpu = match grants.cpu {
            Some(CpuGrant::Fuel { .. }) => EnforcedTier::WasmFuel,
            Some(CpuGrant::Share { .. }) => unreachable!("refused by validate_wasm_grants"),
            None => EnforcedTier::Declared,
        };
        let wall_clock = match grants.wall_clock {
            Some(WallClockGrant::Secs { .. }) => EnforcedTier::WasmEpoch,
            Some(WallClockGrant::Unbounded) | None => EnforcedTier::Declared,
        };
        Ok(EnforcedGrants { cpu, wall_clock })
    }
```

Report the real figures in `VmInfo` (line 431), replacing `cpus: 0, memory_mib: 0`
with the values the applied grants set.

- [ ] **Step 5: Run tests**

Run: `cargo nextest run -p mvm-runtime wasm_backend`
Expected: PASS.

Run: `cargo nextest run --workspace`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-runtime/src/wasm_backend.rs
git commit -m "feat(wasm): enforce fuel, epoch, and store limits on the wasm tier"
```

---

### Task 12: Grants across snapshot, fork, and restore

Today's child-plan check validates signature shape, signer id, plan id, tenant,
and validity window — but not resources. Once grants are the control surface
that opens a laundering path: admit under tight grants, snapshot, restore the
child under loose ones.

**Files:**
- Modify: `crates/mvm-runtime/src/checkpoint/mod.rs` (the child-plan validation
  near line 525)

**Interfaces:**
- Consumes: `Grants` (Task 1)
- Produces: `grants_are_subset(child: &Grants, parent: &Grants) -> Result<()>`

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn a_child_may_narrow_its_parents_grants() {
        let parent = Grants {
            cpu: Some(CpuGrant::Share { millicores: 4000 }),
            ..Default::default()
        };
        let child = Grants {
            cpu: Some(CpuGrant::Share { millicores: 1000 }),
            ..Default::default()
        };
        assert!(grants_are_subset(&child, &parent).is_ok());
    }

    #[test]
    fn a_child_may_not_widen_its_parents_cpu_grant() {
        let parent = Grants {
            cpu: Some(CpuGrant::Share { millicores: 1000 }),
            ..Default::default()
        };
        let child = Grants {
            cpu: Some(CpuGrant::Share { millicores: 4000 }),
            ..Default::default()
        };
        assert!(grants_are_subset(&child, &parent).is_err());
    }

    #[test]
    fn a_child_may_not_reach_a_destination_its_parent_could_not() {
        let parent = Grants {
            egress: Some(EgressGrant {
                allow: vec![HostPort::new("api.example.com", 443)],
            }),
            ..Default::default()
        };
        let child = Grants {
            egress: Some(EgressGrant {
                allow: vec![
                    HostPort::new("api.example.com", 443),
                    HostPort::new("evil.example.com", 443),
                ],
            }),
            ..Default::default()
        };
        assert!(grants_are_subset(&child, &parent).is_err());
    }

    #[test]
    fn a_child_may_not_drop_a_bound_its_parent_carried() {
        // Absent means unbounded for CPU, so an absent child grant under a
        // bounded parent is a widening, not a narrowing.
        let parent = Grants {
            cpu: Some(CpuGrant::Share { millicores: 1000 }),
            ..Default::default()
        };
        assert!(grants_are_subset(&Grants::default(), &parent).is_err());
    }
```

- [ ] **Step 2: Run and watch fail**

Run: `cargo nextest run -p mvm-runtime checkpoint`
Expected: FAIL — `cannot find function grants_are_subset`.

- [ ] **Step 3: Implement and wire in**

```rust
/// Whether `child` asks for no more than `parent` was admitted for.
///
/// Restore is otherwise a laundering path: a VM admitted under tight grants
/// could be snapshotted and its child restored under loose ones, since the
/// child plan is independently signed and internally consistent.
fn grants_are_subset(child: &Grants, parent: &Grants) -> anyhow::Result<()> {
    match (child.cpu, parent.cpu) {
        // An absent child grant is unbounded, so it cannot sit under a
        // bounded parent.
        (None, Some(_)) => anyhow::bail!("child drops the parent's CPU bound"),
        (Some(CpuGrant::Share { millicores: c }), Some(CpuGrant::Share { millicores: p }))
            if c > p =>
        {
            anyhow::bail!("child CPU share {c} exceeds parent's {p}")
        }
        (Some(CpuGrant::Fuel { instructions: c }), Some(CpuGrant::Fuel { instructions: p }))
            if c > p =>
        {
            anyhow::bail!("child fuel {c} exceeds parent's {p}")
        }
        (Some(CpuGrant::Share { .. }), Some(CpuGrant::Fuel { .. }))
        | (Some(CpuGrant::Fuel { .. }), Some(CpuGrant::Share { .. })) => {
            anyhow::bail!("child and parent CPU grants are in different units")
        }
        _ => {}
    }

    if let Some(parent_egress) = parent.egress.as_ref() {
        let child_allow = child.egress.as_ref().map(|e| e.allow.as_slice()).unwrap_or(&[]);
        for want in child_allow {
            if !parent_egress.allow.contains(want) {
                anyhow::bail!(
                    "child egress {}:{} was not admitted for the parent",
                    want.host,
                    want.port
                );
            }
        }
    } else if child.egress.as_ref().is_some_and(|e| !e.allow.is_empty()) {
        anyhow::bail!("child requests egress the parent had none of");
    }

    Ok(())
}
```

Call it in the child-plan validation next to the tenant check, comparing the
child plan's grants against the parent's recorded grants.

- [ ] **Step 4: Run tests**

Run: `cargo nextest run -p mvm-runtime checkpoint`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-runtime/src/checkpoint/mod.rs
git commit -m "fix(checkpoint): refuse a restored child whose grants exceed its parent's"
```

---

### Task 13: The precedence resolver

**Files:**
- Create: `crates/mvm-core/src/grants_resolve.rs`
- Modify: `crates/mvm-core/src/lib.rs`

**Interfaces:**
- Consumes: `Grants` (Task 1)
- Produces: `GrantSources { cli: Option<Grants>, json: Option<Grants>, manifest: Option<Grants>, config: Option<Grants> }`; `resolve_grants(sources: &GrantSources) -> Grants`

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mvm_contract::grants::{CpuGrant, Grants};

    fn cpu(millicores: u32) -> Grants {
        Grants {
            cpu: Some(CpuGrant::Share { millicores }),
            ..Default::default()
        }
    }

    #[test]
    fn the_cli_wins_over_every_other_surface() {
        let s = GrantSources {
            cli: Some(cpu(4000)),
            json: Some(cpu(3000)),
            manifest: Some(cpu(2000)),
            config: Some(cpu(1000)),
        };
        assert_eq!(resolve_grants(&s).cpu, Some(CpuGrant::Share { millicores: 4000 }));
    }

    #[test]
    fn a_lower_surface_supplies_what_a_higher_one_omits() {
        // Precedence is per-dimension, not whole-object: a CLI flag setting
        // CPU must not silently discard the manifest's egress allowlist.
        let s = GrantSources {
            cli: Some(cpu(4000)),
            json: None,
            manifest: Some(Grants {
                egress: Some(mvm_contract::grants::EgressGrant {
                    allow: alloc::vec![mvm_contract::policy::network_policy::HostPort::new(
                        "api.example.com",
                        443
                    )],
                }),
                ..Default::default()
            }),
            config: None,
        };
        let r = resolve_grants(&s);
        assert_eq!(r.cpu, Some(CpuGrant::Share { millicores: 4000 }));
        assert!(r.egress.is_some(), "the manifest's egress must survive");
    }

    #[test]
    fn no_sources_resolve_to_default_grants() {
        let s = GrantSources {
            cli: None,
            json: None,
            manifest: None,
            config: None,
        };
        assert_eq!(resolve_grants(&s), Grants::default());
    }
}
```

- [ ] **Step 2: Run and watch fail**

Run: `cargo nextest run -p mvm-core grants_resolve`
Expected: FAIL — `cannot find type GrantSources`.

- [ ] **Step 3: Implement**

```rust
//! Collapse the four declaration surfaces into one `Grants`.
//!
//! Precedence is applied **per dimension**, not per object: a CLI flag that
//! sets CPU must not discard the manifest's egress allowlist, which whole-
//! object precedence would do silently.

use mvm_contract::grants::Grants;

/// The four surfaces, highest precedence first.
#[derive(Debug, Clone, Default)]
pub struct GrantSources {
    pub cli: Option<Grants>,
    pub json: Option<Grants>,
    pub manifest: Option<Grants>,
    pub config: Option<Grants>,
}

/// Resolve to the effective grants.
///
/// A higher-precedence surface may loosen a lower one — the manifest is a
/// project default and the CLI belongs to the developer running it. What
/// actually bounds the outcome is the ceiling, which no surface here can
/// reach.
#[must_use]
pub fn resolve_grants(sources: &GrantSources) -> Grants {
    let ordered = [
        sources.cli.as_ref(),
        sources.json.as_ref(),
        sources.manifest.as_ref(),
        sources.config.as_ref(),
    ];
    Grants {
        cpu: ordered.iter().flatten().find_map(|g| g.cpu),
        wall_clock: ordered.iter().flatten().find_map(|g| g.wall_clock),
        egress: ordered
            .iter()
            .flatten()
            .find_map(|g| g.egress.clone()),
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo nextest run -p mvm-core grants_resolve`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/grants_resolve.rs crates/mvm-core/src/lib.rs
git commit -m "feat(core): resolve grants across the four surfaces per dimension"
```

---

### Task 14: The four surfaces

**Files:**
- Modify: `crates/mvm-core/src/client/dto.rs:55-131` (`MachineSpec` + builder)
- Modify: `crates/mvm-core/src/domain/manifest.rs:407` (`ManifestMachineWorkflow`)
- Modify: `crates/mvm-core/src/user_config.rs` (ceiling + headroom keys)
- Modify: `crates/mvm-cli/src/commands/machine/mod.rs` (`--cpu-limit`, `--timeout`, `--grants-file`)

**Interfaces:**
- Consumes: `Grants` (Task 1), `resolve_grants` (Task 13)
- Produces: `MachineSpec.grants: Grants`; `MachineSpecBuilder::grants`; `ManifestMachineWorkflow.grants: Option<Grants>`

- [ ] **Step 1: Write the failing tests**

In `crates/mvm-core/src/client/dto.rs`:

```rust
    #[test]
    fn a_machine_spec_can_express_egress() {
        // The in-process library path could not express an outbound allowlist
        // at all before grants: MachineSpec had no network field, so only the
        // argv-shelling SDK builders could set one.
        let spec = MachineSpec::builder("m1", "img")
            .grants(Grants {
                egress: Some(EgressGrant {
                    allow: vec![HostPort::new("api.example.com", 443)],
                }),
                ..Default::default()
            })
            .build();
        assert!(spec.grants.egress.is_some());
    }

    #[test]
    fn a_spec_without_grants_defaults_to_empty_grants() {
        assert_eq!(MachineSpec::builder("m1", "img").build().grants, Grants::default());
    }

    #[test]
    fn a_persisted_spec_without_grants_still_loads() {
        // Machines persisted before grants existed must keep loading.
        let json = r#"{"name":"m1","image":"img","cpus":1,"memory_mib":512,"env":[]}"#;
        let spec: MachineSpec = serde_json::from_str(json).expect("loads");
        assert_eq!(spec.grants, Grants::default());
    }
```

In `crates/mvm-core/src/domain/manifest.rs`:

```rust
    #[test]
    fn a_manifest_grants_table_parses() {
        let toml = r#"
image = "alpine"
[grants]
[grants.cpu]
unit = "share"
millicores = 1500
[grants.egress]
allow = [{ host = "api.example.com", port = 443 }]
"#;
        let m = Manifest::from_toml_str(toml).expect("parses");
        let w = m.machine_workflow().expect("has a workflow");
        let g = w.grants.expect("has grants");
        assert_eq!(g.cpu, Some(CpuGrant::Share { millicores: 1500 }));
    }

    #[test]
    fn an_unknown_grants_key_is_refused() {
        let toml = r#"
image = "alpine"
[grants]
cpu_limt = 2
"#;
        assert!(
            Manifest::from_toml_str(toml).is_err(),
            "a typo must not silently disable a cap"
        );
    }
```

- [ ] **Step 2: Run and watch fail**

Run: `cargo nextest run -p mvm-core dto manifest`
Expected: FAIL — `no field grants`.

- [ ] **Step 3: Implement**

Add to `MachineSpec`:

```rust
    /// The workload's permission set. `#[serde(default)]` so machines
    /// persisted before grants existed keep loading.
    #[serde(default)]
    pub grants: Grants,
```

Add to `MachineSpecBuilder` a `grants: Grants` field defaulting to
`Grants::default()`, the setter:

```rust
    /// Set the workload's grants.
    #[must_use]
    pub fn grants(mut self, grants: Grants) -> Self {
        self.grants = grants;
        self
    }
```

and thread it through `build()`.

Add to `ManifestMachineWorkflow`:

```rust
    /// Declared grants from the manifest's `[grants]` table.
    pub grants: Option<Grants>,
```

Add two `user_config` keys following the existing `set_key` pattern at
`crates/mvm-core/src/user_config.rs:132`: `grant_ceiling_cpu_millicores` and
`budget_headroom_percent`, both parsed as integers with the same
`with_context` error shape as `default_cpus`, and both added to the "Valid
keys" message at line 190.

Add the CLI flags to `MachineRunArgs` in
`crates/mvm-cli/src/commands/machine/mod.rs` beside the existing `--cpus`
(line 278):

```rust
    /// Bound host CPU share, in thousandths of a core (1500 = 1.5 cores).
    /// Distinct from `--cpus`, which is the vCPU count the guest sees.
    #[arg(long = "cpu-limit", value_name = "MILLICORES")]
    pub cpu_limit: Option<u32>,

    /// Maximum wall-clock runtime in seconds.
    #[arg(long = "timeout", value_name = "SECS")]
    pub timeout: Option<u32>,

    /// Read grants from a JSON file. Unknown fields are refused.
    #[arg(long = "grants-file", value_name = "PATH")]
    pub grants_file: Option<PathBuf>,
```

- [ ] **Step 4: Run tests**

Run: `cargo nextest run --workspace`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/client/dto.rs crates/mvm-core/src/domain/manifest.rs \
        crates/mvm-core/src/user_config.rs crates/mvm-cli/src/commands/machine/mod.rs
git commit -m "feat(surfaces): declare grants from config, JSON, CLI, and library"
```

---

### Task 15: SDK parity, docs, and the live witness

**Files:**
- Modify: `xtask/src/ir_parity.rs` (the shared fixture)
- Modify: `crates/mvm-sdk/sdks/python/mvm/_machine.py`
- Modify: `crates/mvm-sdk/sdks/typescript/src/` (the machine module)
- Modify: `public/src/content/docs/reference/cli-commands.md`
- Create: `features/suites/s12_grants/grants.feature`

- [ ] **Step 1: Extend the parity fixture**

Add grants to the shared declaration `xtask gen-ir-parity` executes through
both SDKs, so a grant added to Rust but not Python fails the build.

Run: `cargo run -p xtask -- gen-ir-parity`
Then: `cargo run -p xtask -- check-ir-parity`
Expected: PASS with the regenerated fixture committed.

- [ ] **Step 2: Add the SDK keyword arguments**

In `crates/mvm-sdk/sdks/python/mvm/_machine.py`, beside the existing
`cpus`/`memory` handling near line 145:

```python
    if cpu_limit is not None:
        argv.extend(["--cpu-limit", str(cpu_limit)])
    if timeout is not None:
        argv.extend(["--timeout", str(timeout)])
```

adding `cpu_limit: int | None = None` and `timeout: int | None = None` to each
of the three signatures that already take `cpus`/`memory` (lines ~125, ~170,
~332). Mirror it in the TypeScript machine module.

- [ ] **Step 3: Update the CLI reference**

Document `--cpu-limit`, `--timeout`, and `--grants-file` in
`public/src/content/docs/reference/cli-commands.md`, stating explicitly that
`--cpus` is the vCPU count the guest sees and `--cpu-limit` is the share of
host CPU time — they are different controls and conflating them is the
mistake every container runtime made once.

Run: `cargo run -p xtask -- check-machine-doc-guards`
Expected: PASS. This gate fails the build on undocumented machine flags.

- [ ] **Step 4: Write the BDD suite**

Create `features/suites/s12_grants/grants.feature`:

```gherkin
Feature: Workload grants are declared once and enforced honestly

  Scenario: An unspecified egress grant denies everything
    Given a machine spec with no egress grant
    When the egress policy is derived from its grants
    Then the policy denies every destination

  Scenario: A grant exceeding the host ceiling is refused before boot
    Given a host ceiling of 4000 CPU millicores
    When a machine requests 64000 CPU millicores
    Then admission refuses it naming the cpu dimension
    And no VM is created

  Scenario: A tier that cannot enforce says so
    Given a backend with no CPU control
    When a CPU share grant is applied
    Then the reported CPU tier is "declared"
```

Run: `cargo nextest run -p mvm-conformance grants`
Expected: PASS.

- [ ] **Step 5: The live CPU-quota witness**

A test asserting `cpu.max` file contents proves the write, not the limit. On
the KVM box, boot a workload with `--cpu-limit 1500`, run an in-guest spinner
across more vCPUs than the quota allows, and measure with `/proc/stat` that it
is held near 1.5 cores. Record the measured figure in
`specs/plans/308-cgroup-delegation-findings.md`.

Also confirm the born-into-cgroup property, which the read-back test cannot:
capture the VMM pid at exec and assert `/proc/<pid>/cgroup` already names the
leaf, rather than checking after startup — a post-hoc check passes on the racy
implementation too.

- [ ] **Step 6: Final gate and commit**

```bash
cargo fmt --all
cargo nextest run --workspace
cargo test --workspace --doc
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p xtask -- check-single-grants-projection
cargo run -p xtask -- check-backend-resource-controls
cargo run -p xtask -- check-no-spec-refs-in-comments
cargo run -p xtask -- check-ir-parity

git add -A
git commit -m "feat(grants): SDK parity, CLI reference, and the grant BDD suite"
```

- [ ] **Step 7: Update the plan checkboxes**

Tick the matching workstream boxes in `specs/plans/308-workload-grants.md`
and `specs/REFACTOR-STATUS.md`, bump the rollup's "Last updated" date, and
commit — the repo treats a landed workstream with stale tracking as not done.

---

## Self-Review Notes

**Spec coverage.** WS1 → Tasks 1, 13. WS1b → Task 2. WS2 → Tasks 3, 4.
WS3 → Tasks 5, 6, 7. WS4.0 → Task 8. WS4 → Tasks 9, 10. WS5 → Task 11.
WS5b → Task 12. WS6 → Task 14. WS6b → Task 15.

**Two spec items deliberately deferred, and they are the plan's known gaps:**

1. **The `--prod` refusal of unenforceable grants** is specified in the design
   but has no task. It belongs at the admission site, which Task 5's
   `apply_grants` seam makes reachable but does not itself call. Add it as a
   follow-on once the admission call site is wired, or fold it into Task 14.
2. **Wiring `apply_grants` into the launch path** — Tasks 9 and 11 build the
   enforcement, but nothing in this plan calls `apply_grants` from
   `Supervisor::launch`. That integration is a task in its own right and needs
   the Task 8 verdict first, since the born-into-cgroup requirement changes how
   the VMM process is spawned.

Both are integration rather than mechanism, and both are cheap to specify once
Task 8 resolves. Flagging them here rather than writing a task against an
unknown spawn shape.

**Type consistency checked:** `Grants`, `CpuGrant::Share { millicores }`,
`WallClockGrant::Secs { secs }`, `EgressGrant { allow }`, `GrantCeiling::admits`,
`network_policy_from_grants`, `ResourceControls::for_backend`,
`EnforcedTier::{declared, enforced}`, `EnforcedGrants::all_declared`,
`resolve_grants`/`GrantSources`, `grants_are_subset` are used consistently
across every task that references them.

---

### Task 16: The surfaces — make a grant expressible, and therefore real

**This task combines what the plan originally split into Tasks 13 and 14, on
purpose.** Task 13 was a precedence resolver with nothing to resolve and no
caller. This branch has already produced four controls that shipped correct,
tested, and unreachable — a fifth is registered in `dormant-controls.toml`
right now. Landing a pure resolver on its own would make six. The two halves
ship together or not at all.

**The acceptance criterion is end-to-end, not per-file.** A CPU share and an
egress allowlist declared in `Mvmfile.toml` must reach the signed
`ExecutionPlan`, be checked against the ceiling, and — for egress — be the
thing `EgressGate` enforces. When that holds, `network_policy_from_grants`
has a production caller, and **the `dormant-controls.toml` entry for it is
deleted as part of this task.** That deletion is the done-signal; the gate
fails if the entry lingers once a caller exists, which is the ratchet working.

**Files:**
- Create: `crates/mvm-core/src/grants_resolve.rs`
- Modify: `crates/mvm-core/src/client/dto.rs` (`MachineSpec` + builder)
- Modify: `crates/mvm-core/src/domain/manifest.rs` (`[grants]` table)
- Modify: `crates/mvm-core/src/user_config.rs` (defaults)
- Modify: `crates/mvm-cli/src/commands/machine/mod.rs` (flags)
- Modify: `crates/mvm-cli/src/commands/vm/up/admission.rs:327` — **the connection**
- Modify: `xtask/dormant-controls.toml` (delete the entry)

**The four surfaces, highest precedence first:**

1. **CLI** — `--cpu-limit <MILLICORES>`, `--timeout <SECS>`, `--grants-file <PATH>`.
   `--cpu-limit` is host CPU share; `--cpus` remains the vCPU count the guest
   sees. They are different controls and conflating them is the mistake every
   container runtime made once, so the help text must distinguish them.
2. **JSON** — `--grants-file`, parsed with `deny_unknown_fields` so a typo is a
   refusal rather than a silently dropped cap.
3. **Manifest** — a `[grants]` table on `ManifestMachineWorkflow`.
4. **Library** — `grants` on the `MachineSpec` DTO and its builder, so
   `MvmClient::run_machine` can express an egress allowlist. It cannot today:
   the DTO has no network field at all, which is why every SDK reaches egress
   only by shelling out to `mvmctl`.

**Precedence is per dimension, not per object.** A CLI `--cpu-limit` must not
discard the manifest's egress allowlist. Whole-object precedence would do that
silently, which is the kind of bug that surfaces as "my allowlist stopped
applying" months later.

A higher surface may *loosen* a lower one — the manifest is a project default
and the CLI belongs to the developer running it. What bounds the outcome is
the ceiling, which no surface can reach.

**Witnesses:**
- `a_manifest_grant_reaches_the_signed_plan` — the end-to-end one; assert on
  the admitted `ExecutionPlan`, not on an intermediate struct.
- `cli_overrides_the_manifest_per_dimension_not_wholesale` — set CPU on the
  CLI and egress in the manifest; both must survive.
- `an_unknown_grants_file_field_is_refused`.
- `a_manifest_egress_grant_is_what_the_gate_enforces` — the projection's first
  real caller.
- `a_persisted_machine_spec_without_grants_still_loads` — `#[serde(default)]`;
  machines created before this exist on disk.
- `--cpus` and `--cpu-limit` are independently settable and do not alias.

**Landed.** All six witnesses exist, the dormant entry is deleted, and
`check-dormant-controls` passes — with the entry temporarily restored the gate
fails naming `crates/mvm-cli/src/commands/shared/grants.rs` and
`crates/mvm-hostd/src/run.rs` as production callers, which is the ratchet
confirming the projection is reachable rather than merely present.

Where each surface plugs in:

- **Resolver** — `crates/mvm-core/src/grants_resolve.rs`
  (`GrantLayer`/`GrantSurface`/`resolve_grants`/`load_grants_file`), folded by
  `crates/mvm-cli/src/commands/shared/grants.rs::resolve_run_grants`, which
  settles the grants and derives the egress policy in one step so the two
  cannot be computed in different orders at different call sites.
- **CLI** — `--cpu-limit <MILLICORES>` and `--grants-file <PATH>` on `machine
  run` (and on `machine create`, which also takes `--timeout`). The existing
  `--timeout` supplies the wall-clock dimension rather than a second flag
  meaning the same thing, and `--allow-host` becomes the CLI's egress grant
  through the same parser the legacy path uses.
- **JSON** — `--grants-file` deserializes `Grants` directly, which already
  carries `deny_unknown_fields`.
- **Manifest** — `[grants]` on `Manifest`, converted by
  `ManifestGrants::to_grants` and surfaced as `ManifestMachineWorkflow.grants`.
  Declaring an allowlist in both `[grants]` and `[network]` is a parse error
  rather than a silent ranking.
- **Library** — `grants` on the `MachineSpec` DTO plus
  `cpu_millicores`/`cpu_fuel`/`wall_clock_secs`/`allow_egress`/`grants` on both
  its builder and `LaunchRequestBuilder`. `LocalRunRequest.grants` carries them
  into `admit_and_boot_local`'s `SynthesisInput`, and the egress dimension is
  projected onto `VmStartConfig.network_policy` — the value
  `RealEndpointSpawner` hands the substitution endpoint, i.e. the claim-10
  gate.

The end-to-end path a manifest grant takes: `mvm.toml [grants]` →
`Manifest::validate` → `ManifestGrants::to_grants` → `machine_workflow().grants`
→ `resolve_run_grants` (per dimension, under CLI and grants-file) →
`MachineSpec.grants` on disk → `machine start` → `PersistentImageStartParams`
→ `AdmitPlanForBootParams.grants` → `SynthesisInput.grants` → `admit_for_run`
(ceiling + enforceability) → signed `ExecutionPlan.grants`. Egress splits off at
the resolver: `enforced_network_policy` projects it, `machine start` hands the
result to the launch, and the substitution endpoint enforces it.

Two things worth recording that the task text did not anticipate:

- **`AdmitPlanForBootParams.backend_kind`.** `admit_grants`' enforceability gate
  refuses a declared CPU or wall-clock grant on a sealed run when it cannot name
  the tier that would enforce it, and the CLI was admitting `without_backend`.
  Without threading the typed kind, `--cpu-limit` under a sealed posture would
  have been unusable by construction. The transient path takes it off the
  `AnyBackend` it already selected; the persistent path goes through a new
  `mvm_client::backend_kind_for`, because `check-cli-runtime-surface` (rightly)
  refuses a direct `AnyBackend` reach from a drive-a-machine call site.
- **`Grants` gained `Eq`.** The DTO and the persisted spec both derive it, and
  every field was already `Eq`.

Not done here: the SDK parity fixture (WS6) and everything in WS6b.

---

### Task 19: The host admission budget, and the ADR-001 claim row

Two remaining pieces, landed together because the second is what makes the
first honest.

**The budget.** Nothing refuses the eleventh 4 GiB VM on a 32 GiB host. Per-VM
guest RAM is bounded by construction and CPU is bounded by a quota, but the
*sum* is unbounded, so a host can be oversubscribed into thrashing by
perfectly well-formed individual grants.

Sum committed CPU and memory across running machines and refuse a boot that
would exceed a configurable headroom.

Two constraints that are the whole difficulty:

- **Count only what is live.** A budget summed from inventory *records*
  refuses every subsequent boot forever once a VM crashes without cleanup —
  the safety check becomes a permanent lockout, which is a worse failure than
  the oversubscription it prevents. Derive liveness from the same pid-marker
  probe the fork path already trusts; do not invent a second notion of
  "running".
- **Account against the configured maximum, not current usage.** The balloon
  controller moves committed memory at runtime under host pressure, so
  accounting against the live figure drifts away from what admission actually
  granted.

**The claim row.** `specs/adrs/001-microvm-security-posture.md` carries the
claims ledger, and `xtask check-claim-catalog` parses it — the table is
authoritative, the prose is not. This feature has shipped enforcement across
several PRs with **no row at all**, which is precisely the disease the plan
opens by naming.

Add it as a `Preview` claim, following the shape of rows 16 and 17. Cite only
witnesses that exist — run `rg 'fn <name>'` for each before writing it down,
because `check-witness-citations` will fail the build otherwise and because
fabricated witness names survived in this repo for months once already.

The row must state the limits as plainly as the mechanism: CPU is enforced on
Linux and **declared-only on macOS**, which has no cgroup equivalent; the
wall-clock timer exists only on the libkrun tier, since it is the only VMM
tier with a supervisor process that outlives the workload; a restored child is
admission-bounded but its host-side control is not re-armed. A Preview row
that overstates is worse than no row.

**Witnesses:**
- `a_boot_past_the_headroom_is_refused`
- `budget_ignores_dead_machines` — the lockout regression
- `budget_counts_the_configured_maximum_not_current_usage`
- `an_empty_host_admits_a_boot_within_headroom`
- `xtask check-claim-catalog` passes with the new row
