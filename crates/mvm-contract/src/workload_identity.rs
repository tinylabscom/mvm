//! The claim set a workload presents to an external identity consumer.
//!
//! Today a workload reaches a third-party API because the host holds a
//! long-lived credential and substitutes it on egress. That works, and it keeps
//! the secret off the guest, but the credential is standing: it sits in the
//! host's store until someone rotates it, and the provider's own audit log can
//! only report that *something holding the key* acted.
//!
//! Federation replaces it. The host presents a short-lived assertion of *which
//! workload this is*; the provider exchanges it for its own scoped, expiring
//! credential. Nothing long-lived is stored, and the provider's logs name the
//! workload independently of anything mvm writes.
//!
//! This module is the claim set only — the data, its validity window, and the
//! rules about what may appear in it. There is deliberately no signing, no key
//! material, no network, and no issuer here, so the shape can be settled and
//! tested before any of that exists.
//!
//! # The subject is the workload, not the run
//!
//! [`WorkloadIdentityClaims::subject`] is `(tenant, workload)` and must stay
//! that way. It is tempting to reach for [`crate::plan::types::PlanId`], which
//! is content-addressed and already unique — but `mvm-core`'s `content_id`
//! module is explicit that `plan_id` is *a per-execution identity, not a
//! workload identity*: it commits to the per-synthesis nonce and the validity
//! window, so it changes on every synthesis.
//!
//! That distinction is load-bearing rather than pedantic. A consumer configures
//! trust **once**, against a subject. Binding that to `plan_id` would invalidate
//! the relationship on every single run — the workload would authenticate
//! exactly once and never again. The run identity still travels, as
//! [`WorkloadIdentityClaims::plan_id`], because it is what makes a provider-side
//! log line joinable to an entry in our own audit chain; it is an audit
//! breadcrumb, not the subject.
//!
//! # Why the window is narrow
//!
//! The point of federation is that nothing durable is issued. A long-lived
//! assertion would recreate the standing credential it exists to remove, in a
//! new format. [`MAX_LIFETIME_SECS`] caps it, and
//! [`WorkloadIdentityClaims::validate`] refuses anything longer.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::plan::types::{PlanId, TenantId, WorkloadId};

/// The longest window an assertion may claim, in seconds.
///
/// Ten minutes: long enough to survive a slow exchange and ordinary clock
/// skew, short enough that a leaked assertion is not a credential. Federation
/// exists to stop issuing durable things; a generous window here would quietly
/// undo that.
pub const MAX_LIFETIME_SECS: i64 = 600;

/// The stable identity of a workload across executions.
///
/// A newtype rather than a bare tuple or a formatted string, so the two halves
/// cannot be transposed at a call site and the rendering rule lives in exactly
/// one place.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WorkloadSubject {
    pub tenant: TenantId,
    pub workload: WorkloadId,
}

impl WorkloadSubject {
    pub fn new(tenant: TenantId, workload: WorkloadId) -> Self {
        Self { tenant, workload }
    }

    /// The subject as a consumer sees it: `mvm:workload:<tenant>/<workload>`.
    ///
    /// Prefixed and rendered here rather than at each call site because this
    /// string is what an operator pastes into a trust policy. If it ever
    /// changes shape, every existing policy breaks, so it is deliberately one
    /// function with one test rather than a `format!` scattered around.
    #[must_use]
    pub fn to_subject_string(&self) -> String {
        format!("mvm:workload:{}/{}", self.tenant.0, self.workload.0)
    }
}

/// Why a claim set is not usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimsInvalid {
    /// Empty issuer. A consumer keys trust on it, so it cannot be blank.
    EmptyIssuer,
    /// Empty audience. An assertion valid for anyone is valid for an
    /// attacker's endpoint too.
    NoAudience,
    /// An empty string among the audiences.
    EmptyAudienceEntry,
    /// Empty tenant or workload — the subject would not identify anything.
    EmptySubject,
    /// `not_before` is at or after `expires_at`: the window never opens.
    InvertedWindow,
    /// The window is longer than [`MAX_LIFETIME_SECS`].
    LifetimeTooLong { secs: i64 },
}

impl ClaimsInvalid {
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            ClaimsInvalid::EmptyIssuer => "empty issuer".to_string(),
            ClaimsInvalid::NoAudience => "no audience".to_string(),
            ClaimsInvalid::EmptyAudienceEntry => "empty audience entry".to_string(),
            ClaimsInvalid::EmptySubject => "empty tenant or workload in subject".to_string(),
            ClaimsInvalid::InvertedWindow => "not_before is at or after expires_at".to_string(),
            ClaimsInvalid::LifetimeTooLong { secs } => {
                format!("lifetime {secs}s exceeds the {MAX_LIFETIME_SECS}s maximum")
            }
        }
    }
}

/// A short-lived assertion of which workload is acting.
///
/// Field names mirror the registered claim names a consumer expects, so the
/// serialized form needs no translation layer; the Rust names stay readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentityClaims {
    /// Who issued this. A consumer pins trust to this value.
    #[serde(rename = "iss")]
    pub issuer: String,
    /// Which workload is acting — stable across executions.
    #[serde(rename = "sub")]
    pub subject: WorkloadSubject,
    /// Who may accept it. Never empty: an unscoped assertion is replayable
    /// against any consumer that trusts the issuer.
    #[serde(rename = "aud")]
    pub audience: Vec<String>,
    /// When it was minted.
    #[serde(rename = "iat")]
    pub issued_at: DateTime<Utc>,
    /// Not valid before this. Carried explicitly rather than assumed equal to
    /// `issued_at`, so an issuer can absorb known clock skew deliberately
    /// instead of every consumer guessing a tolerance.
    #[serde(rename = "nbf")]
    pub not_before: DateTime<Utc>,
    /// Expiry.
    #[serde(rename = "exp")]
    pub expires_at: DateTime<Utc>,
    /// The execution this was minted for — an audit breadcrumb joining a
    /// provider-side log line to our own chain. **Not** the subject; see the
    /// module docs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<PlanId>,
}

impl WorkloadIdentityClaims {
    /// Whether the claim set is internally coherent.
    ///
    /// Structure only: whether the window is sane and the required claims are
    /// present. It deliberately does **not** ask whether the window contains
    /// *now* — that is [`Self::is_current_at`], and keeping them apart means a
    /// caller cannot accidentally satisfy "well-formed" by checking the clock.
    ///
    /// # Errors
    ///
    /// The first [`ClaimsInvalid`] found.
    pub fn validate(&self) -> Result<(), ClaimsInvalid> {
        if self.issuer.trim().is_empty() {
            return Err(ClaimsInvalid::EmptyIssuer);
        }
        if self.subject.tenant.0.trim().is_empty() || self.subject.workload.0.trim().is_empty() {
            return Err(ClaimsInvalid::EmptySubject);
        }
        if self.audience.is_empty() {
            return Err(ClaimsInvalid::NoAudience);
        }
        if self.audience.iter().any(|a| a.trim().is_empty()) {
            return Err(ClaimsInvalid::EmptyAudienceEntry);
        }
        if self.not_before >= self.expires_at {
            return Err(ClaimsInvalid::InvertedWindow);
        }
        let secs = (self.expires_at - self.not_before).num_seconds();
        if secs > MAX_LIFETIME_SECS {
            return Err(ClaimsInvalid::LifetimeTooLong { secs });
        }
        Ok(())
    }

    /// Whether `now` falls inside `[not_before, expires_at)`.
    ///
    /// Half-open: an assertion is dead the instant it expires. Takes `now`
    /// rather than reading a clock so this crate stays `no_std` and the
    /// boundary cases are directly testable.
    #[must_use]
    pub fn is_current_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.not_before && now < self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use chrono::{Duration, TimeZone};

    use super::*;

    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 17, 12, 0, 0).unwrap()
    }

    fn claims() -> WorkloadIdentityClaims {
        WorkloadIdentityClaims {
            issuer: "https://issuer.example/mvm".to_string(),
            subject: WorkloadSubject::new(
                TenantId("acme".to_string()),
                WorkloadId("billing".to_string()),
            ),
            audience: vec!["sts.amazonaws.com".to_string()],
            issued_at: t0(),
            not_before: t0(),
            expires_at: t0() + Duration::seconds(300),
            plan_id: None,
        }
    }

    #[test]
    fn a_well_formed_claim_set_validates() {
        claims().validate().expect("should be valid");
    }

    /// The subject string is what an operator pastes into a trust policy.
    /// Changing its shape breaks every policy already written against it, so
    /// the rendering is pinned here on purpose.
    #[test]
    fn the_subject_renders_tenant_and_workload_in_a_stable_form() {
        assert_eq!(
            claims().subject.to_subject_string(),
            "mvm:workload:acme/billing"
        );
    }

    /// The correction this whole module exists to encode: the subject is the
    /// workload, not the run. A `plan_id` subject would break a consumer's
    /// trust policy on every execution.
    #[test]
    fn the_subject_does_not_depend_on_the_execution() {
        let mut a = claims();
        let mut b = claims();
        a.plan_id = Some(PlanId("sha256:aaa".to_string()));
        b.plan_id = Some(PlanId("sha256:bbb".to_string()));
        assert_eq!(
            a.subject.to_subject_string(),
            b.subject.to_subject_string(),
            "two runs of one workload must present the same subject"
        );
        assert_ne!(a.plan_id, b.plan_id, "but the run breadcrumb still differs");
    }

    #[test]
    fn an_unscoped_assertion_is_refused() {
        let mut c = claims();
        c.audience.clear();
        assert_eq!(c.validate(), Err(ClaimsInvalid::NoAudience));
        c.audience = vec!["  ".to_string()];
        assert_eq!(c.validate(), Err(ClaimsInvalid::EmptyAudienceEntry));
    }

    #[test]
    fn an_empty_issuer_or_subject_is_refused() {
        let mut c = claims();
        c.issuer = "  ".to_string();
        assert_eq!(c.validate(), Err(ClaimsInvalid::EmptyIssuer));

        let mut c = claims();
        c.subject.tenant = TenantId(String::new());
        assert_eq!(c.validate(), Err(ClaimsInvalid::EmptySubject));

        let mut c = claims();
        c.subject.workload = WorkloadId(" ".to_string());
        assert_eq!(c.validate(), Err(ClaimsInvalid::EmptySubject));
    }

    #[test]
    fn an_inverted_window_is_refused() {
        let mut c = claims();
        c.expires_at = c.not_before;
        assert_eq!(c.validate(), Err(ClaimsInvalid::InvertedWindow));
        c.expires_at = c.not_before - Duration::seconds(1);
        assert_eq!(c.validate(), Err(ClaimsInvalid::InvertedWindow));
    }

    /// A long-lived assertion is a standing credential wearing a new hat,
    /// which is the thing federation exists to remove.
    #[test]
    fn a_window_longer_than_the_cap_is_refused() {
        let mut c = claims();
        c.expires_at = c.not_before + Duration::seconds(MAX_LIFETIME_SECS + 1);
        assert_eq!(
            c.validate(),
            Err(ClaimsInvalid::LifetimeTooLong {
                secs: MAX_LIFETIME_SECS + 1
            })
        );
        // Exactly at the cap is allowed — the boundary is inclusive.
        c.expires_at = c.not_before + Duration::seconds(MAX_LIFETIME_SECS);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn the_validity_window_is_half_open() {
        let c = claims();
        assert!(!c.is_current_at(c.not_before - Duration::seconds(1)));
        assert!(c.is_current_at(c.not_before), "nbf is inclusive");
        assert!(c.is_current_at(c.expires_at - Duration::seconds(1)));
        assert!(
            !c.is_current_at(c.expires_at),
            "an assertion is dead the instant it expires"
        );
    }

    /// Structural validity and currency are separate questions; a caller must
    /// not be able to satisfy one by answering the other.
    #[test]
    fn validate_does_not_consult_the_clock() {
        let mut c = claims();
        c.not_before = t0() - Duration::days(3650);
        c.expires_at = c.not_before + Duration::seconds(60);
        c.validate()
            .expect("long-expired claims are still well-formed");
        assert!(!c.is_current_at(t0()), "but they are not current");
    }

    #[test]
    fn serde_roundtrips_and_uses_registered_claim_names() {
        let c = claims();
        let json = serde_json::to_string(&c).unwrap();
        for name in [
            "\"iss\"", "\"sub\"", "\"aud\"", "\"iat\"", "\"nbf\"", "\"exp\"",
        ] {
            assert!(json.contains(name), "missing {name} in {json}");
        }
        assert_eq!(
            serde_json::from_str::<WorkloadIdentityClaims>(&json).unwrap(),
            c
        );
    }

    #[test]
    fn an_absent_plan_id_is_omitted_and_an_unknown_field_is_refused() {
        let json = serde_json::to_string(&claims()).unwrap();
        assert!(
            !json.contains("plan_id"),
            "absent breadcrumb is not emitted"
        );
        // `deny_unknown_fields`: a consumer must not silently ignore a claim
        // it does not understand.
        let sneaky = json.replace("{", "{\"extra\":1,");
        assert!(serde_json::from_str::<WorkloadIdentityClaims>(&sneaky).is_err());
    }
}
