//! The nonce ledger a plan admission spends against.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use mvm_core::plan::{ExecutionPlan, NonceStore};
use std::sync::Mutex;

/// The nonce ledger an admission spends against. Holds a `NonceStore` behind a
/// mutex so it's `Send + Sync`.
///
/// [`new`](Self::new) remembers nonces for this ledger's lifetime only, which
/// is right for a plan the host signed itself with a fresh random nonce. A plan
/// signed by someone else can be submitted again until it expires, so a launch
/// that carries one uses [`durable`](Self::durable), which also records each
/// spent nonce in a file shared by every process on the host.
pub struct InMemoryNonceLedger {
    pub(super) inner: Mutex<NonceStore>,
    #[cfg(unix)]
    durable: Option<mvm_core::plan::nonce_ledger::FileNonceLedger>,
}

impl InMemoryNonceLedger {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(NonceStore::default()),
            #[cfg(unix)]
            durable: None,
        }
    }

    /// A ledger that also records spent nonces under the host's plan-nonce
    /// directory. Opening it can fail; a launch that cannot record its nonce
    /// must not proceed.
    #[cfg(unix)]
    pub fn durable() -> std::io::Result<Self> {
        Self::durable_in(mvm_core::config::plan_nonce_dir())
    }

    /// [`durable`](Self::durable) rooted at `dir`.
    #[cfg(unix)]
    pub fn durable_in(dir: impl Into<std::path::PathBuf>) -> std::io::Result<Self> {
        Ok(Self {
            inner: Mutex::new(NonceStore::default()),
            durable: Some(mvm_core::plan::nonce_ledger::FileNonceLedger::open(dir)?),
        })
    }
}

impl Default for InMemoryNonceLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryNonceLedger {
    /// Record `plan`'s nonce for `signer`, refusing a nonce already spent.
    pub(super) fn spend(
        &self,
        signer: &str,
        plan: &ExecutionPlan,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.inner
            .lock()
            .expect("nonce store mutex poisoned")
            .check_and_insert(signer, plan)
            .context("replay protection check")?;
        #[cfg(unix)]
        if let Some(durable) = &self.durable {
            use mvm_core::plan::PlanValidityError;
            use mvm_core::plan::nonce_ledger::NonceLedgerError;
            durable
                .check_and_insert(signer, plan, now)
                .map_err(|e| match e {
                    NonceLedgerError::Replay { signer } => {
                        anyhow::Error::new(PlanValidityError::NonceReplay { signer })
                    }
                    NonceLedgerError::Unavailable(why) => {
                        anyhow::anyhow!("{why} — refusing a plan whose nonce cannot be recorded")
                    }
                })
                .context("replay protection check")?;
        }
        #[cfg(not(unix))]
        let _ = now;
        Ok(())
    }
}
