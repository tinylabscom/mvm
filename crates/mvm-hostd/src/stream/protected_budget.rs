//! In-memory reservations serialized with protected durable admission.
//! Policy and authenticated retirement remain in the transcript layer.

use mvm_core::transcript::GenerationBudget;
use std::sync::{Arc, Mutex};

use crate::audit::transcript_retirement::GenerationReservation;

pub(super) type SharedReservations = Arc<Mutex<Reservations>>;

pub(super) struct Reservations {
    limit: GenerationBudget,
    used: GenerationReservation,
    pressure: Option<GenerationReservation>,
    blocked: bool,
}

impl Reservations {
    pub fn new(limit: GenerationBudget, retained: GenerationReservation) -> Self {
        Self {
            limit,
            used: retained,
            pressure: None,
            blocked: false,
        }
    }

    pub fn reserve(&mut self, bytes: u64) -> bool {
        let incoming = GenerationReservation {
            plaintext_bytes: bytes,
            chunks: 1,
        };
        let fits = self
            .used
            .plaintext_bytes
            .checked_add(bytes)
            .is_some_and(|total| total <= self.limit.max_plaintext_bytes)
            && self
                .used
                .chunks
                .checked_add(1)
                .is_some_and(|total| total <= self.limit.max_chunks);
        if self.blocked || !fits {
            if bytes > 0 && bytes <= self.limit.max_plaintext_bytes {
                let pending = self.pressure.get_or_insert(incoming);
                pending.plaintext_bytes = pending.plaintext_bytes.max(bytes);
            }
            return false;
        }
        self.used.plaintext_bytes += bytes;
        self.used.chunks += 1;
        true
    }

    /// Only queue rejection may release a reservation. Once a writer has
    /// accepted work, even an I/O failure stays charged until a joined seal.
    pub fn release_rejected(&mut self, bytes: u64) {
        self.release_retired(GenerationReservation {
            plaintext_bytes: bytes,
            chunks: 1,
        });
    }

    pub fn release_retired(&mut self, retired: GenerationReservation) {
        match (
            self.used
                .plaintext_bytes
                .checked_sub(retired.plaintext_bytes),
            self.used.chunks.checked_sub(retired.chunks),
        ) {
            (Some(plaintext_bytes), Some(chunks)) => {
                self.used = GenerationReservation {
                    plaintext_bytes,
                    chunks,
                };
            }
            _ => self.blocked = true,
        }
    }

    pub fn pressure(&self) -> Option<GenerationReservation> {
        self.pressure
    }

    /// Caller holds the family owner and has joined the old writer, verified
    /// every retained terminal root, and completed any authorized cleanup.
    pub fn reconcile(&mut self, retained: GenerationReservation) {
        self.used = retained;
        self.pressure = None;
        self.blocked = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_include_old_generations_and_encoded_envelope_bytes() {
        let budget = GenerationBudget {
            max_plaintext_bytes: 100,
            max_chunks: 3,
            ..Default::default()
        };
        let mut ledger = Reservations::new(
            budget,
            GenerationReservation {
                plaintext_bytes: 60,
                chunks: 1,
            },
        );
        assert!(ledger.reserve(30));
        assert!(!ledger.reserve(11));
        assert_eq!(ledger.pressure().unwrap().plaintext_bytes, 11);
        ledger.release_rejected(30);
        assert!(ledger.reserve(40));
        assert!(!ledger.reserve(1));
        ledger.reconcile(GenerationReservation {
            plaintext_bytes: 0,
            chunks: 0,
        });
        assert!(ledger.reserve(100));
        assert!(!ledger.reserve(1));
    }

    #[test]
    fn chunk_limits_and_invalid_release_fail_closed() {
        let budget = GenerationBudget {
            max_plaintext_bytes: 100,
            max_chunks: 1,
            ..Default::default()
        };
        let mut ledger = Reservations::new(
            budget,
            GenerationReservation {
                plaintext_bytes: 0,
                chunks: 0,
            },
        );
        assert!(ledger.reserve(1));
        assert!(!ledger.reserve(1));
        ledger.release_rejected(2);
        assert!(!ledger.reserve(1));
    }
}
