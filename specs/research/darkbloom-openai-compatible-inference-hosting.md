# Research — Darkbloom API compatibility and mvm as an OpenAI-compatible inference host

**Status:** Research note; no implementation commitment  
**Date:** 2026-08-24  
**Owner:** mvm  
**Source:** `specs/scratch.md#L110-L120` (Darkbloom observation)  
**Related:** ADR-001 (security posture / attestation scoping), `feat/tpm2-attestation` (hardware-backed measurement stubbing), Plan 2026-08-18-certifying-assurance-campaign-closeout

## Bottom line

- Darkbloom's API compatibility is a **great UX pattern**: don't make users learn a new SDK.
- mvm already has the *egress* side of AI workloads covered (metering, budgets, audit).
- The *ingress* side — becoming an OpenAI-compatible model host — is a separate, larger bet.
- If mvm makes that bet, the microVM isolation + attestation work we just stubbed out becomes load-bearing and valuable.

## Open question

Do we want to explore what an mvm OpenAI-compatible inference endpoint would look like, or is mvm's current "sandbox workloads that call external AI APIs" direction the right boundary for now?
