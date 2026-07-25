# Stable workload key for firewall state

Issue: #1813

Status: COMPLETE

## Scope

Key supervisor-owned firewall state by `(tenant, workload)` so a hot plan
revision replaces the previous rules instead of leaking an install under the
old `plan_id`. Keep the `DekBinding.plan_id` field unchanged: mvm currently
uses it only for the per-execution encrypted artifact envelope, while mvmd
owns the future workload-lifetime DEK binding and must migrate that path when
hot revisions become live.

## Delivery checklist

- [x] Add a typed `WorkloadKey` and transient plan-to-workload teardown index.
- [x] Replace prior firewall state when a new revision for the same workload
      is admitted, and preserve normal stop/launch-failure cleanup.
- [x] Add a regression test covering two plan revisions with one firewall
      install and no orphaned teardown state.
- [x] Run formatting, workspace check, tests, and clippy gates.
- [x] Publish the verified branch as pull request #1847.
