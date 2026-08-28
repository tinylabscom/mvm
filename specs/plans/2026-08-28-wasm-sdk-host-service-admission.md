# Wasm SDK host-service admission

Backing: shipped-source
Validation: check-sprint-append

**Issue:** [#2977](https://github.com/tinylabscom/mvm/issues/2977)

## Outcome

An admitted wasm launch that binds a native SDK host service is refused at the
delivery seam in terms of the requested services. The typed refusal explains
that the current SDK library needs a read-only disk and native dynamic loader,
so the wasm backend never leaks the synthetic attachment as a generic disk
volume error.

## Delivery checklist

- [x] Add a failing regression for a wasm SDK host-service binding.
- [x] Add a typed backend-compatibility refusal before attachment validation.
- [x] Preserve native microVM SDK-sidecar delivery.
- [x] Add a user-visible BDD scenario and compile the gated runner.
- [ ] Pass the focused BDD scenario, workspace tests, Clippy, and policy gates.
- [ ] Record the completed implementation in the sprint and refactor rollup.
- [ ] Merge the tested pull request and close #2977 through its linkage.
