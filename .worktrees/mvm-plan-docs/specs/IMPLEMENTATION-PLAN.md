# Implementation Prompt

To implement the plans for issues #3068, #3011, and #3007, run:

```bash
source scripts/dev-env.sh && xtask check-all
```

Then proceed with:

1. **Issue #3068 (SDK sidecar)**:
   - Modify `crates/mvm-contract/src/plan/execution_plan.rs` to add `sdk_uses_sidecar: bool` field
   - Update `crates/mvm-contract/src/plan/sdk_sidecar.rs` to condition on this flag
   - Update `crates/mvm-hostd/src/plan_admission.rs` admission gates
   - Update language SDKs (Python, Go) to support direct broker protocol

2. **Issue #3011 (macOS e2e)**:
   - Acquire self-hosted Apple Silicon runner
   - Fix `workspaceRoot` resolution in `nix/images/builder-vm/flake.nix`
   - Ensure `MVM_WORKSPACE_PATH` is exported for SDK-sidecar builds

3. **Issue #3007 (Extended CI)**:
   - Fix #3011 as prerequisite
   - Add failure alerting to GitHub Actions
   - Add CI status badges to README
