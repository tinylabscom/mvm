# Detached declared ingress

**Status: IN PROGRESS**

Issue #2901 identified a lifecycle gap: TCP ingress has to be declared before
boot, but the CLI rejected the only pre-boot declaration flag when the machine
was detached. The ingress listener belongs to the persistent machine runtime,
not to the foreground command, so detaching does not weaken the signed-plan
boundary or require the retired dynamic-forwarding verb.

## Delivery

- [x] Permit `machine run --detach --port HOST:GUEST` while retaining the
      existing conflicts with transient JSON, TTY, interactive, and entrypoint
      modes.
- [x] Pin persistent-mode resolution and post-start ID output for the combined
      flags in the CLI parser regression.
- [x] Update the Obscura service example to declare ingress on its detached
      launch and reject reintroduction of `machine forward`.
- [x] Prove focused tests, formatting, workspace Clippy, and the relevant CLI
      test suite are green.
- [ ] Merge through the queue and confirm issue #2901 closes from the PR.
