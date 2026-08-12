# The eBPF telemetry lane now gates the merge

`Test eBPF telemetry load/attach` ran on every code-bearing merge group and its
result was discarded. It is not a required check in its own right, and it was
named neither in the `Test` aggregate's `needs` nor in the loop that compares
lane results against the scope decision, so a failure there could not block a
merge. The lane is now in both halves. It inherits the same scope-aware
skipped/success matching as every other lane, so non-code merge groups still
skip it and the reporter still passes, and because it finishes well inside the
workspace and Linux lanes the aggregate already blocks on, it gates without
adding wall-clock time. The condition was pre-existing rather than introduced by
the merge-group scoping work, which only prepended `scope` to an already
incomplete list.

The workflow-shape test pins both halves, matching the treatment the
release-witness lane already had; both new assertions were confirmed to fail
against the unfixed workflow before being made green. Workflow syntax,
formatting, xtask Clippy, the complete xtask suite, and the workspace
fmt/Clippy pre-commit gate pass.
