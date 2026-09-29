# `vm diff` with content (PS-08, #3718)

## What landed

`vm diff` listed paths only. It now diffs file content, read on the host
from the ext4 images the workspace already keeps: the baseline the copy
began as, or a checkpoint's frozen copy, against the live copy or another
checkpoint's. No file content crosses vsock; the guest gained only a
small diff verb on the existing request policy.

- `mvm-fs::diff` walks two file trees and produces content hunks (added /
  removed / modified / binary), reading ext4 images directly.
- `mvm-agentd` answers a guest diff verb so a live workspace can be
  compared without stopping it; the request policy admits it on the same
  profile as the other read verbs.
- `mvm-cli vm diff` renders `--stat`, unified (default), `--side-by-side`,
  and `--json`, with `--from`/`--to` checkpoint selection (defaulting to
  the workspace baseline and the live copy), `--volume`, `--context`,
  and `--max-files`/`--max-file-bytes`/`--max-output-bytes` caps so a
  large workspace cannot flood the terminal.
- `commands/vm/workspace.rs` is the seam the apply step (PS-08's
  journaled `Apply to working tree?`) hangs off: it resolves a
  workspace's baseline/checkpoint images and volumes in one place.

## Not in this slice

The apply prompt, the pre-apply content-addressed host snapshot, the
journal, and undo/redo/replay are the remaining PS-08 items; this slice
is the diff and workspace foundation they build on.

## Tests

- 25 `mvm-fs` diff tests (tree walk, hunk shapes, binary detection,
  caps), 24 `vm diff` render/CLI tests (unified reads like a patch,
  side-by-side pairing and gutters, stat totals, volume prefixes),
  119 checkpoint tests still green.
