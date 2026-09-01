# The verified-kernel-reads gate now sees hand-rolled paths

`check-verified-kernel-reads` exists to stop a workload kernel booting on an
`exists()` check instead of a verified digest. It worked, for the callers that
asked the shared helper where the kernel lives:

```rust
crate::fs_walk::for_each_file(&workspace.join("crates"), Some("rs"), &mut |path, text| {
    if text.contains(LOCATION) { ... }   // LOCATION == "cached_kernel_path"
});
```

A file that spelled the layout itself never entered that walk. It was not
examined and found acceptable — it was not examined.

## What that hid

The kernel-cache relocation (PR #3038) found the layout hand-rebuilt at nine
call sites. Routing them through `kernel_cache_dir` / `cached_kernel_path` made
two of them visible to this gate for the first time, and one was a genuine
violation that predates that branch:

```rust
// crates/mvm-conformance/tests/conformance.rs
let cached = /* hand-built <cache>/builder-vm/<arch>/kernels/workload/vmlinux */;
cached.is_file().then_some(cached)
```

That is the kernel every `@workload_kernel` BDD scenario boots, selected by
whether a file exists. It is exactly what the gate is for, and the gate could
not see it for as long as it declined to use the helper.

The incentive was backwards: naming `cached_kernel_path` opted you into
scrutiny, and hand-rolling the path opted you out. A gate that only inspects
the disciplined callers is reporting on the population least likely to be wrong.

## What changed

Two checks, ordered so the first makes the second complete.

**One definition of the layout.** `.join("kernels")` outside
`crates/mvm-build/src/kernel_fetch.rs` is refused. Every caller is therefore
forced through the helper, which puts every caller inside the verified-read
check that follows. The allow-list governs that second check only: a staging
lane may read the location without verifying, but it may not keep its own copy
of where the location is.

**A drift alarm for shell.** A script cannot call a Rust helper, so it is held
to the weaker rule: do not name the retired location. This is aimed at one
concrete failure — the same relocation left
`e2e-launch-modes.sh` running `find "$E2E_HOME/cache/builder-vm" -name vmlinux`,
which finds nothing, reports no error, and silently drops the in-process
`mvm-client` seam from the lane. That was caught only because the script had
been written to fail loudly on a missing kernel rather than skip. The check
distinguishes a kernel path from the builder VM's *own* kernel, which still
lives under `builder-vm/<arch>/vmlinux` legitimately.

## Limits

The one-definition rule is a string match on `.join("kernels")`. A caller
determined to evade it can build the path from a variable, and the shell check
knows only the retired name, not the current layout — a script pointed at a
third location is invisible to both. Neither is a proof; they raise the cost of
the specific mistake that has now happened twice.

The original co-presence caveat is unchanged and still applies: a file may
resolve through the seam in one function and use a bare path in another.

## Verification

Eleven gate tests, of which three are new and were red before the change: the
old gate returned `Ok` for a hand-rolled layout (never walked), `Ok` for an
allow-listed file with its own copy of the layout, and `Ok` for any shell at all
(it scanned no shell). `check-all` is green across all 62 gates, with the
workspace suite, Clippy, doctests and `check-gated`.

## Also in this change

`specs/REFACTOR-STATUS.md` had two entries under **In progress** reading "merge
delivery remains" for work already on `main` — the kernel cache relocation
(#3038, `927f25bc29`) and the machine diff handshake retry (#3024/#3028,
`a22414f5ce`). Both verified merged by commit and moved to **Completed**. The
staleness is structural rather than anyone's oversight: the file asks to be
ticked in the same change as the work, and the tick is only true after that
change merges.
