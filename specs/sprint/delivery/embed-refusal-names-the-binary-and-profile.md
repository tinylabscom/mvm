# One `just embed` now sticks

Plan: `specs/plans/2026-08-28-embedded-host-binaries-are-opt-in.md` (follow-up)

An unembedded `mvmctl` kept coming back after a `just embed` that had genuinely
worked. Three causes, one root.

The root: both feature variants write the same `target/<profile>/mvmctl`, so the
last cargo invocation owns the file. Measured 2026-09-01 — `--features
embed-host-bins` uplifts 32,395,744 bytes, a plain `cargo build --release --bin
mvmctl` puts back 27,012,528 **in 0.26s with nothing compiled**. Any script,
test harness or parallel session was enough to un-embed the binary on `PATH`.
The unembedded build-script arm now restores the payload from the content store
instead of unconditionally writing an empty table: same store, same key
(dependency closure + `Cargo.lock` + pinned toolchain) the embedding arm trusts
when it skips a rebuild, so a hit is proven to be this tree's bytes. It still
cross-compiles nothing. All-or-nothing, because extraction verifies the table as
a unit. A miss, `MVM_EMBED_NO_CACHE=1` or an unreachable store writes the empty
table exactly as before.

The other two were what made it inescapable. `just embed` builds the **debug**
profile, so a release-profile binary told to run it is never replaced — the
refusal is now profile-correct. And `just release-build` had never carried
`embed-host-bins` though `release.yml`'s `MVMCTL_RELEASE_FEATURES` has since the
opt-in landed, so the recipe named "Build optimized release binary" produced the
one build that looks finished and cannot boot anything. `release-channel` stays
out of it: that would resolve artifacts from the published channel rather than
the checkout.

`tests/unembedded_host_binaries.rs` changed shape — it cannot assert
`EMBEDDED.is_empty()` on a machine that has run `just embed`. It matches on the
extraction result and asserts whichever state it finds, in one test with no
skip. Both arms were run: 2042 pass warm, and the binary passes cold under
`MVM_EMBED_NO_CACHE=1`.
