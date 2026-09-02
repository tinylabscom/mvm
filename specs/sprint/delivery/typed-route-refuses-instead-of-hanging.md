# Falling through from the typed route hung; refuse instead

#3110 made `try_typed_persistent_build` return `None` on a disk-transport
session, so the build would "fall through to the single-shot builder". Its PR
body said that cost build time rather than correctness.

Live testing says otherwise: it hangs.

## What the measurement showed

Against a real HVF persistent session on macOS 26 / arm64 — the first live
exercise of that path — the fall-through fired twice and the build then sat on

    [mvm] still waiting for the builder image lock (10m04s elapsed)

until killed. `lsof` named the holder: `mvm-hvf-supervisor`, the persistent
session's own supervisor, holding `nix-store-aarch64.img` open for the VM's
lifetime.

Twice, because `dev_build` tries the typed route in two places. The second is
the contention path, whose comment explains the design: when the store image is
busy, *share the session that holds it* rather than queue. Returning `None`
defeats exactly that mechanism, so the build fell past both attempts into a
queue for a lock that only frees when the session stops.

So the fallback is not a safety net here. It is a wait with no end condition.

## The fix

The contended-store block now refuses when the adopted session uses the disk
transport, naming the situation and the way out:

> the persistent builder session `<id>` holds the Nix store image and cannot
> serve this build: it exchanges jobs over the disk transport, which does not
> read back `/job/<id>/out`. A single-shot build would wait for the store image
> until that session stops. Run `mvmctl persistent-builder stop` and build
> again.

That block is the only place that can distinguish "busy, will free up" from
"busy until someone intervenes", so it is the only place that can say so.

The comment #3110 left in `try_typed_persistent_build` is corrected in place
rather than quietly reworded — it asserted the fallback was cheap, and that was
the wrong half of the diagnosis.

## Verified end to end, live

1. Build with a disk-transport HVF session alive → **refuses in seconds** with
   the message above (was: 10+ minutes of silence, then nothing).
2. `mvmctl persistent-builder stop` → supervisor exits, store lock released,
   session record removed.
3. Build again → **succeeds**: real slot, revision, 11.1 MiB rootfs.

Step 3 initially looked like a failure — exit 0 with zero bytes of output. It
was a build-cache hit, which is silent at default verbosity; `-v` shows the full
"Build complete". Worth recording because an empty log with a success code is
indistinguishable from a no-op until you make it talk.

## Why not fix the typed route properly

Making it work over the transport is the open protocol question: the daemon
would need to write its artifact tar onto the output disk, which needs the
device inside the guest and a raw-tar writer in `mvm-builderd`. Until that
lands, a fast refusal naming the remedy is the honest behaviour — and it is
strictly better than both the silent empty success #3110 replaced and the hang
it introduced.

## Verification

`cargo fmt --all --check`, `just check-gated`, `cargo clippy --workspace
--all-targets -D warnings`, `cargo nextest run --workspace` (12,979 passed),
`cargo test --workspace --doc`, `cargo run -p xtask -- check-all` (67 gates).
