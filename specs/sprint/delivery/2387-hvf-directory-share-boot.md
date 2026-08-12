# HVF directory-share boot regression

Queue-backed virtio-fs now reports the virtio-MMIO all-one sentinel for an
absent DAX shared-memory region instead of exposing a false zero-length window
that Linux rejects. The 456-test VMM suite passes, and the original Alpine
`machine run --mount .:/work -- ls /work` command succeeds on native HVF;
workspace checks, doctests, and host Clippy are green.
