CI notes — short

- UNIX socket path length
  - Some unit tests create AF_UNIX socket files in temporary directories. When the repository or workspace root is deeply nested (e.g. CI worktree paths or developer-specific mounts), the resulting socket path can exceed the OS limit (SUN_LEN; typically 108 bytes) and bind fails with "path must be shorter than SUN_LEN".
  - Workaround implemented in tests: tests that bind AF_UNIX sockets create temp dirs under `/tmp` using `tempfile::tempdir_in("/tmp")`. That keeps paths short across CI/in-tree test runners.

- Fast-mode volume tests
  - To speed unit tests that create/format block images, the code base honors two environment variables during tests:
    - `MVM_TEST_VOLUMES_MIN_BYTES` — explicit cap (bytes) for on-disk image allocation used by mkfs/encrypt steps
    - `MVM_TEST_FAST=1` — shorthand enabling a conservative default cap (4 MiB)
  - These are test-only overrides; they reduce I/O and mkfs/encrypt cost while preserving recorded `capacity_mib` metadata so tests exercise the same logic faster.

If a CI runner still sees socket-length failures, ensure tests run with TMPDIR pointing to a short path (e.g. /tmp) or allow the test helper to choose `/tmp` explicitly.