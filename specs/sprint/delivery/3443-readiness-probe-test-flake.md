# Readiness-probe pipe test: wait for EOF, and stop leaking its holder

Backing: shipped-source
Validation: cargo nextest run -p mvm-cli -E 'test(the_readiness_probe_distinguishes_an_idle_pipe_from_a_written_one)'

`auto_stdin_tests::the_readiness_probe_distinguishes_an_idle_pipe_from_a_written_one`
failed intermittently on macOS under load even when run alone, and it always
leaked a process.

## What fails, measured

The test binary was run directly (`--exact … --nocapture`) in a loop on an
Apple Silicon macOS 26 host at load average 130–270, with 16 extra `yes`
processes for some runs. Every failure was the final assertion: the pipe did
not poll readable after its last write end was dropped. Temporary diagnostics
at that point showed:

- **No process holds the write end.** `lsof` over every process lists only the
  test's own read end, and the pipe polls ready 500 ms later.
- **The delay is short and transient.** Polling again until ready took
  between 3 µs and 241 ms across 85 recorded failures.
- **The holder is not the child.** The child script did not matter:
  `echo exec-done; sleep 30` failed 16/200, `…; exec sleep 30` 4/200, and plain
  `echo exec-done`, which exits at once, 4/200. It still failed 13/200 when the
  child had exited and been reaped before the write end was dropped.
- **Spawning is what triggers it.** With no child spawned, the same assertion
  passed 200/200 under the same load, against 18/200 and 29/200 failures in the
  runs either side of it.

So once a child has been spawned while the pipe is open, macOS can surface EOF
some milliseconds after the last `close`, with nothing holding the write end.
A zero-timeout `poll` reads that window as a live writer. A standalone
reproduction with the same code, as a plain binary or as a libtest test, never
failed across 900 runs, so how often the window opens depends on the process,
but that it opens is a measured fact.

The leak is separate and deterministic. `sh -c 'echo exec-done; sleep 30'` forks
`sleep` as a grandchild that holds the piped stdout and the test's stderr, and
`child.kill()` only reaches `sh`. 20 runs left 7 `sleep 30` processes behind.

## Fix

- The EOF check waits up to 5 s in `poll` instead of sampling once. The case the
  test exists to catch is a leaked write end held by a child that lives 30 s,
  so a bounded wait still fails every time on it. With `FD_CLOEXEC` removed, the
  test failed after 5.03 s as intended.
- The child runs `exec sleep 30`, so the shell becomes the holder and `kill`
  reaches it.

The production probe (`fd_is_readable_now`) is unchanged. For a pipe that has
only been closed, classifying it as idle yields the same empty stdin as reading
EOF would, and a pipe carrying data polls readable immediately.

## Evidence

The old and new binaries were run alternately, 200 each, under the same load:
**before 16/200 failed, after 0/200**. Over 20 runs each, the old binary left 7
`sleep 30` processes behind and the new one left none. `cargo nextest run` of
the test reports no `LEAK`.
