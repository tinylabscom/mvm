# Merge-queue forward progress

A twelve-entry queue stopped landing changes when four speculative merge groups
saturated runner admission, successful checks reported after the 90-minute
queue timeout, and the automatic recovery workflow requeued unchanged timed-out
commits. The live ruleset now limits speculation to two entries, permits
immediate one-entry progress, and allows 240 minutes for check response. The
trusted-base recovery workflow reads the authoritative dequeue reason and
refuses to automatically requeue `checks_timed_out`, so capacity pressure can
delay or eject one PR but cannot make that PR indefinitely block every entry
behind it. Workflow syntax, focused regression tests, formatting, workspace
check, all-target host Clippy, and the complete serial workspace test suite
pass.
