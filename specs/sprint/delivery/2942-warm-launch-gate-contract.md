# Warm-launch gate contract repair

Backing: shipped-source
Validation: check-sprint-append

The launch-mode BDD called a warm claim but compared its one observed dispatch
window with the 200 ms prepared-cold target. That mixed two different contracts:
prepared-cold publishes a 200/250/300 ms percentile matrix plus a strict
per-sample boundary, while a warm claim has a strict sub-300 ms hard ceiling and
tighter aggregate p50/p99 targets.

The CLI now exposes its existing hard-ceiling constant and strict comparison as
one narrow launch-contract surface. The phase-timing report and live BDD step
both call that predicate, so the scenario cannot drift to a second literal.
Exactly 300 ms remains a failure. The 224.5 ms observation from issue #2942 is
therefore honestly classified as within the warm hard ceiling; it is not
presented as a prepared-cold percentile result.
