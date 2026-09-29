# Verb grant no longer expires during boot preparation (#3752)

A cold `machine run --image alpine -d` on macOS failed with
`VerbNotAuthorized{activate-environment}`, and the guest console said
`verb grant expired`. The host mints the agent verb grant from the admitted
plan with `not_after = plan.valid_until`, so the grant's life is the plan's
validity window. Every launch path admitted first, and only then attached the
runtime overlay and initramfs. On a contributor build, attaching the overlay
cold-builds it. In the reported run that build took 446 s, and the guest
checked the grant after the window had closed.

## The fix is the order, not a longer window

`mvm_client::launch::boot_order::admit_after_preparation` runs the preparation
step and only then the admission that starts the window. A preparation failure
admits nothing. The persistent start path (`launch/persistent.rs`) uses it.
The transient run (`mvm-cli/src/exec.rs`), the session VM
(`exec/session.rs`) and the checkpoint fork (`commands/vm/checkpoint.rs`) now
attach their overlay and initramfs before admission, with a comment pointing
at the same rule. As a side effect, the persistent admission now pins the
kernel from the exact config the backend is handed.

## When a grant does expire, the error says so

- **At mint.** `mint_verb_grant_sidecar` refuses a plan whose window has
  already closed, naming the closing time, the window, and the admission
  time. The guest would otherwise refuse with a bare `VerbNotAuthorized`.
- **At activation.** A `VerbNotAuthorized` for activation is explained from
  the grant the host sent. An expired grant says when it expired and how long
  before activation. A live grant that was still refused points at the guest
  console log. A missing grant says that none was sent.

## Tests

- `a_slow_preparation_cannot_spend_the_grant_window` runs real admission and
  a real grant mint after a 1.5 s preparation. It checks that the plan's
  window opens after preparation, and that the grant has the whole window
  left when preparation ends.
- `admitting_before_preparation_loses_the_preparation_time` is the control:
  the old order loses at least the preparation time.
- Two more tests cover the helper itself: a failed preparation admits
  nothing, and admission receives the prepared config.
- The refusal at mint time, and each of the three activation explanations.
