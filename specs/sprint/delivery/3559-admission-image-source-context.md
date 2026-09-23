# #3559 — admission owns a stable image-source context

Boot admission used to reread `MVM_IMAGES_DIR` from the process environment.
That made two otherwise independent admissions share mutable authority: a test
temporarily selecting a local checkout could make parallel production-profile
admissions refuse, even though their callers selected no checkout.

`AdmitPlanForBootParams` now carries the configured image directory captured by
its caller. The release-channel refusal consumes only that value, while the
managed-image trust-tier check remains tied to the rootfs that will actually
boot. CLI and library launch paths capture the selector when they construct the
admission request; unit tests pass the intended context directly and no longer
mutate `MVM_IMAGES_DIR`.

A deterministic parallel regression runs release-channel admission gates with
alternating configured and unconfigured contexts. Configured requests refuse
and unconfigured requests succeed independently, without a process-global
lock or production-path serialization.

Validation is complete: the default and release-channel admission suites,
single-threaded workspace suite, workspace check, zero-warning Clippy,
Linux/feature-gated compilation, formatting, and all 74 repository gates pass.
