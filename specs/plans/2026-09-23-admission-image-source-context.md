# Admission image-source context

Backing: shipped-source
Validation: check-sprint-append

**Status: COMPLETE**

## Scope

Make the image-source selector used by boot admission an explicit input rather
than a process-global read inside the admission function. This fixes #3559:
parallel libtest admissions must not observe a temporary `MVM_IMAGES_DIR`
value owned by a different test.

- [x] Add the captured configured image directory to the boot-admission input.
- [x] Thread the caller's selector through every production admission path.
- [x] Replace admission tests' selector mutations with explicit inputs.
- [x] Prove parallel release-channel admissions with different captured
      selectors remain independent.
- [x] Run the focused default and release-channel libtest suites, workspace
      check/tests, formatting, Clippy, and gated-target checks.
