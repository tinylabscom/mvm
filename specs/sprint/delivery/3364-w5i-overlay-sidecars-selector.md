# The guest runtime path reads the image source selector

Backing: shipped-source
Validation: cargo nextest run -p mvm-cli -p mvm-client -E 'test(pair_routing) | test(image_source) | test(local_pair) | test(runtime_source) | test(runtime_overlay)'

Slice W5i of the sibling-checkout workflow (#3364). With `MVM_IMAGES_DIR`
naming a checkout, the guest runtime — the launch-time runtime overlay and
both SDK sidecar variants — is the pair's `runtime-overlay` targets, served
from the local image cache and installed under the version-matched caches
with the pair identity recorded beside the install. With the selector unset,
the in-tree build and the published download are unchanged.

## What changed

- The launch-time overlay (`attach_runtime_overlay_if_cached_version`) takes
  a pair source. Under a selected checkout it installs the pair's
  `runtime-overlay.default` into the overlay cache and records the pair
  cache-key digest in a sibling stamp; an unchanged pair answers from the
  install, a changed pair builds once and reinstalls. The pair arm resolves
  from the cache and returns: falling through would run the in-tree build
  arm — for a contributor build it rebuilds from the mvm checkout on every
  boot, overwriting the pair's bytes — or the published-download ladder, and
  neither may run under a selector. A version mismatch between the pair's
  overlay and this mvmctl is refused naming both versions.
- The launch-time SDK sidecar (`resolve_sdk_sidecar_attachment_for_host`)
  takes the same pair source and installs through
  `install_source_built_sidecar`, whose source-fingerprint marker is the
  freshness record: the marker names the pair the sidecar was built from,
  and a pair whose identity moved reinstalls. The download arm refuses
  under a selector, naming the explicit pair build command.
- Both build verbs move with the consumer: `mvmctl build runtime-overlay
  build` builds the pair's overlay and stamps the install (fetching the
  published overlay under a selector is refused, as in W5g), and `mvmctl
  build sdk-sidecar build` builds both libc variants from the pair. `--force`
  stays an in-tree concept: the pair answers from its content-addressed
  cache, so an unchanged pair has nothing to force.
- The duplicate checkout detection collapses: the two private copies of the
  "in-tree runtime-overlay flake present?" probe (mvm-client and
  mvm-build/runtime_overlay) are one shared
  `image_source::in_tree_overlay_checkout_root()`, and consumers below the
  CLI resolve the selection through one `image_source::resolve_current_source()`.
  The probe stays deliberately selector-independent: under a selector the
  launch arms route through the pair and never consult it; it remains the
  answer for the selector-unset in-tree window.
- The pair build is injected: `PairArtifactSource` carries the checkout and
  a build closure the CLI supplies (`with_pair_artifact_source`), so
  mvm-client orchestrates caches and stamps without ever booting a VM.

## Evidence

- New tests: the fetch-refusal under a selector; an end-to-end run that
  publishes the pair's `runtime-overlay` set into the warm cache, builds the
  verb (cache hit, no VM), asserts the install and that the recorded stamp
  is the pair cache-key digest, and then attaches at launch from the stamped
  install alone. The 13-minute first run of that test exposed the
  fall-through bug above; fixed, the whole test finishes in seconds.
- Full workspace suite and gates run as part of this change.

## Not done

- The builder VM's own overlay (`builder_runtime_overlay_or_bail`) still
  resolves in-tree or published: the tool builder is exempt from the
  selector (W5f), and its in-guest overlay is a separate consumer a later
  slice can route through the pair without recursion.
- W5j's checkout key protects the supervisor auto-build; the sdk-sidecar
  helper re-exec path keeps its in-tree semantics until a caller needs
  otherwise.
- W5k (admission reads the recorded tier), W5l (docs and the paired CI
  job), W5m (the acceptance witnesses) remain.
