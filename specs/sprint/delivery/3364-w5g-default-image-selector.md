# The default workload image reads the image source selector

Backing: shipped-source
Validation: cargo nextest run -p mvm-cli -E 'test(pair_default_image) | test(local_pair)'

Slice W5g of the sibling-checkout workflow (#3364). With `MVM_IMAGES_DIR`
naming a checkout, the prod default workload image is the pair's
`default-tenant` target: built once by the shared local-image-set build,
served from the local image cache, installed into the default-image cache,
and stamped with the pair identity. With the selector unset, the in-tree
build and the published download are unchanged.

## What changed

- `ensure_default_microvm_prod_image` routes a selected checkout to the
  pair's `default-tenant.default` before the existing logic runs. The
  installed image answers again only when the sidecar's stamped pair
  fingerprint is the pair on disk now; a changed pair reinstalls, and an
  in-tree or fetched image is never mistaken for a pair answer (the probe
  reads only a `source: "local-pair"` sidecar). An unusable configured path
  is an error here, never a quiet fall-through to the published download; a
  binary without the `builder-vm` feature refuses the selector outright
  rather than silently downloading.
- `MVM_BOOT_IMAGE=fetch` under a selected checkout is refused with the way
  out named (unset the selector for that run), matching the plan's rule
  that comparing against a signed release is fetch with the selector unset.
  `MVM_BOOT_IMAGE=build` is the pair build's normal behavior. The
  auto-detect input to the resolver is now "images buildable from source" —
  the in-tree flakes or a selected checkout — through one shared predicate
  (`images_built_from_source`), which `image boot update`'s refusal also
  uses now instead of its private copy.
- `doctor`'s boot-image line reports the pair: "building from the local
  image checkout at <path>", and says fetching is refused while a checkout
  is selected.
- Only the prod variant moves: the sibling image repository publishes the
  `default` attribute and the dev variant's writable image is an in-tree
  convenience with no counterpart there, so dev keeps building from the
  in-tree flake (the tool builder it runs in still comes from the pair when
  one is selected, per W5f).

## Evidence

- New tests: the sidecar probe accepts only a pair-stamped install; a
  published default-tenant set installs into the variant cache, stamps the
  pair identity, and re-answers with the backing cache removed; the
  fetch-under-selector refusal errors before producing anything. The
  pair-fixture helpers moved into a shared `test_pair` module both this
  slice and W5f's tests use.
- Full workspace nextest: 14660 passed; the one failure is the known
  macOS-flaky vcpu-time thread test (#3452), which passes on rerun.
- No VM witness: install and freshness are covered without booting; a live
  boot of a pair-built default image is W5m's witness.

## Not done

- W5h (kernel acquisition and the initramfs): the pair's `default-tenant`
  carries the workload kernel, but `ensure_workload_kernel` and the
  kernel-pin path still build or fetch the kernel independently of the
  selector.
- The dev default image stays in-tree until the sibling image repository
  publishes a dev attribute to build through the shared contract.
