# The template kernel fallback finds the pair's kernel under a selector

Backing: shipped-source
Validation: cargo nextest run -p mvm-cli -E 'test(the_pair_kernel_seeds) | test(local_pair) | test(pair_default_image)'

Closes the open leg the W5m acceptance witness filed as #3615: a sealed
workload built from a user flake reached guest activation and died at
dm-verity setup because the kernel that booted had no device-mapper.

## The mechanism

A plain mkGuest image is a bare rootfs — it carries no kernel. The
template registration resolves the boot kernel through a documented
fallback: the built vmlinux, then the verified workload kernel from the
kernel cache, then the builder kernel. The builder kernel is built
without device-mapper on purpose (the builder boots read-only with no
roothash and never opens a dm device), so the fallback's last rung
cannot activate a sealed rootfs — the comment at the fallback says
exactly that, and the guest died there.

Under a selected checkout the middle rung went unanswered: W5h routes
`ensure_workload_kernel` through the pair, but the template fallback
reads the standalone kernel cache, where the pair's kernel never
landed. With the sibling default, every contributor build selects a
checkout, so every kernel-less flake image fell to the builder kernel.

## The fix

`seed_pair_workload_kernel_cache` runs on the flake/manifest build path
before the template build: under a selected checkout it installs the
pair's verified workload kernel into the standalone kernel cache (copy
plus recorded digest), so the fallback's middle rung answers with the
same bytes the pair's set verified. No selector: the seed is a no-op
and the pre-existing behavior is unchanged.

## Evidence

- New regression test: with a selector and a published default-tenant
  set, the seed installs the pair's kernel and the template fallback
  resolves it `Cached`; the resolved bytes equal the set's verified
  artifact.
- Full workspace suite and gates run as part of this change.
