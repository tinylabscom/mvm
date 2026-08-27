# `gh --jq -r` broke the boot-image tag lookup in two workflows

Backing: shipped-source
Validation: actionlint, simulated against the live repo

`gh release list ... --json tagName --jq -r '<expr>'` fails outright. `gh` has
no `-r`; `--jq` takes the expression as its *value*, so `-r` is consumed as the
expression and the real jq program becomes a positional argument. `gh` then
rejects the whole invocation with

```
unknown command "\n    [ .[].tagName\n      | select(test(...
```

which names neither the flag nor the step's purpose, and buries the jq program
in the error text where it reads like corrupted input.

Both copies of this lookup carried it:

- `pages.yml` — the site deploy died here on every run, before reaching the
  Cloudflare Pages step. The site was still being served by GitHub Pages
  (Cloudflare in front as a DNS proxy only), so the cross-origin isolation
  headers that the WebLinux demo needs were never sent, no matter what
  `_headers` said. See [site-cross-origin-isolation.md](site-cross-origin-isolation.md).
- `release.yml` — same expression, resolving which boot-image release a CLI
  release attaches its assets from. It would have failed every release the
  same way. Nothing had exercised it since the flag was introduced.

## The second blocker it was hiding

With the flag fixed, the step resolves `boot-image/v0.1.3` and then fails
because that release carries no `qemu-wasm-smoke-pack.tar.gz`: it was published
2026-08-23, and the job that builds the pack was added to
`release-boot-image.yml` on 2026-08-26. No boot-image release has ever
contained it.

`gh release download` reports that as `no assets match the file pattern`, which
reads like a typo in the pattern rather than a release that needs re-cutting,
so `pages.yml` now checks for the asset by name first and says what to do:

```
::error::boot-image/v0.1.3 carries no qemu-wasm-smoke-pack.tar.gz, so the
WebLinux demo cannot be staged. Cut a new boot-image/v* tag from a commit whose
release-boot-image.yml builds the pack, then re-run this deploy.
```

The pre-existing message on the tag-lookup branch also claimed a release
"contains the WebLinux runtime pack" when all it had checked was that a tag
matched the version pattern. It now says what it tested.

`release.yml` needs no equivalent gate — it already refuses to publish an
incomplete asset set, and the pack is in the list it checks.

## And the blocker behind *that*

Cutting a boot-image tag runs `nix build ./nix#qemu-wasm-smoke-pack`, the same
build that failed in `pages.yml` the run before:

```
error: Cannot build '/nix/store/27dscpgbrpps8zs6awm70m8ks69h1wnx-download.drv'
       > curl: (22) The requested URL returned error: 403
```

crates.io's API host answers a plain curl User-Agent with 403, and Nix's
fetchurl sends exactly that:

```
$ curl -sS -o /dev/null -w '%{http_code}\n' -L https://crates.io/api/v1/crates/bilge/0.2.0/download
403
$ curl -sS -o /dev/null -w '%{http_code}\n' -L -A "mvm-build/1.0" <same URL>
200
```

`nix/packages/qemu-wasm.nix` fetched twelve crates that way. They now go through
`static.crates.io`, the CDN cargo itself uses. It serves byte-identical `.crate`
files, so every recorded `sha256` carries over untouched — verified directly:
the CDN copy of `bilge-0.2.0` hashes to the `0mvvwq9c…` already in the file, and
a real `nix build` of `arbitrary-int-1.2.7` through the new helper succeeds,
which for a fixed-output derivation is the hash check.

The rewrite lives in `nix/lib/crates-io.nix` rather than inline, because
`nix/lib/static-crates-cargo-deps.nix` had already solved this once for the
lockfile-driven path and the constant was about to exist twice. Both import it
now.

The derivations are also named. `fetchurl` names one after the URL's last
segment, so all twelve were called `download` — which is exactly why the CI
error above names neither the crate nor the host it could not reach. They are
`arbitrary-int-1.2.7.crate` and friends from here on.

A pinned nixpkgs pulls ~116 further crates through its own fetcher, still on the
API host. Those are left alone deliberately: `cache.nixos.org` substitutes them
so they never reach the network, which is why only the twelve written here ever
403'd.

## Limits

The nix change is verified by evaluation and by fetching one crate; the full
`qemu-wasm-smoke-pack` build is an Emscripten QEMU compile that was not run
locally. Cutting the boot-image release is still outstanding, and so is pointing
gomicrovm.com at the Pages project. This makes the deploy reach the point where
those are the only things left, and makes each failure say so.
