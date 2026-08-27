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

## Limits

Cutting the boot-image release is still outstanding, and so is pointing
gomicrovm.com at the Pages project. This change makes the deploy reach the
point where those are the only things left, and makes the failure say so.
