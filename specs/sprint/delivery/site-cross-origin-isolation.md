# The demo on the homepage had no SharedArrayBuffer

Backing: shipped-source
Validation: pnpm check:headers, check-site-isolation-headers.sh, demo-e2e.mjs

The WebLinux demo embedded on the landing page fails in the browser with

```
DEMO-RESULT: ERROR SharedArrayBuffer is not defined
```

QEMU-Wasm uses pthreads, so it needs `SharedArrayBuffer`, which browsers
expose only to a cross-origin-isolated document. Two independent things
were preventing that, and each is sufficient on its own.

## The scope was wrong

`public/public/_headers` declared COOP/COEP for `/demo/weblinux/*` only.
The landing page embeds the demo as an iframe (`DemoTeaser.tsx`), and
isolation does not propagate upward from a frame: a frame is isolated only
when the top-level document is isolated too. So the standalone demo page
would have worked and the embedded copy — the one nearly every visitor
reaches — could not.

The scope is now `/*`. `require-corp` site-wide means every cross-origin
subresource needs CORP or CORS headers; the site loads none today (external
origins appear only as link targets and a form action), so this costs
nothing now and makes a future third-party embed opt in explicitly.

## The headers were never sent at all

`_headers` is a Cloudflare Pages file. gomicrovm.com is still served by
GitHub Pages, which ignores it — the responses carry
`x-github-request-id` and Fastly's `via: 1.1 varnish` behind Cloudflare's
DNS proxy. #2880 moved the deploy to Cloudflare Pages precisely because
GitHub Pages cannot set these headers, but it listed one-time setup a
merged PR cannot perform (create the Pages project, add
`CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID`, repoint DNS), and
`pages.yml` triggers only on `release: published` and manual dispatch. So
the config landed, the lane stayed green, and the site kept serving no
isolation headers.

**That setup is still outstanding.** Nothing here can finish it; the watch
below is what makes it visible until someone does.

## Why the existing test could not catch either half

`public/tests/demo-e2e.mjs` starts a static server that stamped
COOP/COEP on *every* response. Its environment was strictly more permissive
than production, so it passed under a config that isolates nothing, and it
would have passed just as happily against a deployment serving no headers
at all. A harness that invents its own policy tests the harness.

It now parses `_headers` out of the built `dist` and serves exactly the
rules the deployed site declares, via a parser shared with the static gate
(`public/scripts/headers-config.mjs`) so the two cannot drift. It then
asserts `crossOriginIsolated` on the landing page, opens the demo the way a
visitor does, and asserts it on the frame — the direct witness for the
reported failure. Reverted to the old scope, it fails with
`landing page is not cross-origin isolated (crossOriginIsolated=false,
SharedArrayBuffer=false)`.

## Three gates, three different questions

The two halves fail independently, so one gate cannot cover both.

- `pnpm check:headers` (`public/scripts/check-isolation-headers.mjs`, wired
  into `website.yml`) asks **is the config right**. It reads the iframe
  `src` out of `DemoTeaser.tsx` rather than keeping a list, so whatever
  page embeds the demo — and the demo document itself — must both resolve
  to COOP/COEP. It needs no network and runs on every PR touching
  `public/**`.
- `scripts/check-site-isolation-headers.sh`, run from `pages.yml` after the
  deploy, asks **did what we just published come out isolated**. It checks
  the deployment URL, which is all a deploy step can speak for.
- `site-isolation-watch.yml` asks **does the site users load actually send
  the headers**. This is the question the other two structurally cannot
  answer: a correct config, correctly deployed, still reaches nobody while
  DNS points at the old host. It is a cron rather than a trigger on
  anything in the repo because no commit can cause or fix this, and it
  opens/updates/closes one tracking issue in the house style. Run against
  production today it fails, and names the cause:

  ```
  FAIL https://gomicrovm.com/ — Cross-Origin-Opener-Policy: want 'same-origin', got 'nothing'
       ...served by GitHub Pages, which cannot set these headers at all.
  ```

The shell script and the watch both read the domain from
`public/astro.config.mjs` rather than pinning a copy, so a domain move
cannot leave them checking the old one and passing.

## Limits

The wire check reads response headers; it does not run a browser, so it
confirms the precondition for `SharedArrayBuffer` rather than the demo
booting. `demo-e2e.mjs` covers the boot, but only against a local server —
there is no lane that drives a real browser against the deployed site.
