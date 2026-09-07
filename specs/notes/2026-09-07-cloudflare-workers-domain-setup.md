# Cloudflare Workers domain setup for gomicrovm.com

This note records how the public site (`public/`, Astro) is hosted with
Cloudflare Workers Static Assets and how the custom domain `gomicrovm.com` is
wired up from the iwantmyname registrar.

## Current state

- `.github/workflows/workers.yml` deploys the site as the `mvm` Worker.
- The existing `mvm` Pages project remains the rollback target until the Worker
  and production hostname pass the live checks.
- The workflow triggers on:
  - GitHub Release `published`
  - Push of a `v*` tag
  - Manual `workflow_dispatch`
- A manual dispatch can be triggered from the repo with:

```bash
just workers-deploy
# or the generic alias
just docs-publish
```

## Required GitHub secrets

The workflow reads two repository secrets:

- `CLOUDFLARE_API_TOKEN` — account-scoped Cloudflare API token created from the
  **Edit Cloudflare Workers** template. Add zone-scoped **Workers Routes:Edit**
  only when CI, rather than an operator, will attach routes or domains.
- `CLOUDFLARE_ACCOUNT_ID` — Cloudflare account ID.

Set them with the GitHub CLI:

```bash
gh secret set CLOUDFLARE_API_TOKEN --repo tinylabscom/mvm
gh secret set CLOUDFLARE_ACCOUNT_ID --repo tinylabscom/mvm --body "<account-id>"
```

## Cloudflare Worker

Project name: `mvm`

The first authenticated deployment creates the Worker if it does not exist:

```bash
pnpm --dir public deploy
```

The workflow deploys with:

```bash
wrangler deploy
```

The workflow runs `wrangler whoami` before the expensive site build so a missing
or invalid credential fails early. `wrangler deploy` creates or updates `mvm`
from the checked-in configuration; no mutable local Wrangler project state is
used.

## Custom domain setup

Worker custom domains require Cloudflare to be the authoritative DNS provider
for the zone. The registrar (iwantmyname) can keep the registration; only the
nameservers need to point at Cloudflare.

### 1. Add the zone to Cloudflare

In the Cloudflare dashboard:

1. Add site → enter `gomicrovm.com`.
2. Choose the free/pro plan.
3. Cloudflare will provide two nameservers, for example:
   - `bob.ns.cloudflare.com`
   - `lara.ns.cloudflare.com`
     (The exact pair is assigned per-zone; copy the values from the Cloudflare setup page.)

### 2. Update nameservers at iwantmyname

1. Log in to <https://iwantmyname.com>.
2. Go to **Domain Management** → select `gomicrovm.com`.
3. Open the **Nameservers** section.
4. Replace the current nameservers with the two Cloudflare nameservers from step 1.
5. Save. DNS propagation usually takes a few minutes to a few hours.

### 3. Verify the Worker before moving production

1. Deploy `mvm` and open its generated `workers.dev` URL.
2. Run `just docs-check-live-headers https://<deployment-host>`.
3. Open `/demo/weblinux/` and confirm the browser demo boots.
4. Check representative documentation routes and the custom 404 response.

### 4. Move the custom domain

1. Inventory every custom domain on the old `mvm` Pages project; migrate all
   production hostnames rather than assuming the visible primary hostname is
   the only one.
2. In Cloudflare dashboard, open **Workers & Pages** → `mvm` Worker →
   **Settings** → **Domains & Routes**.
3. Add `gomicrovm.com` and each other production hostname as custom domains.
   Remove a hostname from the Pages project if
   Cloudflare reports that it is already assigned.
4. Confirm Cloudflare created the required DNS records and certificates.
5. Do not delete the Pages project yet; its `pages.dev` hostname remains a
   rollback endpoint.

### 5. Verify and retire the old projects

Once DNS propagates:

```bash
curl -I https://gomicrovm.com
```

Look for:

- HTTP 200
- `report-to` / `nel` headers from Cloudflare
- `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp` on `/demo/weblinux/*` paths (from `public/public/_headers`)

Also verify the demo works in a browser: open
`https://gomicrovm.com/demo/weblinux/` and confirm `SharedArrayBuffer` is
available. After the production hostname is stable, delete the old `mvm` Pages
project and the unused `runmvm` Worker only after confirming neither owns a
custom domain, route, binding, secret, or scheduled trigger.

## Email setup

Because Cloudflare is now the authoritative DNS provider for `gomicrovm.com`, all mail-related DNS records are managed in the Cloudflare dashboard.

### Receiving email with Cloudflare Email Routing (free)

Cloudflare Email Routing is a free, receive-only forwarding service. It is the simplest option for addresses like `hello@gomicrovm.com`.

1. In the Cloudflare dashboard, select the `gomicrovm.com` zone → **Email** → **Email Routing**.
2. Click **Get started** and choose **Catch-all address** or individual routes.
3. Add a destination address you already own (e.g., your personal Gmail). Cloudflare will send a verification email; click the link to confirm.
4. Add custom addresses:
   - `hello@gomicrovm.com` → `your-address@gmail.com`
   - `support@gomicrovm.com` → `your-address@gmail.com`
   - Or enable a catch-all so any `@gomicrovm.com` address forwards to your inbox.
5. Cloudflare automatically adds the required DNS records:
   - **MX records** pointing to Cloudflare's inbound mail servers.
   - **SPF TXT record** (`v=spf1 include:_spf.mx.cloudflare.net ~all`) to authorize Cloudflare to receive mail for the domain.

Wait for DNS propagation (usually minutes), then send a test message to `hello@gomicrovm.com` and confirm it arrives in the destination inbox.

**Limitations:** Email Routing only forwards incoming mail. You cannot send mail `From: hello@gomicrovm.com` through Cloudflare.

### Sending email from the domain

To send mail as `@gomicrovm.com`, use a transactional email provider and add their DNS records to Cloudflare. Good options:

- **Resend** (developer-friendly, free tier)
- **Postmark**
- **AWS SES**
- **Mailgun**
- **SendGrid**

Each provider will give you records to add. Typically you need:

- **SPF TXT record** at the root:

  ```
  v=spf1 include:_spf.mx.cloudflare.net include:mailprovider.com ~all
  ```

  Replace `mailprovider.com` with the provider's SPF include (e.g., `include:amazonses.com`, `include:resend.com`). If you are not using Cloudflare Email Routing, omit `include:_spf.mx.cloudflare.net`.

- **DKIM CNAME records** (usually 3) provided by the sending service.

- **DMARC TXT record** at `_dmarc.gomicrovm.com`:
  ```
  v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com; pct=100
  ```
  Start with `p=none` while testing, then move to `p=quarantine` or `p=reject` once mail flows correctly. Provide a real address for aggregate reports, or use a free DMARC reporting service.

### Recommended minimal setup

If you only need to receive email at `gomicrovm.com`:

1. Use Cloudflare Email Routing.
2. Let it manage MX and SPF automatically.

If you also need to send email:

1. Keep Cloudflare Email Routing for inbound mail.
2. Add the sending provider's SPF include to the existing SPF record.
3. Add the provider's DKIM records.
4. Add a DMARC record at `_dmarc.gomicrovm.com`.

## Triggering a deployment

- Automatic: publish a GitHub Release or push a `v*` tag.
- Manual: `just workers-deploy` from the repo root.
- Watch the run: `gh run watch $(gh run list --workflow=workers.yml --limit 1 --json databaseId --jq '.[0].databaseId')`

## Troubleshooting

- **Deployment authentication fails**: replace the repository token with an
  account-scoped token created from **Edit Cloudflare Workers** and verify the
  account ID matches that token.
- **Secrets missing**: ensure `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` are set at the repository level, not just environment level.
- **Custom domain shows "Invalid"**: confirm the zone is active on Cloudflare and the nameservers at iwantmyname match exactly.
- **SharedArrayBuffer still missing**:
  - Check that the deployed response carries the headers:
    ```bash
    curl -I https://gomicrovm.com/demo/weblinux/
    ```
    You should see `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp`.
  - If the headers are missing, the build did not include `public/dist/_headers`. The workflow now fails fast if that file is missing.
  - Make sure you are testing the deployed Worker URL, not a local
    `demo.mvm.local` dev server. Astro dev does not send COOP/COEP headers; use
    the production URL or the local `web/weblinux-demo/serve.py` helper.
- **Email not arriving**:
  - In Cloudflare Email Routing, verify the destination address (e.g., `gomicrovm@ari.io`). An unverified destination causes Cloudflare to silently drop messages.
  - Check the zone overview: the zone status must be **Active** (not **Pending**) for Email Routing to work.
  - Confirm the required DNS records are live:
    ```bash
    dig gomicrovm.com MX
    dig gomicrovm.com TXT
    ```
    You should see MX records pointing to Cloudflare inbound servers and an SPF TXT record including `_spf.mx.cloudflare.net`.
  - Make sure the catch-all rule action is set to **Send to an email** (not **Drop**) and a verified destination is selected.
