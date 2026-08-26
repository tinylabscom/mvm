# Cloudflare Pages domain setup for gomicrovm.com

This note records how the public site (`public/`, Astro) is hosted on Cloudflare Pages and how the custom domain `gomicrovm.com` is wired up from the iwantmyname registrar.

## Current state

- The site is deployed by `.github/workflows/pages.yml` to Cloudflare Pages project `mvm`.
- The workflow triggers on:
  - GitHub Release `published`
  - Push of a `v*` tag
  - Manual `workflow_dispatch`
- A manual dispatch can be triggered from the repo with:

```bash
just pages-deploy
# or the older alias
just docs-publish
```

## Required GitHub secrets

The workflow reads two repository secrets:

- `CLOUDFLARE_API_TOKEN` — Cloudflare API token with `Cloudflare Pages:Edit` and `Zone:Read` permissions for the account/zone.
- `CLOUDFLARE_ACCOUNT_ID` — Cloudflare account ID.

Set them with the GitHub CLI:

```bash
gh secret set CLOUDFLARE_API_TOKEN --repo tinylabscom/mvm
gh secret set CLOUDFLARE_ACCOUNT_ID --repo tinylabscom/mvm --body "<account-id>"
```

## Cloudflare Pages project

Project name: `mvm`

Create it through the Cloudflare dashboard (Pages & Workers → Create a project → Upload assets), or with Wrangler once authenticated:

```bash
npx wrangler pages project create mvm --production-branch=main
```

The workflow deploys with:

```bash
wrangler pages deploy public/dist --project-name=mvm --branch=main
```

## Custom domain setup

Cloudflare Pages custom domains work best when Cloudflare is also the authoritative DNS provider for the zone. The registrar (iwantmyname) can keep the registration; only the nameservers need to point at Cloudflare.

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

### 3. Add the custom domain in Pages

1. In Cloudflare dashboard, go to **Pages** → `mvm` project → **Custom domains**.
2. Click **Set up a custom domain**.
3. Enter `gomicrovm.com` and confirm.
4. Cloudflare will automatically add the required CNAME/A/AAAA records to the `gomicrovm.com` zone because it is authoritative.

If you prefer to keep iwantmyname as the authoritative DNS provider (not recommended for Pages), add a CNAME record for `gomicrovm.com` pointing at `mvm.pages.dev`. Note that CNAME at the zone apex is not valid per RFC and may not be supported by iwantmyname; use Cloudflare nameservers for the root domain instead.

### 4. Verify

Once DNS propagates:

```bash
curl -I https://gomicrovm.com
```

Look for:

- HTTP 200
- `report-to` / `nel` headers from Cloudflare
- `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp` on `/demo/weblinux/*` paths (from `public/public/_headers`)

Also verify the demo works in a browser: open `https://gomicrovm.com/demo/weblinux/` and confirm `SharedArrayBuffer` is available (no console error).

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
- Manual: `just pages-deploy` from the repo root.
- Watch the run: `gh run watch $(gh run list --workflow=pages.yml --limit 1 --json databaseId --jq '.[0].databaseId')`

## Troubleshooting

- **Deployment fails with "Could not find the project"**: create the `mvm` Pages project first; the workflow does not auto-create it.
- **Secrets missing**: ensure `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` are set at the repository level, not just environment level.
- **Custom domain shows "Invalid"**: confirm the zone is active on Cloudflare and the nameservers at iwantmyname match exactly.
- **SharedArrayBuffer still missing**: verify `public/public/_headers` is present in the built output and the request path starts with `/demo/weblinux/`.
- **Email not arriving**: verify the destination address is verified in Cloudflare Email Routing, and that the MX records point to Cloudflare (check with `dig gomicrovm.com MX`).
