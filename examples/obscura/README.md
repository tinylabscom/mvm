# Obscura browser guest

This example packages Obscura `v0.2.0` as a sealed, NIC-less CDP workload.
CDP listens only on guest loopback. Browser traffic is sent through mvm's
guest proxy and remains deny-by-default unless each destination is admitted.

Build and run Nix/microVM commands inside the project builder VM:

Signed TCP ingress has to be declared before boot, so `--port` is part of the
launch rather than a later attach. It is rejected together with `--detach`,
which means this run holds the terminal; drive the CDP endpoint from a second
shell.

```sh
mvmctl machine run --name obscura --flake . \
  --allow-host example.com:443 \
  --port 9222:9222
```

```sh
curl http://127.0.0.1:9222/json/version
mvmctl machine stop obscura --yes
```

The SDK convenience provider is also explicit opt-in:

```python
import mvm

browser = mvm.BrowserSandbox(
    "obscura",
    network={
        "mode": "none",
        "egress": {"allowlist": [{"host": "example.com", "port": 443}]},
    },
)
websocket_url = browser.wait_until_ready()
```

Set `MVM_SDK_MODE=live` for that snippet. The provider pins the upstream OCI
index by digest, fixes the explicit proxy and loopback command, and rejects
command overrides. Chromium remains the default browser provider. Obscura is
experimental and does not promise full Playwright/Puppeteer compatibility.

Obscura is distributed under Apache-2.0; consult the upstream project for its
license and notices. The release-archive and OCI pins are recorded in the
repository plan.
