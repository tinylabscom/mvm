# `llm-agent` — claude-code inside a microVM

This example boots a Firecracker microVM whose only service is
[`claude-code`](https://github.com/anthropics/claude-code), with the
project working directory mounted at `/workspace` and the Anthropic API
key injected as a per-service secret (mode 0400, owned by the agent's
auto-derived uid). It is the showcase used by
[`specs/plans/32-mcp-agent-adoption.md`](../../../../specs/plans/32-mcp-agent-adoption.md)
Proposal B and is the canonical `claude-code-vm` env that the
forthcoming `mvmctl mcp` server (Proposal A) will dispatch into.

## Why a microVM and not bubblewrap

The whole point of this example is the isolation level — full kernel
separation. Bubblewrap-shaped sandboxes (jail.nix, agent-sandbox.nix,
nix-sandbox-mcp's current backend) share the host kernel and trust it.
Running an LLM agent in a microVM means a kernel exploit can't pivot to
the host. mvm's security posture is documented in
[`specs/adrs/002-microvm-security-posture.md`](../../../../specs/adrs/002-microvm-security-posture.md);
the flake here composes with all of W1–W5 from that ADR.

## One-time setup

Drop your Anthropic API key into mvm's secrets directory:

```bash
mkdir -p ~/.config/mvm/secrets
chmod 0700 ~/.config/mvm/secrets
printf '%s\n' 'sk-ant-…' > ~/.config/mvm/secrets/anthropic
chmod 0400 ~/.config/mvm/secrets/anthropic
```

If you skip this, the service start script logs
`[claude-code] no Anthropic API key at /run/mvm-secrets/claude-code/anthropic-api-key`
and exits cleanly — the integration health check reports
"unconfigured" rather than crash-looping. Drop the key in, re-run
`mvmctl up`, and the service comes up on the next boot.

## Build and boot

```bash
mvmctl template create claude-code-vm \
  --flake ./nix/images/examples/llm-agent \
  --profile minimal --role agent \
  --cpus 2 --mem 1024

mvmctl template build claude-code-vm

mvmctl up --template claude-code-vm \
  --network-preset agent \
  --add-dir "$PWD:/workspace:rw" \
  --secret-file "$HOME/.config/mvm/secrets/anthropic:claude-code/anthropic-api-key"
```

`--add-dir host:guest:mode` bind-mounts the working directory into the
VM at `/workspace`. The agent `cd`s there before exec; `git` /
`ripgrep` / `jq` / `curl` / `bash` are all in PATH inside the VM.

`--network-preset agent` (added by [ADR-004 / plan 32 Proposal D](../../../../specs/adrs/004-hypervisor-egress-policy.md))
locks the VM's outbound egress to the LLM-agent allowlist:
`api.anthropic.com:443`, `api.openai.com:443`, `github.com:{443,22}`,
`api.github.com:443`, plus DNS. Anything else gets dropped at the
host's iptables `FORWARD` chain. This is L3-only enforcement; SNI/Host
filtering and DNS-answer pinning (the L7 tiers in ADR-004) are
deferred follow-ups. For now, agents that need extra hosts get an
explicit `--network-allow host:port`.

## Console access for iteration

`mvmctl console claude-code-vm` opens an interactive PTY-over-vsock
session into the VM. `mvmctl exec claude-code-vm <argv>` runs a
one-shot command inside it — both gated to dev-mode builds per
ADR-002 §W4.3.

## Security posture (per ADR-002)

| Surface                            | What this flake does                                                                       |
| ---------------------------------- | ------------------------------------------------------------------------------------------ |
| Per-service uid                    | `claude-code` runs as `1100 + sha256_hex8("claude-code") % 8000`, never uid 0              |
| `setpriv` privilege drop           | `--no-new-privs --bounding-set=-all --inh-caps=-all`                                       |
| Seccomp tier                       | `network` — allows `socket/connect/sendto` for Anthropic HTTPS, blocks `ptrace/keyctl/...` |
| Secrets mode                       | `/run/mvm-secrets/claude-code/anthropic-api-key` is `0400`, owned by the service uid       |
| Verified boot                      | On by default (mkGuest's `verifiedBoot = true`)                                            |
| `do_exec` symbol in prod guest     | Absent (W4.3 CI gate)                                                                      |
| Hypervisor-level egress allowlist  | L3 (iptables): `--network-preset agent` enables it (ADR-004). L7 SNI/Host + DNS pinning deferred. |

## Limitations

- **L3 egress allowlist only.** The recommended `--network-preset
  agent` enforces an iptables-based allowlist (ADR-004). It catches
  raw-IP exfil; it does NOT catch DNS rotation (CDN-fronted domains)
  or SNI/Host header abuse over a permitted destination. The L7
  HTTPS proxy + DNS-answer pinning that close those gaps are
  deferred follow-ups in ADR-004.
- **claude-code is interactive-by-default.** The example service
  launches `claude` with no argv; you'll usually want to `mvmctl exec`
  in or use the upcoming `mvmctl mcp run` (Proposal A) for
  programmatic access.
- **No persistent agent state across boots.** The rootfs is read-only;
  `~/.config/claude` lives on tmpfs. Mount a host directory at
  `/workspace/.claude` (or change `HOME` in `services.claude-code.env`)
  if you want history to survive reboots.

## Where to go from here

- [`specs/plans/32-mcp-agent-adoption.md`](../../../../specs/plans/32-mcp-agent-adoption.md)
  for the broader plan (this flake is Proposal B; the MCP server is
  Proposal A).
- [`specs/plans/33-hosted-mcp-transport.md`](../../../../specs/plans/33-hosted-mcp-transport.md)
  for the cross-repo handoff to mvmd for hosted multi-tenant MCP.
