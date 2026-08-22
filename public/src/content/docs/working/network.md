---
title: Network & exposing ports
description: Control egress and expose guest services intentionally.
---

Networking is part of the sandbox contract. Name what the guest can reach, name what ports are exposed, and keep service exposure separate from outbound egress.

## Egress policy

Use a preset when it matches the workload:

```sh
mvmctl machine run --flake .
mvmctl machine run --flake . --net
mvmctl machine run --flake . --net
```

Use explicit allow rules for narrow agent workloads:

```sh
mvmctl machine run --flake . \
  --allow-host api.example.com:443 \
  --allow-host github.com:443
```

For security-sensitive examples, start from no egress and add only required destinations.
For grant review, SDK declarations, and agent-tool policy, see [Network egress policy](/guides/network-egress-policy/).

## Port forwarding

Expose a guest service to the host:

```sh
mvmctl machine run --flake . --name api-dev \
  --port 8080:8080 --port 3000:3000
```

Use readiness and logs while developing services:

```sh
mvmctl wait api-dev --for all
mvmctl boot-report api-dev
mvmctl machine logs api-dev -f
```

## Host control channel

Host control does not require SSH. Guest communication uses the mvm control plane and guest protocol where supported. For debugging, prefer:

```sh
mvmctl machine console api-dev
mvmctl machine logs api-dev
mvmctl machine exec api-dev -- sh -lc 'id && pwd'
```

## Security notes

- Do not expose ports unless the workflow requires it.
- Keep inbound port forwarding and outbound egress policy separate.
- Treat browser automation and agent workflows as high-risk network users.
- Prefer explicit allowlists over broad presets for production-like runs.
