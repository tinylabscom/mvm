---
title: Network & exposing ports
description: Control egress and expose guest services intentionally.
---

Networking is part of the sandbox contract. Name what the guest can reach, name what ports are exposed, and keep service exposure separate from outbound egress.

## Egress policy

Egress is off unless you ask for it. `--net` opts into the built-in dev preset:

```sh
mvmctl machine run --flake .          # deny-all (the default)
mvmctl machine run --flake . --net    # dev preset
```

Use explicit allow rules for narrow agent workloads. `--allow-host` replaces the
preset with a concrete allow-list:

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

Ingress is declared before boot and is not changed afterwards; there is no
dynamic port-forwarding verb.

Use readiness and logs while developing services (`wait` and `boot-report` are
hidden advanced verbs — they work, but they do not appear in
`mvmctl machine --help`):

```sh
mvmctl machine wait api-dev --for all
mvmctl machine boot-report api-dev
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
