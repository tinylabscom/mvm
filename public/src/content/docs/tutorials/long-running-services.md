---
title: Long-running services
description: Run services with readiness, ports, logs, lifecycle, and policy.
---

Services need more lifecycle structure than one-shot commands.

## Shape

- Build an image with the service and dependencies.
- Declare the service command as the entrypoint.
- Declare ports explicitly.
- Add readiness checks where supported.
- Use `mvmctl machine logs`, `mvmctl wait`, and `mvmctl boot-report` for diagnostics.

```sh
mvmctl machine run --manifest ./mvm.toml --name api-dev --port 8080:8080
mvmctl wait api-dev --for all
mvmctl machine logs api-dev -f
```

## Security notes

- Bind only the ports the caller needs.
- Keep egress policy separate from inbound port exposure.
- Use cold mode only when preserving service state is intentional.
- Make stop/destroy semantics explicit in SDK examples.
