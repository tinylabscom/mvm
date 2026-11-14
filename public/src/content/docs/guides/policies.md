---
title: Policies
description: Compose local mvm policy groups, profiles, and verified pack permissions without overriding denies or ceilings.
---

An mvm policy says what a workload **requests**: outbound destinations,
stored secret bindings, host shares, environment names, and resource limits.
The host resolves those requests into a signed execution plan and checks it
before launch. A policy file or pack does not grant itself authority.

You can keep one small project configuration file and compose reusable policy
files instead of repeating a long list of flags on every run.

## Two different kinds of profile

| Control | What it selects |
| --- | --- |
| `--profile restrictive\|standard\|dev\|permissive` | The run's security tier. It still refuses a requested capability that tier does not support. |
| `--policy NAME\|PATH` | An authored policy profile or group. Repeat the flag to compose several in order. |
| `mvm.toml` `[policy]` | The profile and extra groups this project selects by default. |

For the tier's filesystem and environment rules, see
[Run profiles](/guides/policy-profiles/). `--net` is separate: it requests the
built-in development egress allowlist, **not** a run profile, guest NIC, or
inbound port. Prefer explicit `--allow-host` destinations for a narrow run.

## Compose a project policy

Put a reusable group in `./policy/api-group.toml`:

```toml
description = "Read the GitHub API"

[network]
allow = ["api.github.com:443"]
```

Select it from your project's `mvm.toml`:

```toml
[policy]
profile = "default"
include = ["./policy/api-group.toml"]
```

The project file can include more groups. An `include` entry may also name an
**installed, pinned, verified** pack group, such as `runtime/python`. A
profile can `extends` another profile and include groups of its own. The
same policy documents can be selected explicitly with repeated `--policy`;
in that case the explicit selection **replaces** the project's `[policy]`
table, so list every policy you intend to use.

Inspect the result before running:

```sh
mvmctl policy validate ./policy/api-group.toml
mvmctl policy show
mvmctl why --host api.github.com:443
```

`policy show` and `why` find the project's policy from `mvm.toml` when run
in that directory. These commands inspect policy; they do not boot a VM.

## What composition cannot override

- Allows from groups and profiles can combine, but a deny from any layer
  still wins. A blocked network cannot be reopened later.
- Resource limits are ceilings; the tightest limit wins. A secret's
  destination list can only be narrowed against its stored binding.
- A required group cannot be excluded by a later profile. Pack policy is
  verified when loaded and cannot import local policy files or mount host
  directories on its own.
- Project `[network].allow_hosts` still contributes when an explicit
  `--policy` replaces `[policy]`; it cannot defeat a block or deny.
- A host's `default_policy` is a fallback selection, **not** an
  unoverrideable organization rule.

For the full merge rules, file formats, resolution order, and pack trust
requirements, see [Policy and profiles](/guides/policy-and-profiles/) and
the generated [policy schema](/reference/policy-schema/).
