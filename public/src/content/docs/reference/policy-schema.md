---
title: Policy schema
description: The JSON Schema of authored policy profiles, groups, and the resolved manifest, generated from the Rust types they are parsed into.
---

The documents described in [Policy and profiles](/guides/policy-and-profiles/)
are TOML (profiles and groups) and JSON (the resolved manifest). This schema is
generated from the Rust types they are parsed into, so it cannot describe a key
the parser refuses. The same text is committed at
`schema/policy-profiles-v0.json`, and a test fails when this page, that file,
or the types drift apart.

The root names three documents:

- `profile`: a file under `config/policy/profiles/`, or one passed with
  `--policy PATH`;
- `group`: a file under `config/policy/groups/`;
- `resolved_manifest`: what `mvmctl policy resolve` writes and
  `mvmctl run --plan` reads.

Every object sets `additionalProperties: false`: an unknown key is an error.

Regenerate it with:

```sh
cargo run -p mvm-client --features schema --bin emit_policy_schema > schema/policy-profiles-v0.json
```

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "PolicyDocuments",
  "description": "One root naming every document kind, so shared definitions are emitted once.",
  "type": "object",
  "required": [
    "group",
    "profile",
    "resolved_manifest"
  ],
  "properties": {
    "group": {
      "$ref": "#/definitions/GroupFile"
    },
    "profile": {
      "$ref": "#/definitions/ProfileFile"
    },
    "resolved_manifest": {
      "$ref": "#/definitions/ResolvedManifest"
    }
  },
  "definitions": {
    "BackendKind": {
      "description": "The typed discriminant of a `VmBackend` implementation.\n\nCallers branch on `BackendKind::Hvf` etc. instead of string-matching `VmBackend::name` — a `match` on this enum is exhaustive, so a removed or added backend is a compile error at every dispatch site instead of a silent gap. Prefer a descriptor capability flag or a `VmBackend` trait method for anything that varies *behaviorally* per backend; reserve `kind() == BackendKind::X` for a genuine single-backend identity check.\n\nLives beside the trait in `mvm-core`, which re-exports this DTO here so `&dyn VmBackend` callers can call `.kind()` without an upward dependency on the higher-level backend registry that knows how to *construct* each variant.",
      "oneOf": [
        {
          "type": "string",
          "enum": [
            "firecracker",
            "libkrun",
            "qemu",
            "mock",
            "hvf"
          ]
        },
        {
          "description": "Host-`wasmtime` tier running a user-supplied WASI module. Claim-free portability/demo backend: opt-in only, never returned by auto-detect, no hardware isolation boundary.",
          "type": "string",
          "enum": [
            "wasm"
          ]
        },
        {
          "description": "Browser-hosted Linux tier running a real Nix-built Linux kernel under QEMU-Wasm. Claim-free portability/development backend: opt-in only, never returned by native auto-detect, no hardware isolation boundary.",
          "type": "string",
          "enum": [
            "web_linux"
          ]
        },
        {
          "description": "Apple Container tier: workloads boot Apple's prebuilt container kernel (a fetched binary artifact) with the same universal initramfs and `ActivateEnvironment` flow as every other runner backend, on the in-house HVF VMM. Opt-in only; never returned by auto-detect.",
          "type": "string",
          "enum": [
            "apple_container"
          ]
        }
      ]
    },
    "EgressRoute": {
      "description": "One route: a destination and the endpoint rules that apply there.",
      "type": "object",
      "required": [
        "host",
        "id"
      ],
      "properties": {
        "host": {
          "description": "An exact host or a `*.suffix` wildcard.",
          "type": "string"
        },
        "id": {
          "description": "Stable id, recorded on every decision this route makes.",
          "type": "string"
        },
        "intercept": {
          "description": "Whether the host endpoint may terminate this destination's TLS to enforce the rules when no secret binding already terminates it. An explicit grant: nothing is intercepted silently.",
          "type": "boolean"
        },
        "otherwise": {
          "description": "What a request no rule matches gets.",
          "default": "deny",
          "allOf": [
            {
              "$ref": "#/definitions/RouteOutcome"
            }
          ]
        },
        "port": {
          "description": "Destination port.",
          "default": 443,
          "type": "integer",
          "format": "uint16",
          "minimum": 0.0
        },
        "rules": {
          "description": "Endpoint rules, tried in order.",
          "type": "array",
          "items": {
            "$ref": "#/definitions/EndpointRule"
          }
        }
      },
      "additionalProperties": false
    },
    "EndpointRule": {
      "description": "One endpoint rule: a method (or any) and a path glob.",
      "type": "object",
      "required": [
        "outcome",
        "path"
      ],
      "properties": {
        "id": {
          "description": "Optional stable id for the audit record; the rule's position is used when absent.",
          "type": [
            "string",
            "null"
          ]
        },
        "method": {
          "description": "HTTP method, upper case. Absent matches any method.",
          "type": [
            "string",
            "null"
          ]
        },
        "outcome": {
          "description": "What a matching request gets.",
          "allOf": [
            {
              "$ref": "#/definitions/RouteOutcome"
            }
          ]
        },
        "path": {
          "description": "Path glob, starting with `/`.",
          "type": "string"
        }
      },
      "additionalProperties": false
    },
    "EnvSection": {
      "description": "`[env]`.",
      "type": "object",
      "properties": {
        "allow": {
          "description": "Exact variable names the workload may be handed. When any layer declares an allow-list, an `--env` outside it is refused.",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "deny": {
          "description": "Exact variable names refused whatever allows them.",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "readmit": {
          "description": "Re-admit variables the built-in hygiene denylist refuses (loader, shell, interpreter, password-manager session variables). An escape hatch: honoured only in a user-authored profile.",
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "additionalProperties": false
    },
    "GroupFile": {
      "description": "A policy group file.",
      "type": "object",
      "properties": {
        "description": {
          "description": "What the group is for.",
          "type": [
            "string",
            "null"
          ]
        },
        "env": {
          "$ref": "#/definitions/EnvSection"
        },
        "network": {
          "$ref": "#/definitions/NetworkSection"
        },
        "required": {
          "description": "Once included, no profile below may exclude it.",
          "type": "boolean"
        },
        "resources": {
          "$ref": "#/definitions/ResourcesSection"
        },
        "secrets": {
          "$ref": "#/definitions/SecretsSection"
        },
        "shares": {
          "$ref": "#/definitions/SharesSection"
        },
        "tools": {
          "$ref": "#/definitions/ToolsSection"
        }
      },
      "additionalProperties": false
    },
    "GroupSelection": {
      "description": "`[groups]` in a profile.",
      "type": "object",
      "properties": {
        "exclude": {
          "description": "Groups a parent included, to drop. A required group cannot be dropped.",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "include": {
          "description": "Groups to add, by name or path.",
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "additionalProperties": false
    },
    "HostArch": {
      "description": "Host architectures a `[[when]]` block can match.",
      "type": "string",
      "enum": [
        "x86_64",
        "aarch64"
      ]
    },
    "HostOs": {
      "description": "Host operating systems a `[[when]]` block can match.",
      "type": "string",
      "enum": [
        "linux",
        "macos"
      ]
    },
    "NetworkSection": {
      "description": "`[network]`.",
      "type": "object",
      "properties": {
        "allow": {
          "description": "Destinations as `HOST[:PORT]`, port defaulting to 443.",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "block": {
          "description": "`true` turns all egress off. Once any layer sets it, no later layer can turn it back on.",
          "type": [
            "boolean",
            "null"
          ]
        },
        "deny": {
          "description": "Destinations refused whatever allows them: `HOST[:PORT]` or `*.suffix`. A deny without a port matches every port.",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "routes": {
          "description": "Endpoint routes (method and path rules at a destination).",
          "type": "array",
          "items": {
            "$ref": "#/definitions/EgressRoute"
          }
        }
      },
      "additionalProperties": false
    },
    "OneOrMany_for_BackendKind": {
      "description": "One name or several.",
      "anyOf": [
        {
          "$ref": "#/definitions/BackendKind"
        },
        {
          "type": "array",
          "items": {
            "$ref": "#/definitions/BackendKind"
          }
        }
      ]
    },
    "OneOrMany_for_HostArch": {
      "description": "One name or several.",
      "anyOf": [
        {
          "$ref": "#/definitions/HostArch"
        },
        {
          "type": "array",
          "items": {
            "$ref": "#/definitions/HostArch"
          }
        }
      ]
    },
    "OneOrMany_for_HostOs": {
      "description": "One name or several.",
      "anyOf": [
        {
          "$ref": "#/definitions/HostOs"
        },
        {
          "type": "array",
          "items": {
            "$ref": "#/definitions/HostOs"
          }
        }
      ]
    },
    "OneOrMany_for_String": {
      "description": "One name or several.",
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      ]
    },
    "PolicyBody": {
      "description": "The policy dimensions a group, a profile's overrides, or a `[[when]]` block may speak to. Every section is optional; an absent one says nothing.",
      "type": "object",
      "properties": {
        "env": {
          "description": "Environment variables the workload may be handed.",
          "allOf": [
            {
              "$ref": "#/definitions/EnvSection"
            }
          ]
        },
        "network": {
          "description": "Outbound network.",
          "allOf": [
            {
              "$ref": "#/definitions/NetworkSection"
            }
          ]
        },
        "resources": {
          "description": "Resource bounds.",
          "allOf": [
            {
              "$ref": "#/definitions/ResourcesSection"
            }
          ]
        },
        "secrets": {
          "description": "Stored secrets the workload may use, and where.",
          "allOf": [
            {
              "$ref": "#/definitions/SecretsSection"
            }
          ]
        },
        "shares": {
          "description": "Host directories copied into the guest.",
          "allOf": [
            {
              "$ref": "#/definitions/SharesSection"
            }
          ]
        },
        "tools": {
          "description": "Per-tool privileges. Recorded, not yet enforced.",
          "allOf": [
            {
              "$ref": "#/definitions/ToolsSection"
            }
          ]
        }
      },
      "additionalProperties": false
    },
    "ProfileFile": {
      "description": "A policy profile file.",
      "type": "object",
      "properties": {
        "description": {
          "description": "What the profile is for.",
          "type": [
            "string",
            "null"
          ]
        },
        "extends": {
          "description": "Profiles this one builds on, by name or path, applied in order.",
          "allOf": [
            {
              "$ref": "#/definitions/OneOrMany_for_String"
            }
          ]
        },
        "groups": {
          "description": "Groups to add and drop.",
          "allOf": [
            {
              "$ref": "#/definitions/GroupSelection"
            }
          ]
        },
        "overrides": {
          "description": "This profile's own policy, applied after its groups.",
          "allOf": [
            {
              "$ref": "#/definitions/PolicyBody"
            }
          ]
        },
        "when": {
          "description": "Platform-conditional groups and overrides.",
          "type": "array",
          "items": {
            "$ref": "#/definitions/WhenBlock"
          }
        }
      },
      "additionalProperties": false
    },
    "ResolvedManifest": {
      "description": "A resolved policy as a document.",
      "type": "object",
      "properties": {
        "policy": {
          "description": "The merged policy, denies already applied.",
          "default": {},
          "allOf": [
            {
              "$ref": "#/definitions/PolicyBody"
            }
          ]
        },
        "resolved_from": {
          "description": "The layers it was resolved from, lowest precedence first. Informational: reading the manifest back ignores it.",
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "additionalProperties": false
    },
    "ResourcesSection": {
      "description": "`[resources]` — bounds. Every value is a ceiling: across layers the smallest wins, so no layer can raise one another set.",
      "type": "object",
      "properties": {
        "cpu_millicores": {
          "description": "Share of host CPU time in thousandths of a core (`--cpu-limit`).",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint32",
          "minimum": 0.0
        },
        "max_cpus": {
          "description": "Most vCPUs a run may ask for (`--cpus`).",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint32",
          "minimum": 0.0
        },
        "max_memory": {
          "description": "Most guest memory a run may ask for, e.g. `2G` (`--memory`).",
          "type": [
            "string",
            "null"
          ]
        },
        "wall_clock_secs": {
          "description": "Wall-clock bound in seconds (`--timeout`).",
          "type": [
            "integer",
            "null"
          ],
          "format": "uint32",
          "minimum": 0.0
        }
      },
      "additionalProperties": false
    },
    "RouteOutcome": {
      "description": "What a route or rule decides.",
      "oneOf": [
        {
          "description": "Forward the request.",
          "type": "string",
          "enum": [
            "allow"
          ]
        },
        {
          "description": "Refuse it.",
          "type": "string",
          "enum": [
            "deny"
          ]
        },
        {
          "description": "Ask an approval backend. Until one is wired, an `ask` is refused.",
          "type": "string",
          "enum": [
            "ask"
          ]
        }
      ]
    },
    "SecretGrant": {
      "description": "One `[[secrets.bind]]` entry.",
      "type": "object",
      "required": [
        "name"
      ],
      "properties": {
        "hosts": {
          "description": "Hosts the credential may be sent to. Empty keeps the stored allow-list whole; a list may only narrow it.",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "name": {
          "description": "The stored secret's name.",
          "type": "string"
        }
      },
      "additionalProperties": false
    },
    "SecretsSection": {
      "description": "`[secrets]`.",
      "type": "object",
      "properties": {
        "bind": {
          "description": "Stored secrets (`mvmctl secret set`) to bind, by name.",
          "type": "array",
          "items": {
            "$ref": "#/definitions/SecretGrant"
          }
        },
        "deny": {
          "description": "Secret names refused whatever binds them.",
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "additionalProperties": false
    },
    "ShareGrant": {
      "description": "One `[[shares.mount]]` entry.",
      "type": "object",
      "required": [
        "guest",
        "host"
      ],
      "properties": {
        "guest": {
          "description": "Absolute guest mount point.",
          "type": "string"
        },
        "host": {
          "description": "Host directory. Relative paths resolve against the file declaring it.",
          "type": "string"
        },
        "writable": {
          "description": "Writable inside the guest (default read-only). Two layers naming the same share resolve to read-only unless both ask for writable.",
          "type": "boolean"
        }
      },
      "additionalProperties": false
    },
    "SharesSection": {
      "description": "`[shares]`.",
      "type": "object",
      "properties": {
        "deny": {
          "description": "Host path prefixes no share may come from.",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "mount": {
          "description": "Host directories to copy into the guest.",
          "type": "array",
          "items": {
            "$ref": "#/definitions/ShareGrant"
          }
        }
      },
      "additionalProperties": false
    },
    "ToolsSection": {
      "description": "`[tools]` — per-tool privileges. Parsed, merged and shown so profiles can be written ahead of enforcement; nothing enforces it yet, and `mvmctl policy validate --strict` refuses a policy that relies on it.",
      "type": "object",
      "properties": {
        "allow": {
          "description": "Tool names allowed.",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "deny": {
          "description": "Tool names refused whatever allows them.",
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      },
      "additionalProperties": false
    },
    "WhenBlock": {
      "description": "A `[[when]]` block: groups and overrides that apply only on matching platforms. Each listed predicate must match (any of its values); an omitted predicate matches everything.",
      "type": "object",
      "properties": {
        "arch": {
          "$ref": "#/definitions/OneOrMany_for_HostArch"
        },
        "backend": {
          "description": "The backend the run boots on: `--hypervisor`, or the host's default.",
          "allOf": [
            {
              "$ref": "#/definitions/OneOrMany_for_BackendKind"
            }
          ]
        },
        "exclude": {
          "description": "Groups to drop when matched.",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "include": {
          "description": "Groups to add when matched.",
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "os": {
          "$ref": "#/definitions/OneOrMany_for_HostOs"
        },
        "overrides": {
          "description": "Policy applied when matched.",
          "allOf": [
            {
              "$ref": "#/definitions/PolicyBody"
            }
          ]
        }
      },
      "additionalProperties": false
    }
  }
}
```
