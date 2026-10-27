---
title: CLI Commands
description: Complete command reference for mvmctl.
---

## VM Lifecycle

`mvmctl` is the local microVM substrate CLI: it builds images, boots local
microVMs, talks to guest agents over vsock, manages local artifacts, and exposes
developer/SDK workflows. Fleet and tenant control-plane verbs live in `mvmd`.
`mvmctl deploy` builds and records a local workload artifact and can request
authenticated delivery to `mvmd` with `--mvmd-url`; `mvmctl deployments ls`
lists the local records. `mvmctl` does not expose `tenant` subcommands;
tenant lifecycle and tenant policy authoring/review remain `mvmd`
responsibilities. `mvmctl policy` covers only a workload's own authored
policy, resolved on this host.

**Command grouping (Plan 178).** The surface is organized into a small set
of top-level daily-driver verbs plus noun groups; operations on a single
running VM are flattened into `machine`, contributor build-time verbs under `dev`, observability
under `ops`, install/environment lifecycle under `env`, and provenance &
verification under `trust`. Domains that already own their own subcommands
(`image`, `catalog`, `manifest`, `network`, `cache`, `pool`,
`secret`, `bundle`, `deps`, `artifact`, `capture`) stay top-level.

| Group / top-level          | Commands                                                                                                                                                                |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Daily drivers (top-level)  | `machine` (`run`/`fork`/`restore`/`exec`/`console`/`logs`/`ls`/`stop`/`forward`/…), `build`, `dev`, `doctor`, `init`, `bootstrap`                                       |
| `machine <sub>` (advanced) | `pause`, `resume`, `snapshot`, `save`, `restore`, `checkpoint`, `cp`, `fs`, `proc`, `diff`, `wait`, `boot-report`, `telemetry`, `set-ttl`, `forward`, `sandbox`, `session`, `volume` |
| `dev <sub>`                | `compile`, `validate`, `kernel`, `runtime-overlay`, `sdk-sidecar`, `address`, `image-set`, `guest-bins`                                                                 |
| `ops <sub>`                | `metrics`, `config`, `mcp`                                                                                                                                              |
| `env <sub>`                | `bootstrap`, `cleanup`, `uninstall`, `update`, `sign`                                                                                                                   |
| `trust <sub>`              | `add`/`list`/`remove` (publishers), `instructions`, `attest`, `receipt`, `audit`                                                                                        |
| Other top-level            | `image`, `catalog`, `manifest`, `network`, `cache`, `pool`, `secret`, `bundle`, `deps`, `artifact`, `capture`, `deploy`, `deployments`, `policy`, `backend`             |

**Beginner vs. advanced surfaces.** [`mvmctl machine`](#machine-beginner-ux)
(further down) is the beginner-facing front door — one small command group for
the common "run something in a microVM" cases, and the path the
[machine use-case guide](/guides/machine-use-cases/) leads with. Every
verb in the grouping above is an **advanced / underlying surface**: `machine`
is a thin UX layer over the _same_ signed, audited, OCI-provenance execution
path. The former top-level `up`/`invoke`/`console`/`down` verbs have folded into
`machine` (`machine run`, `machine run --entrypoint`, `machine console`,
`machine stop`); the `vm *` noun-group, contributor-focused `dev *` group, and
the internal `run` SDK transport remain for power users and scripts — reach for them when you need
finer control than `machine` exposes (custom flakes, snapshots, templates, the
guest-RPC surface, fleet-shaped workflows).

| Command                                                                                                                 | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `mvmctl build [SOURCE]`                                                                                                 | Detect a pack spec, manifest project, or Nix flake, build it through its existing pipeline, and write a host-signed local `.mvmpkg`; `SOURCE` defaults to `.` and the archive defaults to `./<source-name>.mvmpkg`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `mvmctl capture`                                                                                                        | Inspect a Linux project and selected commands, resolve the evidence into canonical MVM IR, and render or verify the resulting environment (`project`, `resolve`, and `verify` subcommands)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `mvmctl machine run --flake <ref>`                                                                                      | Build a Nix flake and boot a transient VM                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `mvmctl machine run --manifest <path>`                                                                                  | Boot a pre-built manifest (`mvm.toml`, its directory, or a slot name; short form `-m`). Mutually exclusive with `--flake`/`--image`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `mvmctl machine run <app.mvmpkg> [-- <cmd>...]`                                                                         | The same run with the signed bundle named as the positional source. A path ending in `.mvmpkg` before `--` is always a bundle, never a program: release bundles verify against publisher trust, while a local build must carry the signed local-build label and this host's key. Verification repeats on every run, including dry runs. `mvmctl run <app.mvmpkg>` is the same command. See [Booting a signed bundle](#booting-a-signed-bundle) |
| `mvmctl machine run --manifest <app.mvmpkg> [-- <cmd>...]`                                                              | Verify and boot a signed `.mvmpkg`: release bundles use `~/.mvm/trusted-publishers/`; a directly named local build uses only the matching host key, reports that it is not release-verified, and is refused under `--prod`. The archive is cached under `~/.mvm/bundles/` and re-verified at admission. `bundle install` still refuses local builds. `--dry-run` verifies without caching. See [Booting a signed bundle](#booting-a-signed-bundle) |
| `mvmctl machine run --image <ref>`                                                                                      | Boot an OCI image (pulled/cached). Mutually exclusive with `--flake`/`--manifest`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `mvmctl machine run --prod --image <ref@sha256:...>`                                                                    | Verify and boot a sealed production OCI image, then run its declared Entrypoint/Cmd through the production-safe `RunEntrypoint` path. Do not pass a command after `--`: ad-hoc commands are DevOnly and remain refused. Accepted only for transient `--image` and catalog `--runtime` launches. Persistent runs and `--runtime-pack`, `--deployment`, `--flake`, or `--manifest` are refused before source resolution because those paths cannot preserve or build the sealed production variant                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `mvmctl machine run --no-build`                                                                                         | Fail instead of building when a cache is cold: the run exits naming the artifact it would have built and how to allow it. For CI, perf gates and scripts that must not start a tens-of-minutes build. `MVM_COLD_BUILD=refuse` does the same without the flag. Without either, `machine run` builds what a cold cache lacks (a source checkout's guest runtime, host helpers and initramfs, plus the pair images when an mvm-images checkout is selected) and prints one notice before the first such build; `mvmctl bootstrap` is an optional way to do that ahead of time. Downloads of published artifacts are never refused                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `mvmctl machine run --build`                                                                                            | Build cold artifacts without the first-run notice; overrides `MVM_COLD_BUILD=refuse`. Mutually exclusive with `--no-build`. `MVM_COLD_BUILD=auto` is the environment form                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `mvmctl machine run --name <name>`                                                                                      | Run under a machine identity (auto-generated if omitted)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `mvmctl machine run --entrypoint --stdin <PATH>`                                                                        | Feed the baked entrypoint's stdin from a file, sent as one complete payload with the call                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `mvmctl machine run --entrypoint --stdin -`                                                                             | **Stream** this process's own stdin into the running workload: bytes arrive as they are written and your EOF closes the workload's stdin. Puts the `host.stream.v1` input grant on the signed plan, so a sealed production image whose entrypoint is shell-shaped — or whose entrypoint the host cannot resolve — is refused at admission. Not available with `--attach`, which dispatches into a machine this process did not admit. See [Workload input](/guides/workload-input/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `mvmctl machine run --entrypoint --attach --name <name>` | Run the baked entrypoint on an existing named machine in the foreground. When it ends and the machine has a workspace volume, the changes are offered back through the reviewed apply: on a terminal the diff is shown and `Apply to working tree? [y/N]` is asked on `/dev/tty` (only `y`/`yes` applies); without a terminal, or with `--json`, nothing is applied and the exact `mvmctl machine apply <name>` command is printed. See [Bring agent changes home](/guides/workspace-apply/#apply-when-a-run-ends) |
| `mvmctl machine run --entrypoint --attach --name <name> --apply` | Apply the machine's workspace changes when the run ends without asking, through the same snapshot, journal, protected-path gate and signed audit entries as `machine apply`. Requires `--attach`; cannot be combined with `--json` |
| `mvmctl machine run -d`                                                                                                 | Boot a **persistent** machine detached; return after the machine is running and its guest control channel answers, or fail after the bounded startup wait and cleanup                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `mvmctl machine run --port HOST:GUEST`                                                                                  | Boot a persistent machine and forward the host loopback port to the guest while the command remains attached (repeatable; conflicts with `--detach`; Ctrl-C closes the forwards)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `mvmctl machine run --healthcheck '<cmd>'`                                                                              | Declare the workload a long-running service: presence alone promotes the run to the **persistent** lifecycle (registered, shows in `machine ps`, torn down via `machine stop <name>`). Runs in the foreground unless combined with `-d`. `<cmd>` is exec'd in the guest by the resident host-agent daemon as its liveness check (exit 0 = healthy), actively probed on `--health-interval`; an unhealthy or crashed service is restarted with bounded exponential backoff. A run whose entrypoint exits still tears down on that exit code — a healthcheck on a run-to-completion task is a no-op                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `mvmctl machine run --health-interval <secs> --health-timeout <secs> --health-retries <n> --health-start-period <secs>` | Tune the healthcheck cadence: seconds between checks (default `30`), per-check timeout (default `5`), consecutive failures before unhealthy (default `3`), and grace period after start before checks count (default `0`). Recorded on the machine spec and actively enforced by the host-agent daemon's probe loop                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `mvmctl machine run --cpus N --memory SIZE`                                                                             | vCPU count the guest sees, and memory (supports 512M, 4G, etc.)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `mvmctl machine run --cpu-limit MILLICORES`                                                                             | Cap the workload's share of **host CPU time**, in thousandths of a core (`1500` = 1.5 cores). A different control from `--cpus`, which sets how many vCPUs the guest sees — a workload can hold four vCPUs and be bounded to half a core. Recorded on the signed execution plan and refused when it exceeds the host's `max_cpu_millicores` ceiling                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `mvmctl machine run --grants-file PATH`                                                                                 | Read the workload's grants (CPU, wall clock, egress, drive, display input, application terminal) from a JSON document. Unknown keys are refused, so a typo is an error rather than a silently dropped cap                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `mvmctl machine run --caller-commitment HEX`                                                                            | Bind opaque caller data to the admitted execution and its audit trail. `HEX` must encode exactly 32 bytes as 64 lowercase hexadecimal characters. MVM assigns the bytes no meaning; it includes them in the signed plan identity and copies the typed value into every chain-signed plan audit entry. The same option is available on `mvmctl run`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `mvmctl machine run -e KEY=VALUE`                                                                                       | Inject an environment variable (repeatable; gated by `--profile`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `mvmctl machine run --volume host:/guest[:mode]`                                                                        | Share a host directory (mode defaults to `ro`; `rw` needs `--profile dev`/`permissive`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `mvmctl machine run --profile <p>`                                                                                      | Security posture: `restrictive`, `standard` (default), `dev`, `permissive`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `mvmctl machine run --net`                                                                                              | Enable broad dev-tier outbound egress (default is deny-all)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `mvmctl machine run --allow-host HOST[:PORT]`                                                                           | Allow egress only to these hosts (repeatable; PORT defaults to 443; wins over `--net`). A refused destination prints `egress blocked: …` on stderr while a foreground run is on screen, naming this flag with the exact value when a grant can admit it and nothing when none can (cloud metadata, loopback, the SSH port); the run ends with a summary of every refusal and its count. A run with no network grant at all that exits nonzero ends with one line saying it had no network access                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `mvmctl machine run --hypervisor <backend>`                                                                             | Backend: `firecracker` (Linux/KVM), `hvf` (macOS 26+ default, vsock-only), `libkrun` (bundled macOS 13–25 preview; explicit selection), `qemu` (dev/test)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `mvmctl machine run --flake <ref> --flake-profile <variant>`                                                            | Flake package variant (e.g. worker, gateway)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `mvmctl machine run --host-service <service>`                                                                           | Bind a host service the workload may call over the broker channel (repeatable, e.g. `host.audit.v1`). Baked into the signed execution plan: the broker refuses any service absent from the set. Binding an SDK-served service (`host.audit.v1`, `host.cost.v1`, `host.kv.v1`, `host.time.v1`) also attaches the optional SDK sidecar read-only at `/mvm/sdk`. There is one sidecar per guest libc, and the one attached is chosen from the libc the image recorded when it was materialized — so a musl guest (Alpine, and every `--runtime` in the built-in catalog) gets the musl artifact and a glibc guest the glibc one, whether the image came from `--runtime` or was named directly with `--image`. An image whose libc cannot be established is refused rather than given a guess. On an installed `mvmctl` a cold cache downloads the published sidecar for the running version, arch and libc, hash-verifies it, and boots; the launch is refused if the download fails or the artifact is version-mismatched, tampered, incomplete, or built for the other libc. In a source checkout, a required sidecar is assembled on the host from the same guest-runtime build as the overlay and initramfs; launch does not pair-build it in Stage 0. |
| `mvmctl machine run --peer <NAME:PORT=ADDR:PORT>`                                                                       | Bind a peer route this workload may dial (repeatable, e.g. `db.mvm.peer:5432=127.0.0.1:34567`). The dialed name and the peer's admitted ingress address are both carried on the signed network policy. A binding authorizes one `name:port` route, so the same peer on an unnamed port is refused, and a workload with no bindings admits no peer. A malformed route is refused at the CLI. TCP only; not reachable through the credential-substituting HTTP proxy; not persisted by `machine create`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `mvmctl machine session start <template> --agent-verb <verb>`                                                           | Boot a prod session with an explicit ProdSafe agent-verb allow-list instead of the computed baked-entrypoint/non-dev default. Repeatable; refused with `--dev`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `mvmctl machine build --flake <ref> --watch`                                                                            | Watch the flake and rebuild on change                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `mvmctl machine stop [name...]`                                                                                         | Stop one or more VMs by name, or `--all`. Stopping a machine that is already stopped reports it and exits 0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `mvmctl machine ps`                                                                                                     | List every microVM: persistent machines and running transients (alias: `ls`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `mvmctl machine ps -a`                                                                                                  | Also show transient machines that are no longer running                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `mvmctl machine ps --json`                                                                                              | Output as JSON                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `mvmctl machine run ... --port HOST:GUEST`                                                                              | Declare signed TCP ingress before boot (repeatable)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `mvmctl machine logs <name>`                                                                                            | View the workload's captured stdout/stderr — live while it runs, and still readable after it exits (`-f` to follow, `-n` for how many recorded records to replay first; a record is one captured write, not one line). Workload stdout is written to your stdout and stderr to your stderr, so an ordinary pipeline (`\| grep …`) filters the channel it asked for, and a closed pipe (`\| head -1`) ends the read cleanly rather than erroring. Falls back to the machine's console log when no output capture exists, saying so. Exits nonzero when there is no source at all (for example, if the machine was removed or never booted), suggesting `machine ps`; when state remains but every capture source is missing, it names the retained state and suggests `machine inspect`. Warns on stderr when what it shows is a window rather than the whole run — a truncated capture, a pruned live window, or a hole between the recorded and live halves                                                                                                                                                                                                                                                                                     |
| `mvmctl machine logs <name> --stream <stdout\|stderr\|trace\|all>`                                                      | Show one channel only (default `all`). Refused on a machine whose only source is its console log: that log merges both channels with no labels, so narrowing it has no honest answer. A recorded capture holding nothing on the requested channel is reported as such, not as a missing capture                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `mvmctl machine logs <name> --hypervisor`                                                                               | View the VMM's own diagnostic log (`firecracker.log`) rather than workload output, `-f` to follow it. Firecracker writes one; the other backends do not                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `mvmctl machine display <name>`                                                                                         | Serve view-only frames from a workload admitted with `host.display.view.v1`. Prints a cryptographically random URL whose token authorizes exactly one viewer session. The HTTP listener has no configurable address and binds only to `127.0.0.1`; frames remain guest-to-host and the command adds no input path. Each multipart frame carries its retained-chain digest and optional agent-step sample id.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `mvmctl machine display <name> --input` | Also send pointer, keyboard, text and (with a clipboard grant) paste input from the viewer page. Refused unless the signed plan carries `grants.display_input` (authored in a `--grants-file`), and on a sealed image unless that grant says `"attended": true`. Input goes through a single-writer lease, is recorded in the audit chain as `display.input_event` with event kinds and counts but never keys or text, and reaches the guest only through the agent and a display bridge started with `--input`. With a `human_credential` grant, the page's credential-entry buttons pause frame recording for the entry and refuse checkpoint and fork for the rest of the run. The token authorizes the page, its frame stream and its input endpoint for the life of the session, and is still loopback-only. |
| `mvmctl machine diff <name>`                                                                                            | Show filesystem changes in a running VM (created/modified/deleted since boot)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `mvmctl machine diff <name> --json`
| `mvmctl machine apply <name>` | Review and apply a workspace's guest changes back to the host directory (snapshots first, journaled, undoable); the committed manifest Merkle root is recorded in the host-signed audit chain |
| `mvmctl machine apply <name> --dry-run` | Show what an apply would write without staging anything |
| `mvmctl machine undo <name>` | Reverse the most recent reviewed apply and chain the undo manifest's committed Merkle root |
| `mvmctl machine redo <name>` | Re-apply the most recently undone apply and chain the redo manifest's committed Merkle root |
| `mvmctl machine prompt <name> [PROMPT]` | Send one prompt (or stdin) to the running machine's resident agent — the image's `/etc/mvm/entrypoint` — and print its answer. The plan must grant `agent-prompt`; each prompt is journaled under an agent session (`--session`, default the machine name), recorded encrypted, chain-audited by digest, and captured as a session-bound `vm_full` step checkpoint (`--no-step-checkpoint` skips it). A host with no snapshot key gets one before the first step is captured, as `bootstrap` would mint it |
| `mvmctl machine replay <checkpoint>` | Fork a cursor-bound checkpoint into a fresh VM and re-run its encrypted machine-exec input journal, checkpointing each step |                                                                                     | Output filesystem diff as JSON                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `mvmctl machine wait <name> --for <component>`                                                                          | Block until a guest readiness component is `Ready`, `Disabled`, or `Failed`. Targets: `control-plane`, `entrypoint`, `warm-pool`, `integrations`, `probes`, `all` (default). Exit codes: `0` ready, `65` (`EX_DATAERR`) failed, `75` (`EX_TEMPFAIL`) timeout. Plan 76 Phase 2.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `mvmctl machine wait <name> --timeout <secs> --interval-ms <ms>`                                                        | Tune the deadline and poll cadence. Defaults: 60s / 250ms.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `mvmctl machine boot-report <name>`                                                                                     | Print a single readiness snapshot + per-phase boot timings. Plan 76 Phase 4.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `mvmctl machine boot-report <name> --json`                                                                              | Same payload as JSON.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `mvmctl machine telemetry <name>`                                                                                       | What the host collected from the guest: collector status, host and guest losses by reason, recent records (spans, events, logs, stdio, coverage) and incomplete spans. Read from the host's files; no guest RPC, so a detached machine reads the same way. |
| `mvmctl machine telemetry <name> --follow`                                                                              | Keep printing new records as they arrive. |
| `mvmctl machine telemetry <name> --json`                                                                                | Status, summary and records as one JSON object. |
| `mvmctl machine fork <parent> --as <child>`                                                                             | Snapshot a running machine as a `vm_full` checkpoint and branch it into a fresh child VM with a new identity. The child is admitted through the same path as `machine warm-restore`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `mvmctl machine fork <parent> --branch <slug>`                                                                          | Auto-name the child `<parent>-<slug>-<timestamp>` instead of using `--as`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `mvmctl machine restore <checkpoint> --as <child>`                                                                      | Branch an existing `vm_full` checkpoint into a fresh child VM with a new identity.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `mvmctl machine restore <checkpoint> --branch <slug>`                                                                   | Auto-name the child `<checkpoint>-<slug>-<timestamp>` instead of using `--as`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `mvmctl machine warm-restore <checkpoint> [--name <name>]`                                                              | Low-level synonym for restoring a `vm_full` checkpoint into a fresh child VM. Prefer `machine restore` for new scripts.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |

### GPU device selection

`mvmctl run`, `mvmctl machine run`, `mvmctl machine create`, and the
auto-create forms of `machine start` accept `--gpu` to enable CUDA/NVML API
remoting. Use `--gpu-device ORDINAL` to pin the VM to one host device;
the selector implies `--gpu`. Persisted machines retain the selection, and an
image-backed manifest can express the same choice as `gpu_device = ORDINAL`.
Without a selector, the endpoint exposes the backend's available ordinals.
With a selector, the guest sees one device at ordinal `0`, mapped to the
selected host ordinal. Invalid host ordinals fail closed during endpoint
startup.

## Environment Management

| Command                                           | Description                                                                                                                                                                                                                                                   |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl bootstrap`                                | Host tooling + pre-fetched builder VM image so the first build is fast. Also prewarms what `machine run` checks: host helpers, the source-built guest runtime and overlay, initramfs, and workload kernel. SDK sidecars are assembled only for launches that bind an SDK host service. Idempotent |
| `mvmctl bootstrap --production`                   | Production mode (skip Homebrew, assume Linux with apt)                                                                                                                                                                                                        |
| `mvmctl env bootstrap`                            | Same as `mvmctl bootstrap` (the `env`-grouped form)                                                                                                                                                                                                           |
| `mvmctl doctor`                                   | Run diagnostics + dependency checks + security posture, including per-tenant host-agent daemon state (folded in from the dropped `mvmctl security` verb)                                                                                                      |
| `mvmctl doctor --json`                            | Output diagnostics as JSON                                                                                                                                                                                                                                    |
| `mvmctl env update`                               | Check for and install mvmctl updates. Refuses on an `install.sh` install, which is upgraded by re-running `install.sh`                                                                                                                                        |
| `mvmctl env update --check`                       | Only check for updates, don't install                                                                                                                                                                                                                         |
| `mvmctl env update --force`                       | Force reinstall even if already up to date                                                                                                                                                                                                                    |
| `mvmctl env update --skip-verify`                 | Skip the archive's own signature check; the signed checksum manifest is still verified and still binds the archive                                                                                                                                            |
| `mvmctl env verify-release <ARCHIVE> --tag <TAG>` | Verify a downloaded release archive against its Sigstore bundle (`<ARCHIVE>.bundle`, or `--bundle`) under that release's workflow identity, offline. `install.sh` uses it when an `mvmctl` is already installed                                               |
| `mvmctl backend list`                             | Every backend with this host's support window, install state, and the install-time default, from the component table the release archive carries as `components.tsv`                                                                                     |
| `mvmctl backend add <name>`                       | Fetch this install's own release archive, verify its checksum and signature, and place the backend's component files from it. Refuses a backend outside this host's support window and lists the valid names; idempotent                                  |
| `mvmctl backend remove <name>`                    | Remove the backend's component files from the release directory and its PATH links. Leaves state directories, caches, audit logs and any VM created with the backend. Refuses to remove the install-time default while no other viable backend can take over |
| `mvmctl backend detect [--plain]`                 | Print the backend `install.sh` selects on this host. This is the install-time answer, which accounts for the host OS version (libkrun on macOS 13–25), not the runtime auto-detect ladder; `--plain` prints just the name, and `install.sh` reads that     |

### Offline selected runtime verification

`mvmctl env verify-runtime --config launch.json --version 1.2.3 --arch x86_64 --json`
authenticates a CLI release runtime and checks the selected overlay, verity and
initramfs bytes against the declaration in that same signed archive. This is a
release-only diagnostic: success is not a boot capability, retained file
ownership, or proof that a guest executed the runtime.

`--config` reads runtime-selection fields from launch configuration JSON, not a
separate binding file or a public serialization contract for `VmStartConfig`.
It requires `runtime_release_proof` (with `archive`, `checksum`,
`signature_bundle`, `archive_sha256`, `version` and `arch`),
`runtime_overlay_version`, `runtime_overlay_path`,
`runtime_overlay_verity_path`, `runtime_overlay_roothash` and `initrd_path`.
Unrelated machine settings are ignored. Paths are read as supplied (relative
paths are relative to the command's working directory). Version strings must
match exactly; `v1.2.3` is not normalized to `1.2.3`. `--arch` accepts only
`x86_64` or `aarch64` and need not match the host.

The command rejects `unsigned_runtime_development: true`, a non-null
`source_runtime_archive_sha256`, and any non-null `bundle_boot_assets`,
`legacy_bundle_runtime` or `legacy_portable_runtime`. Missing or partial artifact
selections, invalid signatures, mismatched hashes, roots or incompatible
protocol declarations fail with a nonzero exit status and no JSON success
report. Normal developer Source launch is unchanged.

`--json` is required. On success stdout contains one object with this stable
schema; errors are diagnostics on stderr:

| Field | Type and meaning |
| --- | --- |
| `schema_version` | Integer, `1` |
| `expected_version` | String, exact verified `--version` |
| `expected_arch` | String, verified `x86_64` or `aarch64` |
| `provenance` | String, `cli-release` |
| `archive_sha256` | Lowercase hexadecimal SHA-256 of the authenticated archive |
| `checked_overlay_sha256` | Lowercase hexadecimal SHA-256 checked against actual selected overlay bytes |
| `checked_overlay_verity_sha256` | Lowercase hexadecimal SHA-256 checked against actual selected verity bytes |
| `checked_initramfs_sha256` | Lowercase hexadecimal SHA-256 checked against actual selected initramfs bytes |
| `checked_overlay_roothash` | Authenticated overlay root matched against the selected root |
| `protocol_version` | Integer, authenticated runtime protocol version |
| `min_supported_protocol_version` | Integer, authenticated minimum supported protocol version |

Verification performs no downloads, cache lookup, installation or builds, and
does not fall back to mutable artifact sidecar metadata. Selected artifact bytes
are checked without creating a selected-runtime snapshot; files can change after
the diagnostic returns, so launch must independently verify and own its inputs.

## Building

`mvmctl build` is the workload-archive front door. It detects a JSON pack spec
by its `mvm.pack-spec/v1` schema marker, a directory or file holding
`mvm.toml`/`Mvmfile.toml`, a directory holding `flake.nix`, a Python or
TypeScript SDK source with one statically declared `mvm` app, or an OCI image
reference. A directory matching more than one class is refused; select it
explicitly with `--from pack|manifest|flake|sdk|image`. The result is signed by
this host and marked as a local build. Run that archive directly on the same
host with `mvmctl run ./app.mvmpkg`; the CLI reports `local build, signed by
this host's key; not release-verified`, independently re-verifies that identity
at admission, and records `origin=local-build` plus the bundle SHA-256 in the
signed audit plan. `--prod`, a different host key, a missing origin label, and
tampered bytes are refused. The narrow run path may cache the verified archive
for that boot, but `bundle install` and every registry push, pull, or fetch path
still refuse the local-build origin. Running it does not enroll the host key in
publisher trust.

`mvmctl dev compile app.py --mvm-revision 4e65b221744885e536ec91a3f2948cdc508dcb49`
renders the SDK workload with an immutable mvm flake input for a publishable image source. It
does not create `flake.lock` or run Nix; lock and build the generated flake in
the builder VM before signing a pack. An invalid or abbreviated revision is
refused before any output is written.

| Command                                                             | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl build [SOURCE]`                                             | Build a pack spec, manifest project, Nix flake, SDK-decorated Python/TypeScript source, or OCI image reference into a host-signed local `.mvmpkg`. `SOURCE` defaults to `.`; output defaults to `./<source-name>.mvmpkg` and an existing destination is refused                                                                                                                                                                                                                                                                                                                                                                               |
| `mvmctl build SOURCE --out FILE.mvmpkg`                              | Write the archive at an explicit new path                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `mvmctl build SOURCE --from pack\|manifest\|flake\|sdk\|image`   | Force a source class and skip automatic classification                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `mvmctl build --flake REF [--profile VARIANT]`                      | Build a local or remote Nix flake reference into a local archive                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `mvmctl build app.py --from sdk`                                    | Compile one statically declared SDK app, build its generated flake, and export the result as a local archive                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `mvmctl build ghcr.io/acme/app:v1 --from image`                     | Materialize an OCI image for this host architecture and export it as a local archive; `--arch`, `--production`, and `--debug-out FILE.json` are image-only controls, and production requires a digest-pinned reference                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `mvmctl build PACK.json --health-timeout SECONDS`                   | Build and health-check a locked pack spec before signing; `--lock`, `--hypervisor`, and `--input-observation` are pack-only controls                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `mvmctl build SOURCE --label L --posture P --environment FILE.json` | Record signed archive metadata for any source; `--allow-egress`, `--allow-volumes`, and `--allow-unauthenticated` require `--posture`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `mvmctl machine build <path>`                                       | Build the slot for a manifest directory. A `flake =` manifest builds through Nix in the builder VM; an `image =` manifest materializes the OCI reference through the same path `run --image` boots, then installs it as a slot revision                                                                                                                                                                                                                                                                                                                                                                                                  |
| `mvmctl kernel build`                                               | Build the custom microVM kernels into the local cache. `--which builder|workload|workload-k8s|rootless` (default `builder`) or `--all`; `--source compile|download|auto`. A compile builds from the selected `mvm-images` checkout's `kernel/` flake (`MVM_IMAGES_DIR`, else a sibling `../mvm-images`), otherwise from the in-repo flake. `workload-k8s` is defined only in-repo: it is refused against a configured checkout and built in-repo under a discovered one; `rootless` is defined only in `mvm-images`. Boot a built `workload-k8s` kernel on a dev-tier `machine run` with `MVM_WORKLOAD_KERNEL_VARIANT=workload-k8s`      |
| `mvmctl machine build <path>`                                       | Build from Mvmfile.toml in the given directory                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `mvmctl machine build --flake <ref>`                                | Build from a Nix flake (local or remote)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `mvmctl machine build --flake <ref> --profile <variant>`            | Build a specific flake package variant                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `mvmctl machine build --flake <ref> --watch`                        | Build and rebuild on flake.lock changes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `mvmctl machine build --json`                                       | Output structured JSON events instead of human-readable output                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `mvmctl machine build -o <path>`                                    | Output path for the built .elf image                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `mvmctl dev runtime-overlay build`                                | Prebuild the version-matched read-only runtime overlay into `~/.mvm/cache/runtime-overlay/<version>/<arch>/` without booting a VM. This is the explicit “pay the guest-binary build debt once” command for required-overlay workflows                                                                                                                                                                                                                                                                                                                                                                                                    |
| `mvmctl dev runtime-overlay build --force`                        | Refresh the cached overlay even when the matching cache entry already exists                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `mvmctl dev runtime-overlay build --source build\|download\|auto` | Choose whether the overlay is assembled from the source checkout, downloaded from the published release, or resolved the same way ordinary required-overlay boots do                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `mvmctl dev sdk-sidecar build`                                    | Pack the guest-facing host-services SDK sidecar, one per guest libc, on the host from this checkout's guest-runtime archive (built first if it is not cached) and cache each with its source fingerprint and archive digest. No `mvm-images` checkout or builder VM. Outside a source checkout it packs them from the published guest runtime of this version |
| `mvmctl dev sdk-sidecar build --force`                            | Repack (or re-download) even when the cached sidecar already matches |
| `mvmctl dev image-set <role> [--attr <attr>]`                     | Contributor builds only. Build one Linux-layer role (`builder-vm`, `default-tenant`, `rootless-tenant`; `--attr dev` for the writable default-tenant image) of the `mvm-images` checkout named by `MVM_IMAGES_DIR` against the mvm checkout this binary was compiled from, inside the HVF or Firecracker builder VM, and publish it to the local image cache at `~/.mvm/cache/local-images/` as `local-dev`. A second run with unchanged checkouts reuses the cached set. Run it through `MVM_IMAGES_DIR=../mvm-images bin/dev dev image-set <role>`, which scopes `MVM_HOME` and `CARGO_TARGET_DIR` to the checkout pair |
| `mvmctl dev guest-bins [--out <dir>] [--arch aarch64\|x86_64]...` | Contributor builds only. Assemble the guest-runtime archive `mvm-guest-bins-v<version>.tar.gz` plus a `sha256sum`-format `.sha256` beside it: every guest artifact mvm owns — the static guest executables, the initramfs agent, the host-services and GPU shim shared objects for glibc and musl, for both guest architectures (or the repeated `--arch` subset), and the Python SDK — compiled through cached host-side `cargo zigbuild` builds, with a `manifest.json` recording each member's sha256, the workspace version, the checkout's commit and whether its tree was dirty, and its guest-source and host-services cdylib source fingerprints. The archive is byte-reproducible from the same inputs. See the Guest Binaries section |
| Runtime overlay update model                                        | Stopped VMs pick up the newer version-matched overlay on the next boot. Running VMs keep the overlay they booted with; mvm does not hot-remount a different runtime overlay into a live guest                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `just check::overlay [--force]`                                    | Preferred worktree-local convenience wrapper around `mvmctl dev runtime-overlay build`; sources `scripts/dev-env.sh` first so cache/target state stays isolated per worktree                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `mvmctl env cleanup`                                                | Remove old dev-build artifacts and run Nix garbage collection                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `mvmctl env cleanup --all`                                          | Remove all cached build revisions                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `mvmctl env cleanup --keep <N>`                                     | Keep the N newest build revisions                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `mvmctl env cleanup --verbose`                                      | Print each cached build path that gets removed                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `mvmctl env cleanup --cache`                                        | Remove the regenerable `~/.mvm/cache`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `mvmctl env cleanup --state`                                        | `--cache` plus the regenerable subdirs `dev`, `vms`, `log`, `dev-cluster`, `mock-vms`, `tool-staging`. Preserves identity, templates, and everything not named here                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `mvmctl env cleanup --nuclear`                                      | Remove **every** entry under `~/.mvm`, leaving the (0700) root directory itself in place. Defined by subtraction, so a state directory added by a future subsystem is covered without editing a list. Always requires typing `DELETE-EVERYTHING` at an interactive prompt; `--yes` does not bypass it                                                                                                                                                                                                                                                                                                                                    |
| `mvmctl env cleanup --nuclear --keep-identity`                      | As above, but spares the material a rebuild cannot regenerate: `keys`, `audit`, `attestation`, `secrets`, `secret-bindings`, `egress-ca`, `.secret-store.key`, `snapshot.key`, `config.toml`. Past audit logs stay verifiable. Templates, images, machines, checkpoints and snapshots still go                                                                                                                                                                                                                                                                                                                                           |
| `mvmctl env cleanup --<tier> --dry-run`                             | Print the paths a tier sweep would remove, with sizes, and remove nothing                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `mvmctl env cleanup --<tier> --force`                               | Let the sweep proceed even when a VM appears to be running. Wiping live VM state corrupts the running guest — use only when the PID file is known stale                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

To reclaim disk without losing anything unrecoverable, `--nuclear --keep-identity`
is the command. `mvmctl env uninstall --purge` also removes `~/.mvm`, but it
removes the installed `mvmctl` and its host binaries too.

## Manifests

> **Status:** the `mvmctl init/build/manifest *` surface below is the **plan-38 model**, shipped on `feat/manifest-driven-template-dx-claude`. The user-facing primitive is an `mvm.toml` file alongside your `flake.nix`. See the [Manifests guide](/guides/manifests/) for the conceptual model. The old `mvmctl template <verb>` namespace was removed; clap returns "unrecognized subcommand" for old invocations. `mvmctl manifest push` / `pull` are planned but not yet implemented.

### Scaffolding (top-level)

| Command                               | Description                                                                                                                                                                                                                                                                                                                   |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl init <DIR>`                   | Scaffold `mvm.toml` + `flake.nix` (+ NixOS config) in `DIR` (required)                                                                                                                                                                                                                                                        |
| `mvmctl init <DIR> --preset <preset>` | Preset: `minimal`, `http`, `postgres`, `worker`, `python` (default: `minimal`)                                                                                                                                                                                                                                                |
| `mvmctl init <DIR> --catalog <name>`  | Scaffold from a bundled catalog entry (run `mvmctl catalog list` to browse). Mutually exclusive with `--preset`/`--prompt`                                                                                                                                                                                                    |
| `mvmctl init <DIR> --prompt "<text>"` | Generate scaffold from a natural-language prompt. In `auto` mode (default) probes for a local OpenAI-compatible endpoint on loopback (Ollama @ `:11434`, LocalAI @ `:8080`) before falling through to OpenAI. Override with `MVM_TEMPLATE_PROVIDER=openai\|local\|heuristic`; skip probe with `MVM_TEMPLATE_NO_LOCAL_PROBE=1` |

### Building (top-level)

| Command                                                             | Description                                                                                                                                                                                                                                         |
| ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl machine build [PATH]`                                       | Build the manifest at `PATH` (file or directory; default: cwd walk-up). Persists artifacts to a slot keyed by `sha256(canonical_manifest_path)`. Subsumes today's `mvmctl machine build --flake .` and the legacy `Mvmfile.toml` flow into one verb |
| `mvmctl machine build [PATH] --force`                               | Rebuild even if the cache hits                                                                                                                                                                                                                      |
| `mvmctl machine build [PATH] --update-hash`                         | Recompute the Nix fixed-output derivation hash                                                                                                                                                                                                      |
| `mvmctl machine build [PATH] --vcpus N --mem SIZE --data-disk SIZE` | CLI overrides for resource sizing; persisted to the slot record                                                                                                                                                                                     |
| `mvmctl machine build [PATH] --json`                                | Stream structured build events                                                                                                                                                                                                                      |

### Running (top-level — already manifest-aware)

`mvmctl machine run --manifest PATH -- <cmd>` and `mvmctl run --manifest PATH -- <cmd>` accept a manifest path or its directory and look up the manifest-keyed slot. A positional source before `--` is an OCI image or a signed `.mvmpkg`, never a manifest; a manifest path there is refused with a pointer to `--manifest`. If no current revision exists, they error with a hint to run `mvmctl machine build`. See the [VM Lifecycle](#vm-lifecycle) and [One-shot Exec](#one-shot-run-transient-runner) sections for full flag lists. (Plan 40 dropped the `start` and `run` aliases on `up`.)

### Inspection / registry (`mvmctl manifest *`)

`ls`, `info`, and `verify` share their operations with the
`mvm_client::manifest` library facade. The host library exposes the same
operations as `manifest.list`, `manifest.info`, and `manifest.verify` (ABI
1.7), with generated request/reply types and method constants for the Python
and TypeScript SDK bindings. These inspect the local registry without booting
a machine. Listing supports repeated `--tag` filters: a slot must have every
requested tag. `info` keeps snapshot lookup best-effort; a missing snapshot
does not make the persisted manifest unavailable. `verify` checks artifact
checksums, not publisher trust: `--check-signature` remains explicitly refused.
Persisted names and revision metadata are validated before resolving paths:
invalid template names contribute no tags, and invalid snapshot references
produce no snapshot. Verification refuses artifact paths that escape the
selected revision rather than checking unrelated host files.

The SDK adapters call these host-library operations in-process:
`mvm.manifest.list()`, `mvm.manifest.info(path)`, and
`mvm.manifest.verify(path)` in Python; `manifest.list()`,
`manifest.info(path)`, and `manifest.verify(path)` from `@runmvm/mvm` in
TypeScript. Listing takes `orphans` and `tags` options in both languages.
An omitted inspection or verification path uses the same cwd discovery as
the CLI. Verification takes `revision` and `check_signature` keyword arguments
in Python, or `revision` and `checkSignature` in the TypeScript options object.
The signature option is forwarded to the shared refusal, never ignored.

| Command                                             | Description                                                                           |
| --------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `mvmctl manifest ls [--json]`                       | List built slots — manifest path, last-built timestamp, optional `name`               |
| `mvmctl manifest ls --orphans`                      | Slots whose source manifest file is missing on disk                                   |
| `mvmctl manifest info [PATH] [--json]`              | Print manifest, slot path, current revision, snapshot info, provenance                |
| `mvmctl manifest rm [PATH] [--force]`               | Remove the slot from the registry                                                     |
| `mvmctl manifest rm [PATH] --manifest-file`         | Also delete the source `mvm.toml` (off by default)                                    |
| `mvmctl manifest verify [PATH] [--revision <hash>]` | Verify checksums for a built slot                                                     |
| `mvmctl manifest verify --check-signature`          | Reserved for plan 36 (sealed-signed-builder-image); errors today with "not yet wired" |
| `mvmctl manifest prune --orphans`                   | Remove builds whose source manifest is gone                                           |
| `mvmctl manifest prune --orphans --dry-run`         | Preview what would be removed                                                         |
| `mvmctl manifest push` / `mvmctl manifest pull`     | **Planned, not yet implemented.**                                                     |

## Configuration

| Command                               | Description                                                          |
| ------------------------------------- | -------------------------------------------------------------------- |
| `mvmctl ops config show`              | Print current config as TOML                                         |
| `mvmctl ops config edit`              | Open the config file in $EDITOR (falls back to nano)                 |
| `mvmctl ops config set <key> <value>` | Set a single config key (e.g. `mvmctl ops config set dev_vm_cpus 4`) |

## Audit

| Command                                                                                                  | Description                                                                                                                                                                                                                                                                                                                                                             |
| -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl trust audit tail`                                                                                | Show the last 20 audit events from /var/log/mvm/audit.jsonl                                                                                                                                                                                                                                                                                                             |
| `mvmctl trust audit tail -n <N>`                                                                         | Show the last N audit events                                                                                                                                                                                                                                                                                                                                            |
| `mvmctl trust audit tail -f`                                                                             | Follow audit log output (poll until Ctrl-C)                                                                                                                                                                                                                                                                                                                             |
| `mvmctl trust audit verify [--tenant <t>]`                                                               | Verify every segment of the chain-signed audit log from genesis; nonzero exit on any signature or chain-link failure                                                                                                                                                                                                                                                    |
| `mvmctl trust audit verify <session> [--tenant <t>] [--json]`                                            | Verify one session: the whole chain, then each `session.sealed` record against it. Prints `VERIFIED`, `MISMATCH` with the reason (chain break, signature, count, sequence, session root, checkpoint root, environment identity, head, ledger), `UNSEALED`, or `NOT_FOUND`; exit 0, 1, 2, or 3                                                                                  |
| `mvmctl trust audit sessions [--tenant <t>] [--since <t>] [--until <t>] [--json]`                        | List sessions (admitted runs) with their entry counts and seals, and check the hash-chained session ledger. Times are RFC 3339, `YYYY-MM-DD`, or a duration back from now (`7d`)                                                                                                                                                                                        |
| `mvmctl trust audit show <session> [--tenant <t>] [--kind <glob>] [--since <t>] [--until <t>] [--json]`  | Show a session's entries across every segment. `<session>` is a plan id or at least 8 leading hex characters of it; `--kind` is a glob over the event name                                                                                                                                                                                                              |
| `mvmctl trust audit usage [--tenant <t>] [--vm <name>] [--json]`                                         | Aggregate the chain-signed `host.ai.usage` entries: one row per destination (provider, host, path, model) with request counts and summed provider-reported token counts, a totals row, and the budget-exceeded count. Token columns show `-` (null in JSON) when no entry for the destination reported that count; `--vm` filters to one VM's entries. Prints `no AI egress usage recorded` when the chain carries no usage entries       |
| `mvmctl trust audit publish-root [--tenant <t>]`                                                         | Build, sign, and publish a Merkle transparency-log root over the tenant's chain-signed audit log to `~/.mvm/audit/<tenant>.root.json`. Only builds over a chain that verifies clean                                                                                                                                                                                     |
| `mvmctl trust audit prove <selector> [--tenant <t>] [--json]`                                            | Emit an inclusion proof that one audit line is in the log, paired with the current signed root. `<selector>` is a numeric line index, a `plan_id`, or `sha256:<hex>` of the exact line; an ambiguous selector is refused                                                                                                                                                |
| `mvmctl trust audit verify-inclusion --proof <file\|-> [--root <file>] [--pubkey <file>] [--tenant <t>]` | Verify an inclusion proof against a host-signed root: verifies the signed root under the trusted host key, checks its tenant, verifies the proof, and binds root_hash + tree_size. Nonzero exit naming the failed check                                                                                                                                                 |
| `mvmctl trust audit provenance export [--tenant <t>] [--local] [-o <path>]`                              | Export the chain-signed audit log as W3C PROV-O/Turtle for compliance reporting                                                                                                                                                                                                                                                                                         |
| `mvmctl trust audit decisions export [--tenant <t>] [--format json\|tibet] [-o <path>]`                  | Export cached decision records for a tenant; default format is JSON                                                                                                                                                                                                                                                                                                     |
| `mvmctl trust audit decisions list [--tenant <t>] [--json]`                                              | List cached decision records for a tenant                                                                                                                                                                                                                                                                                                                               |
| `mvmctl trust audit decisions show <decision-id> [--tenant <t>] [--json]`                                | Show a single decision record by its content address                                                                                                                                                                                                                                                                                                                    |
| `mvmctl trust audit decisions trace <decision-id> [--tenant <t>] [--json]`                               | Trace the causal chain that led to a decision                                                                                                                                                                                                                                                                                                                           |
| `mvmctl trust audit decisions impact <decision-id> [--tenant <t>] [--json]`                              | Show decisions that depend on or were caused by a decision                                                                                                                                                                                                                                                                                                              |
| `mvmctl trust audit decisions similar <decision-id> [--tenant <t>] [--json]`                             | Find cached decisions similar to the given decision                                                                                                                                                                                                                                                                                                                     |
| `mvmctl trust audit receipts export [--tenant <t>] [--plan-id <id>] [--json]`                            | Derive signed `ExecutionReceipt`s from the chain-signed audit log. Entries with no receipt mapping (egress decisions, stream attach/input grants, sealed-transcript anchors) are reported as citations rather than dropped                                                                                                                                              |
| `mvmctl trust audit receipts export --archive <path> [--tenant <t>] [--plan-id <id>] [--full-chain]`     | Write a signed `.mvmev` evidence archive: the receipts, one RFC 6962 inclusion proof per leaf against the host-signed audit root, the raw chain lines, and a citation for every in-scope entry with no receipt mapping. `--full-chain` covers the whole tenant so a verifier can derive coverage; without it, scope completeness is host-attested and cannot be checked |
| `mvmctl trust audit receipts verify <archive> [--json]`                                                  | Verify a [`.mvmev` evidence archive](/reference/mvmev-format/) offline. Reports integrity, inclusion, and scope completeness separately; exit code is a bitmask (1 integrity, 2 inclusion, 4 completeness). Completeness reports `attested` rather than a pass when the archive is plan-scoped                                                                          |

### Protected forensic transcripts

| Command | Description |
| --- | --- |
| `mvmctl trust audit transcript arm <vm> [--tenant <t>]` | Create a new encrypted capture with seven-day payload retention after terminal sealing. Duration is at most 3600 seconds; byte/chunk limits remain independent. |
| `mvmctl trust audit transcript disarm <capture-id> [--tenant <t>]` | Acquire the capture lease, finalize an inactive generation, and anchor its immutable root in the host audit chain. Refuses while a protected producer owns the lease. |
| `mvmctl trust audit transcript reconcile <capture-id> [--tenant <t>]` | Reconcile one known capture: authenticate its original seal and concrete VM identity without requiring the current VM plan, durably sign expiry evidence with the original attribution, then remove only its authorized ciphertext segments. Safe to retry after interruption. |
| `mvmctl trust audit transcript export <capture-id> [--tenant <t>] [--out <path>]` | Verify and decrypt a readable capture. Expired or authentically retired payload is refused even if physical cleanup is delayed. |
| `mvmctl trust audit transcript list [--tenant <t>] [--json]` | List captures without enrolling existing data in retention. |

Existing v6 captures remain readable and retention-ineligible; formats v1–v5
are not supported. Reconciliation retains the original manifest, wrapped key,
root, and signed audit proof. It never cleans export destinations or recursively
sweeps arbitrary paths. Symlinks, hard-linked payloads, invalid clocks, missing
authority, and conflicting evidence refuse cleanup. Unaccounted missing payload
remains corruption, not successful expiry.

An expired export is a read refusal, not a cleanup operation: it leaves the
stored ciphertext and manifest unchanged. Use authenticated reconciliation for
payload removal; an export failure is not evidence that deletion completed.
Neither expiry nor reconciliation erases plaintext exports already held by an
authorized recipient.

Unattended producer startup/tick maintenance and hourly generation rotation need
the protected capture lifecycle owner; the explicit command alone does not
enable them. Workload-output generations may additionally opt into a separately
authenticated aggregate family budget; unrelated forensic captures are not
pooled into that budget. Removing names is not secure erasure of backups or open
descriptors. The directory lease coordinates trusted host processes, not hostile
same-user processes that ignore locks.

## Instruction-file provenance

Sign and verify agent instruction files (`CLAUDE.md`, `AGENTS.md`, `SKILL.md`,
`.claude/**/*.md`, …) and manage the policy every boot verifies them against.
Status: Preview. See [Provenance for instruction files](/guides/instruction-provenance/)
for the policy format, merge rules, audit entries, and limits.

| Command | Description |
| --- | --- |
| `mvmctl trust instructions init [--enforcement deny\|warn\|audit] [--force]` | Write the user policy at `$MVM_HOME/config/instruction-trust.toml`, trusting this host's signing key. Refuses to overwrite without `--force` |
| `mvmctl trust instructions init --project <DIR> [--enforcement <mode>]` | Write a project policy at `<DIR>/.mvm/instruction-trust.toml`. It can only tighten the user policy; alone it is advisory |
| `mvmctl trust instructions sign <PATH>... [--key <FILE>] [--policy <FILE>]` | Write `<file>.mvmsig.json` beside each named file, and beside each instruction file under a named directory. Signs with the host key unless `--key` names a raw 32-byte Ed25519 secret key |
| `mvmctl trust instructions sign --dry-run <PATH>...` | Print the files that would be signed, one per line, and sign nothing |
| `mvmctl trust instructions verify [PATH] [--policy <FILE>] [--json]` | Verify the instruction files under `PATH` (default `.`) the way admission does. Exits nonzero when the effective policy is `deny` and any file fails |
| `mvmctl trust instructions policy [--project <DIR>] [--policy <FILE>] [--json]` | Print the effective policy after merging the user and project policies |

`--policy <FILE>` reads that file as the user policy instead of the configured
one. Keyless (`<file>.sigstore.json`) signatures are produced in CI by
`cosign sign-blob --new-bundle-format`; see `.github/workflows/sign-instructions.yml`.

## Local Secrets

| Command                                                   | Description                                                                                                                       |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl secret put <name>`                                | Store or replace a local secret using hidden interactive input when stdin is a terminal, or piped stdin otherwise                 |
| `mvmctl secret put <name> --value -`                      | Store or replace a local secret from stdin                                                                                        |
| `mvmctl secret put <name> --value-file <path>`            | Store or replace a local secret from a file                                                                                       |
| `mvmctl secret put <name> --from <ref>`                   | Store a secret read on the host from `env://VAR`, `file:///path`, `keychain://service/account`, `op://vault/item/field` or `bw://item/field`. `set` takes `--from` too|
| `mvmctl secret put <name> --value <value>`                | Store or replace a local secret from an inline value. Avoid in interactive shells because the value may be saved in shell history |
| `mvmctl secret set <name> --provider <provider>`          | Store a secret and bind it to a catalogued provider's destinations and auth type                                                  |
| `mvmctl secret set <name> --host <host> --type <auth>`    | Store a secret and bind it to explicit destinations. Repeat `--host`; `*.` subdomain wildcards supported                          |
| `mvmctl secret set <name> ... --inject <mode>`            | Restrict substitution to `header` (default), `query_param`, `url_path`, or `basic_auth`                                            |
| `mvmctl secret set <name> ... --oauth-authorization-url <url> --oauth-token-url <url> --oauth-client-id <id>` | Bind the secret to an OAuth flow (bearer only); the three flags are required together                                             |
| `mvmctl secret set <name> ... --oauth-client-secret <secret>` | Store the client secret as the initial token set; the host-side refresher exchanges it for a live token set (`-` reads stdin; `--oauth-client-secret-file <path>` reads a file) |
| `mvmctl secret set <name> ... --oauth-login`               | Define the secret, then consent to its OAuth flow in a browser on this host, as `secret login` does                                 |
| `mvmctl secret login <name>`                              | Consent to an OAuth-bound secret's flow in a browser on this host and store the token set it yields                               |
| `mvmctl secret login <name> --no-browser --timeout <secs>` | Print the authorization URL instead of opening a browser; wait up to `<secs>` (default 300) for the consent                        |
| `mvmctl secret providers`                                 | List the built-in service providers `--provider` accepts                                                                          |
| `mvmctl secret providers --search <query>`                | Filter providers by name, description, or tag                                                                                     |
| `mvmctl secret get <name>`                                | Verify that a local secret exists without printing the value                                                                      |
| `mvmctl secret ls`                                        | List stored secret names, and for bound secrets their auth type, destinations, and authoring provider                             |
| `mvmctl secret rm <name>`                                 | Remove a local secret                                                                                                             |
| `mvmctl secret <put\|get\|set\|login\|ls\|rm> --tenant <tenant>` | Use a non-default local tenant namespace. Default: `local`                                                                  |

`secret set` is `put` plus an egress binding: it records where the substituted
credential may go and how it authenticates. `--provider` takes those from the
built-in catalog so the destination is not hand-typed, which matters because a
mistyped host does not fail loudly — it withholds the credential, surfacing as an
unrelated upstream auth error. `--provider` and `--host`/`--type` are mutually
exclusive, and an unrecognised provider name is refused rather than falling back
to a default.

`--inject` is part of the durable binding. `header` works with every auth type;
`query_param` and `url_path` work with bearer and basic credentials; and
`basic_auth` requires `--type basic`. The host refuses a placeholder found in
any position other than the one the binding declares. URL values are
percent-encoded and Basic credentials are decoded, substituted, and re-encoded
without exposing the raw secret to the guest.

The catalog is expanded once, when `secret set` runs, and the resulting literal
hosts are what get stored and enforced; it is never consulted again for that
binding. A later change to a catalog entry therefore cannot widen a binding that
already exists. For a SigV4 provider the credential-scope service comes from the
entry, while `--region` and `--aws-access-key-id` stay yours to supply — they
belong to your account, not to the provider.

An OAuth binding turns the stored value into a token set the host maintains,
and the per-VM network endpoint refreshes it against the binding's
`--oauth-token-url` before it expires, so the guest only ever receives a live
access token through substitution. The set records which grant renews it.

For a machine client, `--oauth-client-secret` writes the stored value as the
*initial* token set — the client secret plus an already-expired timestamp — and
the endpoint exchanges the client-credentials grant at boot and again before
each expiry.

For an API a person signs in to, the consent happens in a browser on the host.
`secret login <name>` (or `--oauth-login` on `secret set`) runs the
authorization-code grant with PKCE (S256): it listens on `127.0.0.1` on a port
the kernel picks, prints the authorization URL and opens it in the desktop
browser, and accepts the redirect to `http://127.0.0.1:<port>/callback` only if
its `state` matches the one this login sent. A callback with a missing or
different `state` is answered with an error and ignored, and the login keeps
waiting, so another process on the host cannot cancel it. The code is redeemed at the token endpoint with the
PKCE verifier, and the resulting token set replaces the stored value. Register
`http://127.0.0.1/callback` as the client's redirect URI. Without
`--oauth-client-secret` the client is public and identifies itself with its
client id; with it the client is confidential, and the secret authenticates
the code exchange and every refresh. The endpoint renews a consented set with
the refresh-token grant, and stores a rotated refresh token when the provider
issues one; it never falls back to the client-credentials grant, which would
replace the user's identity with the application's. A provider that issues no
refresh token gives a set that lasts until its access token expires; run
`secret login` again then. Until a consent completes, `secret set
--oauth-login` leaves the secret defined with no tokens, and resolution fails
closed. A login records an `oauth_login` entry in the secret audit log, with
its outcome and no value.

Live token sets are written by these host flows and can never be imported with
`--from`. `--oauth-scope` is repeatable, and
`--oauth-response-access-token-pointer` names a non-standard access-token
location in the token response (default `/access_token`). The OAuth endpoints
must be absolute `https` URLs, and the workload's network policy must admit
the token endpoint's host: the refresher sends the client secret only where
that policy allows, and records every attempt as a `secret.oauth_refresh`
audit entry. Neither the refresh token nor the client secret goes anywhere
else. The token response must carry an expiry (`expires_in` or `expires_at`)
far enough out to refresh ahead of; a token without one is refused rather than
stored.
`mvmctl secret ls` shows the oauth client id and token URL alongside the
binding; the client secret is never displayed.

`secret providers` also names the environment variable each provider's own
tooling reads (`env=ANTHROPIC_API_KEY`) and the header its API reads the
credential from (`header=x-api-key: <credential>`), which is where the guest's
client must put the placeholder. `run --secret <name>` and
`machine run --secret <name>` hand the guest its placeholder under that
variable; a secret bound with `--host` uses its own name, uppercased. See
[Agent sandbox](/guides/agent-sandbox/) for the substitution path.

Secret values are write-only through the CLI after storage: `get` is a presence
check and never emits the raw value. Replace a secret by running `secret put`
again with the same name. Local secret storage is encrypted at rest: the OS
keyring backend stores values in the platform keystore, and the file fallback
stores AES-256-GCM encrypted records with mode-0600 files and a mode-0600 local
store key. Auto backend mode keeps file-backed secrets visible when the OS
keyring is reachable, so a backend probe change cannot hide an existing secret.
Legacy plaintext file records are refused; replace them with `secret put`.
Secret audit entries in `~/.mvm/audit/secrets.jsonl` record the operation
metadata plus `secret_visibility: "write_only"` and
`storage_security: "encrypted_at_rest"`; secret values are never logged.

## Authored Policy

Composable groups and profiles for what a workload may do. See
[Policy and profiles](/guides/policy-and-profiles/) for the file format, merge
rules and discovery order, and the [policy schema](/reference/policy-schema/).

| Command | Description |
| --- | --- |
| `mvmctl policy show [PROFILE...] [--format toml\|json\|plan] [--project DIR] [--backend KIND]` | Print the merged policy: TOML with its layers, JSON with per-item provenance, or the grants, egress rules, routes and bindings the signed plan would carry. Without `PROFILE`, reads the project's `mvm.toml` `[policy]` table |
| `mvmctl policy resolve [PROFILE...] [-o FILE] [--project DIR] [--backend KIND]` | Write the resolved manifest `run --plan` accepts |
| `mvmctl policy validate [PROFILE\|PATH...] [--strict]` | Check a profile, or one profile or group file. `--strict` refuses every warning and every secret the store would not bind |
| `mvmctl policy diff A B [--json] [--backend KIND]` | What each profile allows or denies that the other does not |
| `mvmctl policy groups [--json]` | List built-in and user groups and profiles |
| `mvmctl why --host H[:P] [--method METHOD --request-path PATH] \| --path P \| --tool T \| --secret S [--profile NAME\|PATH... \| --plan FILE] [--project DIR] [--json]` | Resolve policy without booting and explain one allow/deny answer. Defaults to the current project's `mvm.toml`; `--profile` selects an authored profile and `--plan` reads `policy resolve` output. A routed host needs method and path for a request-level decision; a tool marked `ask` needs runtime approval and is not pre-authorized |
| `mvmctl run --policy NAME\|PATH\|ns/name[@version]... -- <cmd>` | Run under authored profiles or groups (repeatable; TOML or JSON documents). Each entry names a profile or a group — a group composes as one layer — and later entries take precedence over earlier ones — a later deny beats an earlier allow; allows union. Also on `machine run`, `machine create` and `machine start`. Replaces the project's `[policy]` table; the project's `[network] allow_hosts` still applies, and applies on every verb even with no policy. Flags add to its allows and cannot reach its denies, blocks or ceilings. Pack references require an installed, pinned, publisher-verified signed pack; pack-authored references cannot import local policy files |
| `mvmctl run --plan FILE -- <cmd>` | Run under a resolved manifest. Mutually exclusive with `--policy`, `--net`, `--network-preset`, `--allow-host`, `--allow-endpoint`, `--peer`, `--cpu-limit`, `--grants-file`, `--mount`, `--allow-env` and `--secret`. The file is re-validated, and a plan or signature in it is refused: admission signs the plan itself |

For `run` and `machine run`, a root `--policy` pack that declares a signed
image supplies the boot source when no explicit image, manifest, flake,
deployment, or runtime was selected. The pack's exact version and manifest
digest are recorded in the signed plan and reverified by host admission.
Explicit boot sources retain precedence; the pack still supplies policy.
`machine run --entrypoint` refuses an image-bearing pack because that separate
boot path does not bind the pack identity.

## Policy Contracts

`mvmctl machine run` still synthesizes and admits signed execution plans with policy
references. The default local ref is `local-default`; tenant-scoped policy
bundle authoring, diffing, rollout, and review are exposed by `mvmd`. An
authored workload policy (above) is lowered into the same flags a launch
carries before synthesis, so it reaches the plan the same way.

When admission resolves a workload policy bundle, `[audit].chain_signing = true`
is required. The default local chain remains active, and `file://...` entries in
`[audit].stream_destinations` receive exact JSONL replica chains. Other
destination schemes validate at the policy-shape layer but fail closed during
admission until their transports are wired.

## Flake Validation

| Command                               | Description                                              |
| ------------------------------------- | -------------------------------------------------------- |
| `mvmctl dev validate`               | Validate a Nix flake before building (current directory) |
| `mvmctl dev validate --flake <ref>` | Validate a specific flake path or reference              |
| `mvmctl dev validate --json`        | Output structured JSON instead of human-readable output  |

`mvmctl dev validate` is the contributor-facing replacement for the former
`flake check` and `build validate` command paths.

## Runtime Overlay

| Command                                                                        | Description                                                                                                                                                                |
| ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl dev runtime-overlay build`                                           | Populate the local runtime-overlay cache at `~/.mvm/cache/runtime-overlay/<version>/<arch>/` for this `mvmctl` version and host architecture without booting a workload VM: assembled from this checkout's guest runtime, or outside a checkout from the published guest runtime of this version. The image set carries no overlay, so there is no `--source download` |
| `mvmctl dev runtime-overlay build --source build`                            | Assemble the overlay on the host from this checkout's guest-runtime archive. A selected `MVM_IMAGES_DIR` checkout does not change this                                                        |
| `mvmctl dev runtime-overlay build --arch aarch64\|x86_64 --version <semver>` | Override the target architecture or the expected overlay version                                                                                                           |
| Runtime overlay update model                                                   | Running VMs keep the overlay they booted with; a changed overlay takes effect on the next boot of a stopped VM                                                             |
| `just check::overlay`                                                         | Prebuild the overlay through the worktree-local dev environment so later required-overlay boots avoid rebuilding guest binaries on the hot path                            |

## SDK Sidecar

| Command                                  | Description                                                                                                                                                                               |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl dev sdk-sidecar build`         | Pack the current checkout's host-services sidecars — one per guest libc — on the host from its guest-runtime archive and install each into the version/architecture/libc cache with source provenance and the archive digest. `--source auto` (the default) packs in a source checkout and otherwise from the published guest runtime of this version; the image set carries no sidecar, so there is no `--source download` |
| `mvmctl dev sdk-sidecar build --force` | Repack even when the installed sidecar already matches |

## Guest Binaries

The `mvm-guest-bins` archive is mvm's guest runtime as one versioned unit: every guest artifact mvm owns, built from this repository. In a source checkout, `mvmctl machine run` builds it once and assembles the runtime overlay, initramfs, and required SDK sidecar on the host from its verified contents. Each CLI release publishes the archive as a signed asset, version-locked to the CLI and listed in the release's signed checksum manifest. `install.sh` and the deb and rpm packages install it beside `mvmctl` (in the release directory's `guest-runtime/`, or `/usr/lib/mvmctl/guest-runtime/`), and `mvmctl bootstrap` on a downloaded binary otherwise fetches it, held to its digest and then its signature; `mvmctl env update` fetches the new version's archive before it replaces the binary. `mvmctl bootstrap` on a downloaded binary then assembles the runtime overlay, the initramfs and both SDK sidecars from that archive, as a source checkout does from its own, and `mvmctl doctor`'s `guest runtime` line names the archive each piece came from. A launch attaches only the pieces assembled this way and never an image set's copy: the image set's contract is the Linux layer, and a set that still publishes an overlay, sidecars or initramfs is read with those members ignored. Run `mvmctl bootstrap` to assemble a piece that is missing or fails verification, including on a binary that has not bootstrapped since it was installed or updated. The archive is not an `mvm-images` input; that repository still publishes its own guest artifacts until its side of the image boundary lands, and nothing in `mvmctl` reads them except a portable bundle's boot assets.

| Command | Description |
| ------- | ----------- |
| `mvmctl dev guest-bins` | From a source checkout, build (or reuse from the guest-build cache) every guest artifact mvm owns, for `aarch64` and `x86_64`, and write `mvm-guest-bins-v<version>.tar.gz` and its `.sha256` into the current directory. The archive holds, per architecture: `<arch>/bin/` — `mvm-guest-agent`, `mvm-guest-netinit`, `mvm-seccomp-apply`, `mvm-display-bridge`, `mvm-runner`, `mvm-egress-client`, `mvm-addon-dns`, `mvm-exit-report`, `mvm-ping`, `mvm-oci-entrypoint` and `mvm-setpriv` as static musl executables (only `mvm-egress-client` and `mvm-addon-dns` are built with `mvm-agentd`'s `addons` feature); `<arch>/initramfs/mvm-guest-agent` — the size-tuned static agent the universal initramfs runs as `/init`; and `<arch>/lib/glibc/` and `<arch>/lib/musl/` — `libmvm_host_services.so`, `libcuda.so.1`, `libcudart.so` and `libnvidia-ml.so.1`, the glibc objects linked against glibc 2.34. `sdk-py/mvm/` carries the in-guest Python SDK once for both architectures. Every executable is checked to be a static ELF for its architecture, and every shared object to be one for its architecture that needs its libc and nothing outside that libc's base libraries, before it is packaged. `manifest.json` records each member's sha256, the workspace version, the producing commit (`source.worktree` is `dirty`, with a fingerprint of the changes, when the tree did not match it), and the guest-source and host-services cdylib source fingerprints; the written archive is re-verified against it before the command reports success. Cross-compiling the glibc objects needs the pinned toolchain's `*-unknown-linux-gnu` targets, which `just payload::toolchain` installs |
| `mvmctl dev guest-bins --out <dir>` | Write the archive and its checksum into `<dir>` (created if missing) |
| `mvmctl dev guest-bins --arch x86_64` | Build only the named architecture; repeat `--arch` for more than one |
| `mvmctl dev guest-bins --check-release-archive <file>` | Read and validate an existing complete archive against this CLI's compiled version using the canonical archive and runtime validators, and print its manifest as JSON. Does not build, fetch, install or boot anything and does not require a source checkout. Refuses `--out` and `--arch`; validates bytes/inventory, not a publisher signature or native execution |

Guest-bins manifest schema 2 also records an `assemblies` declaration per guest
architecture: assembly format 1, the guest control protocol and its minimum
supported version, SHA-256 digests of the deterministic overlay image, verity
tree and compressed initramfs, and the overlay's verity root. The producer
computes these from the exact captured archive members before signing; no
cache fingerprint authenticates them. A producer whose compiled protocol
source differs from the selected checkout refuses the build: rebuild `mvmctl`
from that checkout first.

When both guest architectures are selected, `dev guest-bins` also runs the
canonical release-runtime inventory validator before reporting success. A wrong
version, incomplete required-member inventory or invalid boot assembly refuses
the build. An explicit single-architecture contributor build remains partial
and is not a publishable release runtime.

Release runtime verification requires these declarations for both architectures
and rejects unsupported schemas or assembly formats. Source development
artifacts remain unsigned; legacy schema 1 development caches remain readable
but are never release evidence. Authenticating these
declarations and copying matching artifact bytes is not, by itself, assurance
of what a detached VM executed: launch admission must still bind those owned
bytes to the backend for the VM's lifetime.

Cold workload starts and newly booted standby parents bind release artifacts
to fresh private generations under
`$MVM_HOME/runtime-evidence/<vm-name>/` (normally
`~/.mvm/runtime-evidence/<vm-name>/`). The launcher authenticates the signed
release, checks the selected guest RPC protocol and verity root, and copies
and hashes the selected overlay, verity tree and initramfs in the same read
stream. It publishes the generation before spawning and boots those private
paths, not the mutable cache paths. A deserialized proof or a source-cache
fingerprint grants no authority.

Contributor runtimes use a separate, explicitly unsigned source-integrity
path, available only to binaries whose compiled distribution channel permits
source builds. The launcher checks the actual checkout and source archive,
derives the runtime declaration, and checks the selected artifact bytes before
snapshotting. Choosing a development flag is not authorization, and choosing a
sealed workload does not disable the contributor workflow. Source integrity
does not become signed-release assurance.

The retained namespace is canonicalized and its ancestor ownership and write
permissions are checked before use. A private VM directory beneath an
unprotected writable ancestor is refused; private permissions on the leaf
alone cannot prevent another account from replacing the pathname.

These generations deliberately outlive launch handles, failed starts and VM
stops. Current backend stop interfaces do not prove which launch generation
they terminated; PID disappearance alone cannot authorize deletion. Launch
and stop logs report the retained directory, generation count and byte count.
Account for this retained disk usage. Do not remove a generation merely because
a PID file is absent or a VM name was reused: remove it only after independently
establishing that no running, detached, restoring or forked VM can still read
it. There is no automatic runtime-generation garbage collection.

## Networks

| Command                         | Description                                               |
| ------------------------------- | --------------------------------------------------------- |
| `mvmctl network create <name>`  | Create a named dev network with its own bridge and subnet |
| `mvmctl network list`           | List all dev networks (alias: `ls`)                       |
| `mvmctl network inspect <name>` | Show details of a named network (JSON)                    |
| `mvmctl network remove <name>`  | Remove a named network (alias: `rm`)                      |

## Image Catalog

`mvmctl catalog *` is the metadata-only browser for bundled application entries. `mvmctl image *` is reserved for the local OCI image cache under `~/.mvm/cache/oci/`.

| Command                                                                                                           | Description                                                                                                                                                                                                                                                                                                        |
| ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `mvmctl catalog list`                                                                                             | List bundled catalog entries                                                                                                                                                                                                                                                                                       |
| `mvmctl catalog search <query>`                                                                                   | Search entries by name, description, or tag                                                                                                                                                                                                                                                                        |
| `mvmctl catalog info <name>`                                                                                      | Show catalog entry details (JSON)                                                                                                                                                                                                                                                                                  |
| `mvmctl init <DIR> --catalog <name>`                                                                              | Scaffold a project from a catalog entry                                                                                                                                                                                                                                                                            |
| `mvmctl image build-layer --source ./staged-root --output ./app-assets`                                           | Given a complete staged root filesystem, write unsigned ext4, dm-verity, root-hash, and digest-report assets into a new directory; this does not sign or publish a pack.                                                                                 |
| `mvmctl image pull <ref> [--prod]`                                                                                | Pull an OCI image, unpack its layers, scan the base image's OS packages (dpkg/apk) and any in-image kernel against OSV, materialize a bootable `rootfs.ext4`, and record the image plus provenance, `cve.json`, and CycloneDX SBOM sidecars in the local OCI cache. `--prod` requires a digest-pinned reference, an OCI policy file, cosign verification, and a completed CVE scan                                                                               |
| `mvmctl image ls [--registry <host>] [--json]`                                                                    | List cached OCI images by reference, resolved digest, fetched timestamp, and size                                                                                                                                                                                                                                  |
| `mvmctl image inspect <ref-or-digest> [--json]`                                                                   | Print cached OCI manifest/config metadata, layer digests, and any claims/provenance sidecar                                                                                                                                                                                                                        |
| `mvmctl image inspect <ref-or-digest> --digest-ref` | Print only an immutable canonical `registry/repository@sha256:digest` reference for repeatable launches. Preserves an existing source/index pin; tag-only sources use the resolved platform manifest digest. No pull or cache mutation; refuses missing or malformed digest metadata. Mutually exclusive with `--json`. |
| `mvmctl image rm <ref-or-digest>`                                                                                 | Remove a cached OCI image and garbage-collect unreferenced layer files                                                                                                                                                                                                                                             |
| `mvmctl image boot status [--json]`                                                                               | Report each cached default boot image variant (`dev`, `prod`): tag, source (`built-local` / `fetched`), acquisition time, protocol version, on-disk size, and whether the next run would use it. Cache only, no network                                                                                            |
| `mvmctl image boot check [--json]`                                                                                | Compare the cached boot image tag against the latest published `boot-image/v*` release. Read-only; exits nonzero only when behind, so a script can gate on the exit code                                                                                                                                           |
| `mvmctl image boot update [--tag <t>] [--force]`                                                                  | Fetch and hash-verify a published boot image into a staging directory, then atomically swap it into the cache. `--tag` pins a release; `--force` is required in a source checkout, where the local build is authoritative                                                                                          |
| `mvmctl image dev ensure`                                                                                          | Ensure the writable dev default-tenant image is installed in the local cache: pair-build it from the selected mvm-images checkout, or, with none selected, install the pinned image set's `dev` members, verified against its signed root |
| `mvmctl image boot verify --manifest <f> --bundle <f> [--lock <f>] --artifacts <dir> [--artifact <name> ...] [--require-complete] [--check-revocations] [--json]` | Verify a published image set offline. Without `--artifact`, verify every member artifact. With repeatable `--artifact`, verify only the named declared artifact bytes while still checking the signed manifest against the lock, its producer, structure, and signature; output explicitly marks unselected artifacts as unverified. The omitted lock uses the pin compiled into `mvmctl`. With `--check-revocations`, also refuse a revoked set or member under the signed image-set revocation list applied with `mvmctl image revocations update`; a missing, expired, or modified list fails the command rather than being treated as empty. Without it, revocation status is not checked. No network or cache writes; a refusal names its stage and exits nonzero. |
| `mvmctl image revocations update --document <revocations.json> --bundle <revocations.json.bundle>` | Apply the signed image-set revocation list published at `https://github.com/tinylabscom/mvm-images/releases/download/revocations/revocations.json`. The bundle must name the mvm-images `revocations.yml` workflow at a `revocation-list/v<N>` tag under the GitHub Actions issuer; any other signer, including the registry-pack revocation authority, is refused. The list must be inside its own validity window (at most 62 days), and neither the publication number `N` nor `issued_at` may go back from the last applied list. Two different lists at the same `N` or `issued_at` are refused. A refused list leaves the local copy unchanged. No network. |
| `mvmctl image revocations status [--json]` | Re-verify the applied image-set revocation list and report its publication, validity window, digest, signer, and entry count. A missing, expired, incomplete, or modified local copy exits nonzero and names the command that fixes it. |

`image boot verify` also checks compatibility with this CLI. Legacy schema 2
sets retain their guest-protocol declaration. Linux-only schema 3 sets must
declare a supported `base_image_contract`; after authenticating each selected
workload root's digest, the verifier checks its
`/etc/mvm/base-image-contract` marker against that declaration. Missing,
malformed, or mismatched markers fail verification. Legacy sets do not need
the new marker. Successful JSON reports include `image_manifest_schema` and
the authenticated `compatibility` declaration; selected-artifact verification
still does not certify unselected roots.

Production OCI policy reads `MVM_OCI_POLICY` when set, otherwise
`$MVM_HOME/oci-policy.toml`. The policy allow-lists registries and trusted
keyless cosign identities. Production mode always requires signatures and
verifies the resolved digest form (`registry/repo@sha256:...`) before the image
is cached or booted:

```toml
allowed_registries = ["ghcr.io"]

[[cosign]]
certificate_identity = "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main"
certificate_oidc_issuer = "https://token.actions.githubusercontent.com"
```

Private registry pulls use explicit mvm bearer-token environment variables only.
For a single registry, set `MVM_OCI_BEARER_TOKEN_<HOST>` where `<HOST>` is the
registry host uppercased with `.`, `-`, and `:` replaced by `_`
(`ghcr.io` -> `MVM_OCI_BEARER_TOKEN_GHCR_IO`). `MVM_OCI_BEARER_TOKEN` is the
global fallback. mvm does not read `~/.docker/config.json` or invoke Docker
credential helpers, and audit entries record only the credential source name,
never the token value.

## Console

| Command                                                 | Description                                                                                                                                                                   |
| ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl machine attach <name>`                          | Dev-only interactive PTY shell into a running VM (vsock, no SSH; refused for sealed/production VMs). Attaches to the running session, replaying its scrollback, or starts one |
| `mvmctl machine console <name>`                         | Compatibility alias for `machine attach`                                                                                                                                      |
| `mvmctl machine attach <name> --force`                 | Take the session over from the client attached to it; that client is detached and the shell keeps running                                                                     |
| `mvmctl machine attach <name> --list`                  | List the VM's console session: attached, detached (and for how long), or exited with its code                                                                                 |
| `mvmctl machine attach <name> --detach-timeout <secs>` | When this attach starts the session, end it after that many seconds with no client attached                                                                                   |
| `mvmctl machine detach <name>`                          | Disconnect whoever is attached to the VM's console; the session keeps running                                                                                                 |
| `mvmctl machine console <name> --command <cmd>`         | Dev-only one-shot command in the VM (refused for sealed/production VMs)                                                                                                       |

When the machine's signed plan carries an `application_terminal` grant, an
interactive attach opens that application instead of a shell: the granted
argv runs as the workload user with the host-provisioned proxy, CA bundle and
secret placeholders. `--env` and a different argv are refused on the host, and
the guest agent refuses any argv but the granted one, any variable outside
that host-provisioned set, and a program path reached through a symlink or
writable by anyone but root, against the host-signed grant. The grant never opens a terminal on a sealed image.

In an interactive console, press Enter and then `~d` to detach (the shell keeps
running) or `~.` to end the session. Closing the terminal or losing the
connection detaches rather than ending the shell. One client is attached at a
time; a second `machine attach` is refused until the first detaches, unless it
passes `--force`. Reattaching is authorized exactly like the first attach:
sealed VMs refuse all of these verbs.

## One-shot Run (transient runner)

`mvmctl run` is an alias of `mvmctl machine run`. It takes the same flags and
follows the same path, plus the SDK `--mode`/`--dev` transport, which only
`run` carries. Both name what to boot before `--` and the guest command after
it:

```sh
mvmctl run alpine:3.20 -- echo hi          # an OCI image
mvmctl run ./app.mvmpkg -- python app.py   # a signed bundle
mvmctl run agent/claude -- true           # an installed application, explicit command
mvmctl run -- npm test                     # infer the runtime from the command
```

The positional source is classified by its shape, never by what exists on
disk. A path ending in `.mvmpkg` is a signed bundle, and anything else is an
image reference, as `--image` takes it. A release bundle is verified against
the publisher trust store every time it runs. A host-built bundle instead needs
both the signed `mvm.origin=local-build` label and the current host key; neither
condition grants authority alone. The verified archive is cached in the
content-addressed bundle registry on first use, then booted the way
`--manifest <bundle-sha256>` boots an installed bundle; it is the same run as
`--manifest ./app.mvmpkg`. A local build prints its non-release status and is
refused under `--prod`. Any other path is refused with a pointer to `--manifest` or
`--deployment`, and `app.mvmpkg` without a leading `./` is refused rather than
pulled from a registry. The guest command must follow `--`: a command written
without it is a parse error.

`run` accepts three inputs: an OCI image reference, a signed `.mvmpkg` path, and
an installed application reference `NAMESPACE/NAME[@VERSION]`. An application is
installed with `mvmctl pack pull <ref>`. As a positional, a value is read as an
application only when it parses as a reference and names an installed
application; otherwise it is an image or a bundle as before. `-a`, `--app` and
`--application` are one flag that takes the value strictly as an application
reference, with no fallback: a missing install is refused and names
`mvmctl pack pull`. The flag conflicts with `--image`, `--manifest`, `--flake`,
`--deployment` and a positional source. Without a version the installed version
is used; with one it must be the installed version. The descriptor, its
publisher policy and revocations, and the archive under your enrolled keys are
checked again at launch, and the run then continues as
`--manifest <bundle-sha256>`, so the signed plan and admit-time bundle
re-verification are the ones a `.mvmpkg` gets. The exact application reference
and descriptor digest are also bound into that signed plan; client and host
admission each reopen the typed descriptor, and host boot preparation retains
the independently reverified archive while checking the final boot files. The
normal installed application workflow needs no launch flags:

```sh
mvmctl search agent/claude
mvmctl pull agent/claude
printf '%s\n' 'tell me a joke' | mvmctl run agent/claude
```

One-time setup requires a compatible CLI, helper and native caller identity,
publisher trust (including independent bundle trust and current revocation
trust), and one existing host-held provider-bound key. Running an application
never implicitly enrolls a caller identity, publisher or key.

On macOS builds with native caller identity support, explicitly enroll once with
`mvmctl env caller-identity enroll`. `mvmctl env caller-identity show` (alias
`status`) reads only the saved public pin. Enrollment refuses an existing or
pending identity instead of replacing it; the private credential stays in the
native store.

With no command after `--`, an authenticated installed application selects its
baked entrypoint; implicit piped input is a bounded one-shot payload. An explicit
command is preserved, and conflicting entrypoint or interactive selections are
refused. Advisory resources and network defaults come from the authenticated
bundle's signed environment. Operator policy is folded after resource defaults
and before missing secret slots are filled. Explicit network selections do not
inherit additional signed destinations and cannot exceed the signed
`policy.allow_hosts` ceiling; the host independently enforces actual network
policy. Older descriptors without `policy` keep their existing network behavior.

A partial authored `--policy` can inherit signed network defaults when it
selects no destinations. A resolved `--plan` instead preserves its complete
effective network, including an empty network: application defaults never add
destinations back after resolution removed them. Explicit launch flags still
pass through the ordinary policy fold and the signed ceiling.

Required secret slots select exactly one existing provider-bound host binding
whose conventional guest variable matches the slot. Selections from `--policy`,
`--plan` or `--secret` satisfy slots before automatic selection; missing or
ambiguous slots fail before boot. Automatic names obey applied policy secret
denies. Selection reads binding metadata, not raw values, and does not change
binding destinations or admission checks. These secret defaults apply only to
authenticated application entrypoint launches, not OCI images or explicit
commands. The immutable policy-only `agent/claude@1.0.1` is not runnable.

The application entrypoint route refuses persistent and attached launches, and
request dimensions it cannot preserve: `--grants-file`, `--cpu-limit`,
`--dry-run`, `--launch-plan`, `--peer`, `--host-service`, `--asset`, `--receipt`,
GPU options, `--mount`, `--env`, `--allow-env`, policy tool rules, policy shares
and CPU-share ceilings. Other entrypoint and native-route restrictions still
apply; defaults do not grant authority or bypass admission.

The resolution is recorded as an
`application_launch` audit entry (reference, descriptor digest, bundle digest),
written once admission has produced the plan, so the entry also carries the
`run_id` (the machine name) and the `plan_id` it booted under. A positional that
names an installed policy pack is refused with a pointer to `--image`, rather
than pulled as an OCI image.

Without `-d` or another persistent flag, it is the one-shot sandbox UX: it
boots a fresh transient microVM, runs one command, and tears the VM down on
exit — like `docker run --rm` but with a Firecracker microVM as the sandbox. Plan 178 merged the former bare
`mvmctl machine exec` into `run` (it was already a strict superset); `run` adds a
security `--profile`, OCI `--image`, signed `--receipt`, `--json`/`--dry-run`,
and the SDK `--mode`/`--dev`/`--prod` transport. Arbitrary command dispatch
requires a dev-feature guest agent (the `do_exec` handler is `interactive`-gated,
claim 4). A baked-entrypoint run on a non-dev profile receives the restricted
ProdSafe grant; PTY and ad-hoc argv runs require DevOnly verbs. A production
OCI run omits the trailing command and dispatches only the Entrypoint/Cmd sealed
into the image; Nix-built production guests may also use
`mvmctl machine run --entrypoint` (no shell).

No setup is needed before a run. An unnamed run claims a standby VM already
booted from the same image with the same vCPUs and memory when one is ready, and
cold-boots otherwise. A cold boot is declared on stderr and recorded in the audit
log as `plan.start_mode`; a claimed standby is held to the 300 ms startup
ceiling, and a standby that exists but cannot be claimed fails the run with the
refusal rather than falling back to a cold boot. Each such run
leaves one standby of its image prepared afterwards, refilled after every claim,
so the first run of an image is cold and the runs after it are warm. Standbys
stay within the `standby_memory_mib` cap and are released after 20 idle minutes, after
which the next run is cold again. `mvmctl pool warm --image <image>` prepares
one ahead of time, so even the first run is warm, and `MVM_RESIDENCY=cold` turns
implicit standbys off:

```sh
mvmctl run -- uname -a                   # first run: cold boot, leaves a standby
mvmctl run -- uname -a                   # claims the standby
mvmctl pool warm --image alpine          # optional: pre-warm an OCI image
```

A named run, and a run that shares a host directory, attaches a disk
(`--mount`, `--volume`, `--output`), allows egress, or boots a signed bundle, is
never served from a standby and always boots cold.

| Command                                                             | Description                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl run -- <cmd>...`                                            | Boot the bundled default microVM image, run `<cmd>`, exit                                                                                                                                                                                                                                                                                                                             |
| `mvmctl run <image> -- <cmd>...`                                    | Boot an OCI image; the same as `--image <image>`                                                                                                    |
| `mvmctl run ./app.mvmpkg -- <cmd>...`                               | Verify and boot a publisher-trusted bundle or a same-host local build; local builds are reported as not release-verified and refused under `--prod` |
| `mvmctl run <namespace/name[@version]> -- <cmd>...`                 | Boot an installed application (`mvmctl pack pull` first); `-a`, `--app` and `--application` take the same reference with no fallback to an image |
| `mvmctl run --manifest <name-or-path> -- <cmd>...`                  | Boot a registered manifest/template instead of the default                                                                                                                                                                                                                                                                                                                            |
| `mvmctl run --manifest <app.mvmpkg> -- <cmd>...`                    | Verify, install, and boot a signed `.mvmpkg` bundle, as `machine run --manifest <app.mvmpkg>` does |
| `mvmctl run -- npm test`                                            | Infer the runtime when no source is given (see **Runtime detection** below)                                                                                                                                                                                                                                                                                                           |
| `mvmctl run --runtime <name> -- <cmd>...`                           | Boot a named runtime from the built-in catalog; an unknown name is refused, never defaulted                                                                                                                                                                                                                                                                                           |
| `mvmctl run --no-detect -- <cmd>...`                                | Skip inference and use the bundled default image                                                                                                                                                                                                                                                                                                                                      |
| `mvmctl run --image <ref> -- <cmd>...`                              | Pull or reuse a cached OCI image, emit signed audit-chain provenance for the resolved image, boot its prepared OCI rootfs (read-only virtiofs-root on capable dev-tier backends, otherwise block `rootfs.ext4`), run `<cmd>`, exit                                                                                                                                                    |
| `mvmctl run --prod --image <ref@sha256:...>`                        | Require the digest-pinned reference to satisfy the OCI policy, boot its sealed rootfs, and run the image's declared Entrypoint/Cmd via the ProdSafe `RunEntrypoint` verb under the signed plan. The plan must grant `run-entrypoint`; the guest refuses the dispatch without it. A trailing command, `--launch-plan`, and `--profile dev` remain refused before anything is pulled because they require DevOnly behavior. The base image must also carry a pull-time OSV CVE scan bound to its digest with no high/critical finding; a missing scan or a high/critical finding refuses admission                                                                                                                                |
| `mvmctl image pull --prod <ref@sha256:...>`                         | Verify the digest-pinned image against the OCI policy, scan the base image against OSV (refusing when the scan cannot run), and build/cache its sealed rootfs without running it                                                                                                                                                                                                                                                                                                                          |
| `mvmctl run --profile standard -- <cmd>`                            | Default profile on both `run` and `machine run`: explicit env is allowed; host shares must be read-only                                                                                                                                                                                                                                                                               |
| `mvmctl run --profile dev -- <cmd>`                                 | Dev tier: as standard, plus a writable (`:rw`) host share on a persistent machine and the dev guest profile for a sealed-image entrypoint run                                                                                                                                                                                                                                         |
| `mvmctl run --profile restrictive -- <cmd>`                         | No env injection and no host directory shares                                                                                                                                                                                                                                                                                                                                         |
| `mvmctl run --mount .:/work:ro -- <cmd>`                            | Attach a read-only host directory, materialized into an ext4 image at boot (a snapshot, not a live share)                                                                                                                                                                                                                                                                             |
| `mvmctl run --profile permissive -- <cmd>`                          | Escape hatch; requires `MVM_ACK_PERMISSIVE_RUN=1`                                                                                                                                                                                                                                                                                                                                     |
| `mvmctl run --mount HOST:GUEST:ro -- <cmd>`                         | Attach a read-only host directory, materialized into an ext4 image at boot (a snapshot, not a live share)                                                                                                                                                                                                                                                                             |
| `mvmctl run --output HOST_DIR:/GUEST[:SIZE[:MAX_ENTRIES]] -- <cmd>` | Give the workload a fresh writable disk at `/GUEST`; after it exits, copy its regular files and directories into `HOST_DIR` (absent or empty) under a byte bound (default `64M`) and an entry bound (default `10000`), refusing the whole collection past either. Repeatable; also on `machine run` (foreground only); disabled by `--profile restrictive`                            |
| `mvmctl run --env KEY=VAL -- <cmd>`                                 | Inject an explicit environment variable. Repeatable; disabled by `--profile restrictive`                                                                                                                                                                                                                                                                                              |
| `mvmctl run --allow-endpoint "GET https://host/path/**" -- <cmd>`   | Admit a host and allow only the listed method and path glob there; every other request to it is refused. Repeatable; flags for one host form one route. Named and detached `machine run` invocations persist validated routes                                                                                                                                                          |
| `mvmctl run --allow-env NAME --env NAME=VAL -- <cmd>`               | Re-admit one denied variable (loader, shell, interpreter, or password-manager session) by exact name; patterns are refused. Without it, a denied `--env` or launch-plan variable refuses the run                                                                                                                                                                                      |
| `mvmctl run --secret <name>[:<host>,...] -- <cmd>`                  | Bind a stored secret. The guest gets an opaque placeholder under the provider's variable (`ANTHROPIC_API_KEY`, …) and the host substitutes the real value into requests to the bound destinations. Hosts narrow the binding, never widen it. Repeatable; refused before boot                                                                                                          |
| `mvmctl run --cpus <n> --memory <size> -- <cmd>`                    | Resize the transient VM                                                                                                                                                                                                                                                                                                                                                               |
| `mvmctl run --timeout <secs> -- <cmd>`                              | Per-command timeout                                                                                                                                                                                                                                                                                                                                                                   |
| `mvmctl run --dry-run -- <cmd>`                                     | Validate and explain the run plan without resolving an image, booting a VM, writing a receipt, or executing the command                                                                                                                                                                                                                                                               |
| `mvmctl run --dry-run --json -- <cmd>`                              | Print the dry-run preflight summary as redacted JSON                                                                                                                                                                                                                                                                                                                                  |
| `mvmctl run --receipt <path> -- <cmd>`                              | Write a signed JSON receipt with invocation hashes, output hashes, and exit status. Raw argv, env values, stdout, and stderr are not stored.                                                                                                                                                                                                                                          |
| `mvmctl run --json -- <cmd>`                                        | Print a redacted JSON execution summary with invocation metadata, output hashes, `egress_denials` (each refused destination, its recorded reason, count, and remedy), optional `egress_review` (the command for later review of grantable refusals), and `network` (`none` when the run has no egress grant, peer route, or secret; otherwise `granted`). Guest stdout/stderr are not streamed and no review prompt opens.                                                                                                                                                                                                                                        |
| `mvmctl run --json --receipt <path> -- <cmd>`                       | Print the same JSON summary and also write a signed receipt artifact                                                                                                                                                                                                                                                                                                                  |
| `mvmctl trust receipt verify <path>`                                | Verify a signed run receipt against `~/.mvm/keys/host-signer.pub`                                                                                                                                                                                                                                                                                                                     |
| `mvmctl trust receipt verify <path> --pubkey <path>`                | Verify a signed run receipt against an explicit raw Ed25519 public key                                                                                                                                                                                                                                                                                                                |

`run --dry-run` is a preflight-only path. It validates profile, env-key,
resource, and host-share policy, then reports hashes and policy-relevant
metadata. Manifest arguments, argv, host paths, and receipt paths are hashed
rather than printed. It deliberately does not resolve manifests, build/download
the default image, start a VM, execute the command, or write a receipt.

`run --json` is intended for machine callers. It preserves the command's exit
code, but the JSON does not include raw argv, env values, stdout, stderr, or host
paths.

### Runtime detection

With no positional source and no `--image` / `--manifest` / `--flake` /
`--deployment` / `--runtime-pack`, a transient run settles the boot source in
this order. The order is the contract:

1. **An explicit source**, positional or flag. Nothing is inferred.
2. **`--runtime <name>`** against the built-in catalog. An unknown name is
   refused and lists the known ones — a typo never falls through to a default.
3. **A first command word that reads as an OCI image reference** — a tag
   colon, a digest, or an explicit registry host before a `/`, and not a
   path — refuses right here, before any inference runs. This is not part
   of inference and is not gated on steps 5–6 below finding nothing: it
   applies equally to `--no-detect` and to persistent runs, which never reach
   steps 5 or 6 at all. `mvmctl run -- app:1.0 sh` refuses with a hint to
   name the image before `--` (`mvmctl run app:1.0 -- sh`) for exactly this
   reason. A source flag
   from step 1, or `--runtime` from step 2, skips this check entirely, so a
   legitimate command whose first word happens to contain a colon still
   runs. A word that names an existing path relative to the working
   directory is never refused, whichever marker it carries: `app.d/run`
   reads like a registry host and `bin/run:dev` like a tag.
4. **`--no-detect`** stops here, leaving the bundled default image.
5. **An `mvm.toml` (or `Mvmfile.toml`)** in or above the working directory,
   found by the same walk-up `mvmctl machine build` uses, stopping at a `.git` boundary.
6. **The command, then a project file.** `npm` selects node; `Cargo.toml`
   selects rust. The command wins over the directory — argv is what you just
   typed, the directory is where you happened to be standing.
7. **The bundled default image.**

| Runtime  | Image                | Commands                                     | Project files                                               |
| -------- | -------------------- | -------------------------------------------- | ----------------------------------------------------------- |
| `python` | `python:3.12-alpine` | `python`, `python3`, `pip`, `pip3`, `pytest` | `pyproject.toml`, `requirements.txt`, `Pipfile`, `setup.py` |
| `node`   | `node:22-alpine`     | `node`, `npm`, `npx`, `yarn`, `pnpm`         | `package.json`                                              |
| `rust`   | `rust:1-alpine`      | `cargo`, `rustc`                             | `Cargo.toml`                                                |
| `go`     | `golang:1-alpine`    | `go`, `gofmt`                                | `go.mod`                                                    |
| `ruby`   | `ruby:3-alpine`      | `ruby`, `bundle`, `rake`, `gem`              | `Gemfile`, `Rakefile`                                       |
| `shell`  | `alpine:3`           | `sh`, `bash`, `ash`                          | —                                                           |

Separately, a known flag (`--image`, `--net`, …) placed as the very first
word after `--` is refused and named rather than passed to the guest
verbatim: `trailing_var_arg` never reinterprets anything after `--` as an
option, so `mvmctl run -- --image alpine` would otherwise hand `--image` to
the guest silently. Only that first position is checked; the same flag name
appearing deeper in a workload's own argv is left alone. The flag list is
read from the subcommand being run, including the global flags clap passes
down to it, so it covers `machine run` flags (`--name`, `-d`), `run`'s own
(`--mode`), the flags they share, and `--verbose`/`-v`, `--builder` and the
other global flags. The error says whether the flag belongs to that
subcommand or is a global one. Every spelling counts: aliases, hidden or not
(`--volume`), `--flag=value`, short flags, short clusters (`-it`), and a
short flag with its value attached (`-p8080:80`). A standalone `--help` or
`-h` is not refused, since a workload may forward it to its own program;
inside a cluster (`-ih`), `h` is a flag like any other. `--version` and `-V`
are never refused, because neither subcommand has them. On
`mvmctl run` the check also runs before an SDK `--mode`, whose first word is
a script path.

An inferred source always announces itself on stderr before booting
(`[mvm] detected node from the command `npm` — booting node:22-alpine`), so a
run never boots an image you did not choose without saying so. `--json` stdout
is unaffected.

Detection picks a **source**, never a posture. An inferred run admits through
the same signed `ExecutionPlan`, with the same `--profile standard` default and
the same deny-all egress, as one that named its image.

**A persistent run does not infer.** Steps 5 and 6 are skipped for `-d`,
`--ttl`, `--port`, `--healthcheck` and `--up-json`, on either verb: a machine
that outlives the command should not take its base image from whatever
directory you were standing in — inside any Rust checkout it would quietly
become a machine on `rust:1-alpine`. Such a run keeps its error naming every
way to supply a source. `--runtime <name>` works either way, because that is
you naming one. The misplaced-image-reference refusal (step 3) runs for every
run.

The catalog is curated, in-tree, and versioned with the code; it is never
fetched at runtime. Its refs are **tags, not digests**, which is deliberate:
they are a dev-tier convenience. `--prod` refuses a mutable reference before any
network fetch, so a production run cannot inherit a detected tag — it has to
name a digest.

## Machine (beginner UX)

The named-machine lifecycle uses one `mvmctl machine` surface. Start a
persistent machine with `machine run -d` (or `machine create` followed by
`machine start`), then use `machine ps`, `machine attach <name>`,
`machine detach <name>`, `machine logs -f <name>`, `machine stop <name>`, and
`machine inspect <name>`. `machine ls` and `machine console` remain aliases for
`ps` and `attach` for existing scripts. `detach` disconnects the console
client; it does not stop the machine. Console attach remains dev-only and
requires the same grant as before.

A detached start returns its name or success receipt only after the guest
answers an authenticated Ping/Pong on its control channel, within a 30-second
readiness deadline. If startup fails or times out, the command returns an
error and rolls back the partial backend start before volume leases commit or
launch acceptance is recorded. The failed plan is recorded and sealed in the
audit chain. The persisted machine definition remains available for
`machine inspect` and a later explicit `machine start`. An already-running
machine is reused without a new boot.

`machine session` remains a hidden compatibility and SDK warm-residency
surface, with its own session IDs and idle timeout. `agent-session` manages
durable agent state that may outlive and resume in a different sandbox. Neither
is another way to list, attach to, or stop a named machine: use the six
`machine` lifecycle commands above for that.

`mvmctl machine` is the beginner-facing command group. It is a thin UX layer
over the existing runtime verbs and state helpers, not a parallel runtime.
Booting machine commands use the same signed-`ExecutionPlan`, audited,
OCI-provenance execution path as the lower-level commands; non-booting state
commands persist declarative specs under `MVM_HOME`.

The flagship verb is `machine run`, which selects one of three lifecycles by
flag:

- **Transient** (default): boot a fresh microVM from an OCI image, run the
  command, tear the VM down. Routes into the same code path as
  `mvmctl run --image`, inheriting **deny-all networking by default**, opt-in
  egress via `--net` / `--allow-host`, and the same `--profile`, `--volume`,
  `--receipt`, `--json`, and `--dry-run` semantics.
- **Foreground interactive** (`-t`/`--tty`, with `-i` accepted so `-it`
  parses): boot a fresh transient VM, run the requested argv attached to a PTY,
  return that command's exit code, then tear the VM down. **Dev-only** —
  requires DevOnly verbs, is refused for a sealed image (claim 15), and is
  refused when stdin is not a terminal.
- **Persistent** (`machine create` + `machine start`, or `machine run -d`):
  boot a machine that survives after the command returns and is reconnectable by
  name through `machine shell`/`exec`/`stop`. Bare `-d` auto-generates a name and
  prints it; `-d --name <N>` uses your chosen name.

A fourth trigger promotes into the persistent lifecycle without `-d`:
`--healthcheck '<cmd>'` declares the workload a long-running service — its mere
presence registers the machine (shows in `machine ps`, torn down with `machine
stop <name>`) and it runs in the **foreground** unless you also pass `-d`. The
command is exec'd in the guest as a liveness check (exit 0 = healthy); the
`--health-interval`/`--health-timeout`/`--health-retries`/`--health-start-period`
tuning flags are recorded on the machine spec and actively enforced. The
entrypoint's own exit code still terminates the machine either way, so a
healthcheck on a run-to-completion task has no effect.

The resident host-agent daemon (default-on; opt out with
`MVM_HOST_AGENT_DAEMON=0`, in which case health always shows `unknown`) probes
every healthchecked persistent machine every `--health-interval` seconds, once
`--health-start-period` seconds have elapsed since start (failures during the
start period are grace-period noise and don't count). `machine ps` shows the
result in a `HEALTH` column and `machine inspect` shows a `health:` line, one
of:

- `starting` — still inside the start period, or no probe result yet.
- `healthy` — the most recent probe exited 0.
- `unhealthy` — `--health-retries` consecutive probes have failed.
- `-`/`unknown` — no readiness signal (including when the daemon is disabled).

When a service goes `unhealthy`, the daemon restarts it (the same stop→start
`mvmctl machine restart` does) under a bounded exponential backoff: 1s base,
doubling per attempt, capped at 5 minutes, up to 5 attempts. Once the cap is
hit the service is left `unhealthy` rather than crash-looping forever; a
sustained-healthy period afterward resets the restart budget back to zero. A
crashed service — the guest process gone, the agent unreachable — is caught by
the same probe path (an unreachable agent counts as a failed probe) and
restarted under the identical policy, so there's no separate crash-detection
mechanism to reason about.

This is a dev/accessible-tier feature: the check runs inside the guest via the
host agent, so it only applies to backends where that agent is reachable.

A warm session (`machine session start`, or a session opened through an SDK)
is stopped once it has sat idle past its `--idle-timeout` (default 300
seconds), measured from its last call. On libkrun and HVF the per-VM
supervisor enforces this with no command running: it marks the session
`reaped`, records the reap in the audit log, seals the session's audit chain
the way `machine stop` does, and stops the machine. Firecracker and QEMU have
no per-VM supervisor; there the tenant's resident host agent, which a session
start launches if it is not already running, watches the session and runs
`machine session reap` once it expires. That sweep stops a Firecracker machine
through the same `sudo` signal `machine stop` uses, and the host agent has no
terminal, so it needs `sudo` that does not prompt; where `sudo` prompts, the
session is stopped by the next `machine session` command instead.

HVF stop uses authenticated instance control and confirms the supervisor's actual
process exit and successful finalization before cleanup. A missing endpoint, key,
or lifetime proof is an error, not evidence that the machine stopped, with one
exception: when the control socket refuses the connection and the supervisor
process recorded for the machine is no longer alive, `machine stop` reports
`machine <name> is already stopped` and exits 0, so repeating a stop is safe.
A socket error with a live or unrecorded supervisor stays an error. Older HVF
instances without this control protocol require separate operator recovery; there
is no PID-based stop fallback. Runtime and session evidence is retained on refusal.
An owned launch can prove its normal exit after its endpoint closes; a later
detached client cannot reconstruct that proof from a missing PID file.

HVF wall-clock and session expiry preserve the hard timeout exit code 124, without
adding a guest-execution grace period. A hard expiry does not claim graceful
capture or helper finalization, so it retains runtime evidence and automatic
cleanup can still refuse. Other backends retain their existing expiry cleanup.

Identity and lifetime are separate: `--name <N>` names a foreground transient
run but does not make it persistent. `-d`/`--detach`, `--up-json`, or the
explicit `machine create`/`start` lifecycle make a long-lived machine.
`--volume` host shares work on every run mode. The syntax is
`HOST:/GUEST[:MODE]` (`MODE` defaults to `ro`; `rw` needs `--profile dev` or
`permissive`). Persistent machine specs canonicalize host paths to absolute
paths so later reconnects re-mount the same share regardless of your working
directory; the host directory must exist at boot.

SSH is banned in microVMs, with no dev-tier carve-out: `--allow-host <host:22>`
is refused, the runtime also denies TCP/22 even under broad egress, and there
is no ssh-agent forwarding of any kind — no private keys, `~/.ssh`,
known-hosts material, SSH config, or host agent socket ever crosses into a
guest, on any tier.

| Command                                                                                        | Description                                                                                                                                                                                                                                                                                                                          |
| ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `mvmctl machine run --image <ref> -- <cmd>...`                                                 | Boot an OCI image, run `<cmd>` with no network, tear down                                                                                                                                                                                                                                                                            |
| `mvmctl machine run --net --image <ref> -- <cmd>...`                                           | Boot with dev-tier outbound networking enabled                                                                                                                                                                                                                                                                                       |
| `mvmctl machine run --image <ref> --allow-host <host[:port]> -- <cmd>...`                      | Boot with egress narrowed to the listed TCP host/port entries (`<host>` alone defaults to `:443`)                                                                                                                                                                                                                                    |
| `mvmctl machine run --image <ref> --profile dev --volume .:/work:rw -- <cmd>`                  | Same, with a writable host share under the dev profile                                                                                                                                                                                                                                                                               |
| `mvmctl machine run --image <ref> --cpus <n> --memory <size> -- <cmd>`                         | Resize the transient VM                                                                                                                                                                                                                                                                                                              |
| `mvmctl machine run --image <ref> --dry-run -- <cmd>`                                          | Validate and explain the run plan without booting a VM                                                                                                                                                                                                                                                                               |
| `mvmctl machine run --image <ref> --json -- <cmd>`                                             | Print a redacted JSON execution summary with `egress_denials` and optional `egress_review`; no review prompt opens                                                                                                                                                                                                                  |
| `mvmctl machine run --image <ref> --receipt <path> -- <cmd>`                                   | Write a signed execution receipt                                                                                                                                                                                                                                                                                                     |
| `mvmctl machine run -d --image <ref>`                                                          | Boot a **persistent** machine, auto-name it (printed), return                                                                                                                                                                                                                                                                        |
| `mvmctl machine run -d --name <name> --image <ref>`                                            | Boot a **persistent** named machine and return. Add `--profile dev` at launch if later `machine shell` or ad-hoc `machine exec` is needed; the standard profile's signed verb grant does not authorize those operations.                                                                                                                    |
| `mvmctl machine run --healthcheck 'curl -fsS localhost/health' --image <ref>`                  | Boot a **persistent** machine in the foreground (registered, shows in `machine ps`); its presence alone promotes the lifecycle even without `-d`                                                                                                                                                                                     |
| `mvmctl machine run -d --healthcheck 'curl -fsS localhost/health' --name <name> --image <ref>` | Same, detached — the usual way to run a long-lived service                                                                                                                                                                                                                                                                           |
| `mvmctl machine run --name <name> --image <ref> -- <cmd>`                                      | Boot a named foreground transient machine, run `<cmd>`, tear down                                                                                                                                                                                                                                                                    |
| `mvmctl machine run -it --image <ref> -- <cmd>`                                                | Run `<cmd>` attached to a PTY, return its exit code, tear down                                                                                                                                                                                                                                                                       |
| `mvmctl machine run -it --name <name> --image <ref> -- <cmd>`                                  | Same, with a stable transient VM name while it runs                                                                                                                                                                                                                                                                                  |
| `mvmctl machine create <name> --image <ref>`                                                   | Persist a named OCI-backed machine spec without booting it                                                                                                                                                                                                                                                                           |
| `mvmctl machine create <name> --manifest <path>`                                               | Persist a named machine spec from an image-backed `mvm.toml` / `Mvmfile.toml`                                                                                                                                                                                                                                                        |
| `mvmctl machine create <name> --manifest <path> --policy NAME\|PATH`                          | Persist a spec under an authored policy profile, resolved with the manifest's `[policy]` and `[network] allow_hosts` exactly as `run` resolves them; the spec records network, resource and tool-command rules, then re-admits them on each start. Tool-scoped routes and secrets are refused until endpoint binding is enforced. Also on `machine start --image/--manifest` |
| `mvmctl machine create <name> --image <ref> --net --allow-host <host[:port]>`                  | Persist a named spec with opt-in egress settings for future lifecycle starts                                                                                                                                                                                                                                                         |
| `mvmctl machine create <name> --manifest <path>`                                               | Persist an image-backed `mvm.toml` / `Mvmfile.toml` as a named machine spec                                                                                                                                                                                                                                                          |
| `mvmctl machine create <name> --image <ref> --force`                                           | Overwrite an existing named machine spec                                                                                                                                                                                                                                                                                             |
| `mvmctl machine start <name>...`                                                               | Boot one or more persisted named machines through the admitted OCI-backed start path (`--receipt`/`--json`/`--dry-run` are single-machine)                                                                                                                                                                                           |
| `mvmctl machine start <name> --dry-run`                                                        | Validate and explain the effective machine-start policy without booting a VM                                                                                                                                                                                                                                                         |
| `mvmctl machine start <name> --dry-run --json`                                                 | Print the machine-start preflight summary as redacted JSON                                                                                                                                                                                                                                                                           |
| `mvmctl machine start <name> --json`                                                           | Print a redacted JSON start summary instead of plain text                                                                                                                                                                                                                                                                            |
| `mvmctl machine start <name> --receipt <path>`                                                 | Write a signed machine-start receipt with effective policy plus the resolved digest and start timestamp                                                                                                                                                                                                                              |
| `mvmctl machine start <name> --image <ref>`                                                    | Start a persisted machine, creating its spec on demand if it does not exist. Combines `machine create <name> --image <ref>` and `machine start <name>` into one command                                                                                                                                                              |
| `mvmctl machine start <name> --manifest <path>`                                                | When auto-creating, source defaults (image, sizing, network, volumes, dev-init) from an image-backed `mvm.toml` / `Mvmfile.toml`                                                                                                                                                                                                     |
| `mvmctl machine start <name> --image <ref> --cpus N --memory SIZE`                             | Size the machine when auto-creating it (same defaults as `machine create`)                                                                                                                                                                                                                                                           |
| `mvmctl machine start <name> --image <ref> --net --allow-host <host[:port]>`                   | Set egress policy when auto-creating the machine                                                                                                                                                                                                                                                                                     |
| `mvmctl machine start <name> --image <ref> --force`                                            | If the machine exists with a different config, stop the old instance, overwrite the spec, and start. Without `--force` a config mismatch errors                                                                                                                                                                                      |
| `mvmctl machine restart <name>...`                                                             | Restart one or more named machines: stop if running, then start (same stop→start as a config-change recreate). This is also how a running machine picks up a newer version-matched runtime overlay.                                                                                                                                  |
| `mvmctl machine ps` (alias `ls`)                                                               | List every microVM: persistent machines and running transients                                                                                                                                                                                                                                                                                                   |
| `mvmctl machine ps --json`                                                                     | Print the same inventory as JSON                                                                                                                                                                                                                                                                                          |
| `mvmctl machine inspect <name>`                                                                | Show one persisted named machine spec, plus `enforced-cpu:` — the tier that actually bounded its last boot, read back off the live control. A `cpu-limit:` line shows what was _requested_; the two are separate on purpose, since a request and an enforcement are not the same statement. Absent when no boot has recorded a tier. |
| `mvmctl machine inspect <name> --json`                                                         | Print one persisted named machine spec as JSON, with an `enforced_grants` object carrying the achieved per-dimension tiers                                                                                                                                                                                                           |
| `mvmctl machine rm <name>... --yes`                                                            | Remove one or more persisted named machine specs (refuses a running machine; pass `--force` to stop then remove)                                                                                                                                                                                                                     |
| `mvmctl machine rm --all --yes`                                                                | Remove every persisted named machine spec                                                                                                                                                                                                                                                                                            |
| `mvmctl machine rm <name>... --yes --json`                                                     | Print a JSON array deletion summary                                                                                                                                                                                                                                                                                                  |
| `mvmctl machine exec <name> -- <cmd>...`                                                       | Run a command in an already-started named machine                                                                                                                                                                                                                                                                                    |
| `mvmctl machine exec <name> --tool TOOL -- <cmd>...`                                           | Run a declared non-interactive command only after the admitted per-VM tool policy and endpoint audit allow its exact argv. The policy must bind `TOOL` to the exact absolute guest executable path passed as `<cmd>`; aliases, relative commands, a missing endpoint, or a missing approval are refused before spawn. The same declared command spawned by the workload itself is intercepted in-guest and decided by the same endpoint gate before it runs (see the tool-policy guide). |
| `mvmctl machine exec <name> -it -- <cmd>...`                                                   | Run a command in an already-started named machine attached to a PTY                                                                                                                                                                                                                                                                  |
| `mvmctl machine exec <name>`                                                                   | Omit the command to drop into an interactive shell (same as `machine shell`)                                                                                                                                                                                                                                                         |
| `mvmctl machine shell <name>`                                                                  | Attach an interactive shell/console to an already-started named machine — persistent or transient (a `machine run --name <name>` VM is reachable while it runs)                                                                                                                                                                      |
| `mvmctl machine stop <name>...`                                                                | Stop one or more already-started named machines (prompts for confirmation; pass `--yes` to skip)                                                                                                                                                                                                                                     |
| `mvmctl machine reconfigure <name> [flags]`                                                    | Patch a persistent machine's config and relaunch it. Only the flags you pass are changed; everything else (image, volumes, profile) is preserved. When the machine is running, it is stopped and restarted automatically; when stopped, the change is staged for the next `machine start`.                                           |
| `mvmctl machine reconfigure <name> --net` / `--no-net`                                         | Enable or disable the dev-tier outbound network preset                                                                                                                                                                                                                                                                               |
| `mvmctl machine reconfigure <name> --allow-host <host[:port]>`                                 | Replace the stored egress allowlist with these hosts (repeatable within one invocation); use `--clear-allow-host` to empty it                                                                                                                                                                                                        |
| `mvmctl machine reconfigure <name> --clear-allow-host`                                         | Remove all per-host egress entries and fall back to the default network posture                                                                                                                                                                                                                                                      |
| `mvmctl machine reconfigure <name> --cpus <n>`                                                 | Change the vCPU count                                                                                                                                                                                                                                                                                                                |
| `mvmctl machine reconfigure <name> --memory <size>`                                            | Change the memory limit (accepts `512m`, `1g`, etc.)                                                                                                                                                                                                                                                                                 |
| `mvmctl machine reconfigure <name> --mem-initial <size>`                                       | Change the initial balloon memory target (CLI-only; not exposed on the remote facade)                                                                                                                                                                                                                                                |
| `mvmctl machine check-artifact <bundle.mvmpkg> [--trust-store <dir>]`                           | Verify the signed bundle, its declarations, its complete embedded image-set manifest, and every image size/hash, confirm its architecture matches this host, and preview its posture, without installing or booting                                                                                                                                                                                                                        |
| `mvmctl machine check-artifact <bundle.mvmpkg> --json`                                        | Print the verdict as JSON, including the declared posture (`null` when none), kernel command line, and build input                                                                                                                                                                                                                   |
| `mvmctl machine check-artifact <bundle.mvmpkg> --backend <name>`                                | Also refuse before boot when the selected Linux-direct backend lacks the artifact's architecture, boot protocol, image format, or required guest device                                                                                                                                                                               |

### Workload output capture

`machine run` attaches to the workload's output by default — `--detach`,
`--json`, and `--up-json` are the three ways to opt out. Interrupting an
attached run on a **persistent** machine detaches from the output and leaves
the machine running; the command says so before it blocks.

Every workload's stdout and stderr are captured whether or not anybody is
watching. Two sources feed one stream: the guest's entrypoint frames over
vsock, which keep their channel, and the hypervisor's console capture, which
covers boot and anything written after the guest agent is gone. Console-sourced
records are recorded as `stdout` whichever fd wrote them, because a console is
one merged byte stream; a narrowed `--stream` read prints a note saying so.

Records are hash-chained and the recorded transcript is sealed to a Merkle root
at exit, so `machine logs` verifies what it shows and **exits nonzero on a
verification failure**, mirroring `mvmctl trust audit verify`. A pruned window
is not a failure: retention is a ring, so a chatty workload loses its oldest
records rather than being throttled or killed, and the loss is announced as a
gap or truncation notice on stderr.

Recording is on by default. `ExecutionPlan.stream_retention` (`persist` /
`ephemeral`) is a signed plan field, not a CLI flag, recorded on
the `plan.admitted` audit entry so an absent transcript is attributable rather
than ambiguous. Nothing selects `ephemeral` today — every production caller
takes the default — so treat the field as the place a future opt-out will live
rather than one you can reach now.

The following limits apply to legacy file-backed console capture, not the
native HVF protected path described below:

- The recorded transcript is redacted; the **console fallback is not**, so a
  read that falls back to (or splices in) the console shows raw guest bytes.
- A machine started with `-d` is captured only for as long as the starting
  process lives, so a detached machine's later output reaches no recorder. You
  still see it, via the unchained console log.
- A spliced read **repeats** the part the recording already showed, because
  console byte offsets and transcript sequence numbers share no coordinate.
  Duplicated, never lost.

**Native HVF protected capture (draft integration).** New native HVF launches
require a matching host helper and a supervisor-owned encrypted console
capture before boot is announced. The supervisor continues consuming console
output after the launcher exits. A bounded, nonblocking handoff drops and
counts output under overload or consumer failure; it never slows the guest
behind encryption or disk I/O and never falls back to a plaintext console
file. `machine logs` refuses plaintext fallback for these runs, including when
capture setup fails. Signed `ephemeral` policy remains non-persistent.

New protected capture families and their routing metadata live under
`$MVM_HOME/audit/workload-output/<hex-encoded-concrete-vm-name>/`, outside
disposable runtime and machine-instance directories. Public stop/removal and
orphan reaping do not delete these captures. Live sockets and fixed supervisor
status remain runtime-local. Legacy recordings are not moved or enrolled.
Restart publishes a fresh run selection without merging earlier sequence
spaces; a retained family belonging to another tenant refuses name reuse.

Raw supervisor stderr is deliberately discarded on this path, including
startup failures; it is not retained or exportable. Public errors retain exit
status and sanitized guidance rather than raw helper output.
`supervisor-status.json` in the VM state directory records fixed lifecycle
states such as `capture_setup_failed`, `boot_failed`, and `capture_failed`.
Encrypted supervisor-stderr collection is a separate follow-up.

Durable generations rotate hourly and become unreadable seven days after sealing. The
existing 8 MiB / 65,536-chunk budget covers the concrete VM's entire managed
generation set, including the active generation; encrypted record-envelope
bytes count against that budget. Pressure seals the active generation before
authenticated oldest-generation retirement. Unreclaimable capacity sheds
durable output and reports capture failure, rather than enlarging the limit.
Startup and bounded periodic maintenance use the signed original capture
authority. Recovery requires exclusive producer leases and a durable signed
opening; recovered output is explicitly incomplete and retry preserves the
original staged terminal timestamp. Missing or pruned audit authority refuses
recovery/retirement. `mvmctl trust audit prune --through <segment>` is a dry-run;
`--ack` commits only after repeating verification and protected-evidence admission
under the audit lock. Original opening, seal and retirement evidence remains
pinned while enrolled verification metadata is retained, even after ciphertext
retirement; the containing audit segments may remain indefinitely. Retirement
records are pre-unlink intent, not proof of completed deletion.
Busy managed capture inventory refuses pruning with a retryable diagnostic,
including when its tenant cannot yet be authenticated. Missing/corrupt authority
and ambiguous legacy enrollment also refuse rather than disposing of metadata
or manufacturing replacement authority. Known authenticated legacy v6 captures
remain unenrolled. Unaccounted interrupted ciphertext tails are preserved for
offline recovery rather than automatically discarded.
If a verified legacy seal is pruned but its manifest remains, that manifest alone
cannot authenticate legacy status during a later prune; the later attempt refuses
for missing authority. Do not treat this refusal as permission to delete metadata.
Maintenance runs at supervisor startup and while it is alive. There is no
always-on physical cleanup of stopped, never-restarted captures in this slice:
read expiry remains enforced, but seven-day physical deletion is not
guaranteed. Always-on stopped-capture maintenance remains a separate follow-up.

Verified history checks signed retirement before decrypting any payload, even
when deletion was interrupted. Retired/expired history reports an explicit
retention gap. Live attachment has a bounded RAM replay window, not a promise
that every active byte is already terminally verified history.
An already-open reader has no lifetime exemption: buffered history rechecks its
generation's authority before each record, and stalled live frames recheck
revocation and expiry before each nonblocking write. Revocation closes a
partially sent frame rather than transmitting the remainder under stale
authorization. Already-delivered bytes cannot be recalled.

The dedicated native cold witness verifies genuine boot UART output through the
live reader after the launcher exits, then through verified encrypted history
after public stop, with no matching plaintext managed artifact. This proves
post-launcher availability of boot output, not that bytes were emitted after
launcher exit. The stronger synthetic post-detach UART-emission witness remains
outstanding: ordinary unprivileged guest processes cannot write `/dev/console`,
and RPC stdout is not a substitute for the UART path.

This integration remains scoped to protected native-HVF console capture; final
review and CI determine merge readiness, not a claim that all diagnostic
surfaces or lifecycle witnesses are complete.
The draft warm-handoff path prepares a fresh child capture, requires every vCPU
to acknowledge quiescence, replaces the parent's UART capture state, and
finalizes the old owner before acknowledging transfer. Failure refuses the
transfer rather than using the parent's capture or plaintext output. This path
has unit/mock evidence only; native-HVF lifecycle and prepared-launch performance
have not been validated.
The seven-day lifetime after sealing and hourly generation schedule do not
replace byte limits. Legacy captures are not automatically enrolled. This
native-HVF sequencing does not cover other backends or telemetry.

Full walkthrough: [Workload output
streaming](/guides/workload-output-streaming/).

### Runtime overlay updates

For overlay-backed guests, runtime updates happen on **start/restart**, not by
live remounting inside a running VM:

- `mvmctl machine start <name>` picks up the overlay version attached for that
  boot.
- `mvmctl machine restart <name>` is the normal way to move a running machine
  onto a newer version-matched runtime overlay.
- A running machine keeps the runtime overlay version it already booted with
  until restart.

### `machine run` lifecycles in practice

A transient run is the default and needs no flags — it boots, runs the command,
and tears the VM down:

```bash
mvmctl machine run --image alpine -- echo hi      # prints "hi", VM gone
```

A bare `machine run --image alpine -- /bin/sh` is **non-interactive**: it streams
the command's output but forwards no terminal. For a live shell or any command
that needs a TTY, add `-it` and pass the foreground argv explicitly:

```bash
mvmctl machine run -it --image <dev-image> -- /bin/sh   # exits with /bin/sh, VM gone
mvmctl machine run -it --image <dev-image> -- htop      # exits with htop, VM gone
```

For OCI `--image` runs that request outbound egress (`--net` or `--allow-host`),
`mvmctl` selects only backends that can keep the guest NIC-less and route
traffic through the host-side vsock mediation endpoint. On that path the
guest agent starts `mvm-egress-client` and the runtime injects proxy
env vars pointing at its loopback SOCKS listener automatically. Today that
means `hvf`; incapable backends are refused rather than silently
falling back to a guest NIC. That makes TCP/HTTP clients work, but it does
**not** add ICMP
support: `ping` is not a valid smoke test for `--allow-host`.

Naming a foreground run does not make it persistent; it only gives the transient
VM a stable identity while it is running:

```bash
mvmctl machine run --name debug --image alpine -- echo hi
mvmctl machine run -it --name debug --image <dev-image> -- /bin/sh
```

Use the explicit persistent lifecycle when you want the VM to survive:

```bash
mvmctl machine run -d --profile dev --image alpine  # boots, prints e.g. "blue-fox-3f2a", returns
mvmctl machine shell blue-fox-3f2a            # reconnect (dev PTY)
mvmctl machine exec  blue-fox-3f2a -- ps          # one-shot command in the running machine
mvmctl machine exec  blue-fox-3f2a -it -- /bin/sh   # PTY command in the running machine
mvmctl machine stop  blue-fox-3f2a --yes      # tear it down when done
```

`-d --name <N>` does the same with a name you choose.
The explicit dev profile permits later shell and ad-hoc exec requests under
the admitted plan's guest profile. A detached standard-profile service does
not receive those verbs; attaching a dev command to it is refused.

**Interactive is dev-only.** `-t`/`--tty` attaches the foreground command to a
PTY and requires DevOnly verbs; it is refused for a sealed/production image
(claim 15 — no interactive access to a sealed microVM) and when stdin is not a
terminal. `machine run -it`
requires an argv after `--`; use `machine shell <name>` (or `machine exec
<name>` with no argv) for the default shell on an already-running machine.

`machine create` accepts either `--image <ref>` or an image-backed manifest, not
both. When `--image` is omitted, it searches the current directory for
`mvm.toml` / `Mvmfile.toml`; `--manifest <path>` selects a file explicitly. The
persisted spec carries the manifest's image, CPU/memory sizing, `mem_initial`,
network defaults, allow-hosts, volumes, and its `[grants]` table.

A workload's grants — what it may consume and where it may reach — can be
declared in four places, resolved **per dimension** from highest precedence to
lowest: CLI flags, a `--grants-file` JSON document, the manifest's `[grants]`
table, and the `~/.mvm/config/config.toml` defaults. Per dimension means a
`--cpu-limit` on the command line does not discard an egress allowlist the
manifest declared; each of CPU, wall clock, and egress is settled on its own.

`machine create` is the verb that reads the `[grants]` table — from `--manifest
<path>`, or from the `mvm.toml` / `Mvmfile.toml` in the current directory when
`--image` is omitted. Transient `machine run` reads no project manifest at all
(its own `--manifest` names a pre-built image, not an `mvm.toml`), so grants
there come from `--cpu-limit`, `--timeout`, `--allow-host`, `--grants-file`, and
the host config. That split is deliberate: discovering an `mvm.toml` from the
working directory would let a manifest in an unrelated checkout cap a run that
never meant to use it.

```toml
# mvm.toml
image = "alpine:3.20"

[grants]
cpu_millicores = 1500      # or cpu_fuel = <instructions>; the two are units, not precisions
wall_clock_secs = 600      # must be > 0; omit to leave the workload unbounded
allow_hosts = ["api.example.com:443"]
```

`[grants].allow_hosts` and `[network].allow_hosts` are two spellings of one
decision, so declaring both is a parse error. The granted form is the one the
egress gate enforces: the run's network policy is _derived_ from it, never
supplied alongside it, so the policy in force and the policy the plan was signed
over cannot drift apart. An absent egress grant and an empty allowlist both mean
deny-all.

Every grant is bounded by the host operator's ceiling
(`max_cpu_millicores`, `max_memory_mib`, `max_wall_clock_secs` in
`~/.mvm/config/config.toml`), which no surface above can reach and which is
checked before the plan is signed. The ceiling bounds one workload; two further
keys bound the _sum_ across the host — `host_budget_memory_mib` and
`host_budget_cpu_millicores` refuse a boot whose figures, added to every live
machine's admitted charge, would exceed the headroom. Both are unset by
default. The total counts only machines whose supervisor process is actually
alive, so a VM that crashed without cleanup cannot lock the host out, and it
counts each machine's configured maximum rather than its current commitment,
which the memory balloon moves at runtime. `standby_memory_mib` caps the guest
RAM held by idle standbys across all images (2048 MiB by default); when a new
standby would exceed it, the oldest is released first, and standbys are also
kept within the `host_budget_memory_mib` headroom. Separately, `default_cpu_millicores`
and `default_wall_clock_secs` supply defaults for dimensions nothing else named.
There is no host-wide egress default: one would open outbound access for every
workload that never asked for any. Relative manifest volume host paths
are resolved relative to the manifest file; volume validation keeps the shared
default of read-only mounts unless `:rw` is explicit. `--name` is optional: when
omitted, `machine create` auto-generates a name and prints it (mirroring
`machine run -d`).

A host can also admit plans it did not synthesize. By default every plan booted
locally is synthesized and self-signed under the host key at admission time;
a fleet control plane can instead sign an `ExecutionPlan` itself and have a
host boot it, when the operator pins the fleet's issuer key in
`~/.mvm/config/config.toml`:

```toml
[[trusted_plan_signers]]
signer_id = "fleet-prod"              # the signer_id the plan envelope names
ed25519_pubkey_hex = "88a4b2c1046fb3f6a1d3e5c709a2b4d6e8f0a1b3c5d7e9f1a2b4c6d8e0f2a4b6c8"
```

The list is empty by default and the default is the posture: a host that pins
nobody refuses every externally-signed plan. Pinning a key delegates plan
_authorship_, not host policy — the grant ceiling, host budget, validity
window, replay protection, and content-address check above all still apply to
an externally-signed plan unchanged, so a fleet signer cannot ask for more
than the operator's ceiling allows. A pinned entry whose key does not parse
fails the whole admission rather than being silently skipped.

`machine start`, `machine exec`, `machine shell`, and `machine stop` require the
named `MachineSpec` to exist first. `machine start` resolves the stored OCI
image through the normal cache/materialization path, emits the same admission
and OCI provenance audit substrate as the transient image runner, then boots
the named VM with any persisted `mem_initial` and volume settings. When the
stored machine requests outbound egress and is OCI-backed (`machine create
--image`, `machine create --manifest` with an image-backed manifest, or
`machine run -d --image`), `machine start` applies the same NIC-less
host-vsock-proxy backend gate as transient `run --image`: only backends that
honestly advertise `{ vsock, no_routable_guest_nic, host_vsock_proxy }` are
allowed, and incapable backends are refused instead of silently falling back to
a guest NIC helper. `no_routable_guest_nic` is a reachability
guarantee: it holds whether the backend attaches a drained/sinked virtio-net
device with no upstream route or presents no NIC device at all. When the named spec came from an image-backed
manifest, `machine create --manifest`
persists the manifest's `net`, `[network].allow_hosts`, `cpus`, `mem`,
`mem_initial`, `[dev].volumes`, and `[dev].init` fields into the durable
machine spec; relative manifest volume paths are resolved against the manifest
directory when persisted. `dev.init` currently requires
`--profile dev` or `--profile permissive`; standard/prod-like profiles refuse
it. `machine start --dry-run` reports the
effective network posture, enforcement tier, dev-init hash/count,
and redacted volume policy without resolving or booting the image; the signed
machine-start receipt carries the same policy summary plus the resolved digest
and start timestamp after a real boot. `exec` / `shell` / `stop` reuse the
existing console/down paths for the running VM. `machine reconfigure <name>`
patches a subset of the stored config (`net`, `allow_host`, `cpus`, `memory`, and the CLI-only `mem_initial`) and relaunches the machine — auto stop + start when running,
persist-only when stopped; identity, image, and volumes are preserved.
`machine check-artifact` is the read-only gate for a signed `.mvmpkg`: it
streams verification of the signed manifest and every artifact's size and hash,
enforces the size caps (2 GiB per entry, 4 GiB in total), checks posture
coherence (a `sealed-prod` posture must cover a dm-verity rootfs and require
authentication), and confirms the host architecture before printing a preview.
Release verification success (exit 0) is not a launch-readiness or freshness
guarantee. A same-host local build also exits successfully but prints `local
build, signed by this host's key; not release-verified`; JSON reports
`origin: "local-build"`, `verified: false`, and `release_verified: false`.
The read-only preview does not prepare a runtime, apply a revocation feed,
install the archive, or boot a VM. JSON reports `runnable_here: null` (unknown),
`host_arch_compatible: true`, and `backend_compatibility_checked`, which is true
only after at least one embedded image set was actually checked for `--backend`.
Consumers of the former unconditional boolean must handle the nullable field.
Neither cache-file presence nor package-publisher declarations establish
canonical Linux authority or current-policy admission.
The older `.mvm` format and its separate packaging verbs are gone; `mvmctl
build` produces the `.mvmpkg` that `mvmctl run` consumes.

#### Packaging an OCI image

`mvmctl build` resolves an explicitly selected OCI image, materializes its
filesystem, and signs a single architecture-specific `.mvmpkg` with the host
signer:

```sh
mvmctl build docker.io/library/alpine:3.20 --from image \
  --out alpine.mvmpkg --debug-out alpine.bundle.json
mvmctl machine check-artifact ./alpine.mvmpkg
mvmctl run ./alpine.mvmpkg -- /bin/sh
```

The archive above is a host-local build, not a publisher release. Fetching it
through the publisher-verification surface is deliberately refused with exit
code 1; use `machine check-artifact` to inspect it and `run` to launch it locally:

```sh
mvmctl bundle fetch ./alpine.mvmpkg
```

The package carries the workload kernel, rootfs, resolved entrypoint and libc
metadata, universal initramfs, runtime overlay and its verity tree. The kernel
comes from the authenticated Linux image-set pin; the original image-set
manifest is carried unchanged. Runtime assets come from the matching signed CLI
release, with the original archive, checksum and both signature bundles retained
inside the package. Source-built runtime bytes cannot substitute for these
release proofs. Materialization finishes before the CLI loads its host signing
key. The builder never receives the publisher key.

`--arch` accepts `aarch64`/`arm64` or `x86_64`/`amd64` and defaults to the host.
Packaging currently requires the selected architecture to match the host;
cross-architecture runtime injection is refused before acquisition. `--label`
sets the package's display label. The command prints the resolved OCI manifest
digest, bundle SHA-256, signer key ID, architecture, and output path.

`--production` requires a digest-qualified OCI input and produces an actually
dm-verity-sealed rootfs with sealed-production posture. Missing entrypoint
metadata, a platform mismatch, changed materialization bytes, or incomplete
verity metadata is an error before signing. The default is a signed development
package, not an unsigned archive. Production admission still applies its normal
entrypoint, authentication, backend, and security-policy checks.

Both development and production packages construct the rootfs and its verity
data in-process from the verified OCI content. `MVM_MATERIALIZE_BUILDER_VM`
and inputs outside the pure writer's supported limits are refused; packaging
never falls back to an untrusted builder or replaces that seal through one.

`--debug-out` uses the shared bundler's JSON report. YAML and TOML reports are
not currently supported by that shared exporter.

New portable OCI packages use bundle schema 6's explicit CLI-runtime declaration.
The consumer verifies the package signature and inventory, then independently
authenticates the retained CLI-runtime release and checks the prepared overlay,
verity tree and initramfs against its assembly declaration. Consumer launch does
not build, assemble, download or use a producer runtime cache. Readers supporting
only schema 5 or earlier refuse these packages. Existing bundles retain their
existing semantics; CLI and historical boot-asset declarations cannot be mixed.

The package publisher binds the selected kernel bytes to the embedded Linux
manifest. This structural binding is not independent Linux-publisher signature
or current-revocation evidence; applications requiring that stronger authority
must satisfy their separate admission requirements. A successful archive check
alone is not a launch-readiness or protected-observer acceptance result.

Schema 7's closed `canonical_linux_proof` member names the original Linux
manifest and signature plus the original revocation document and signature.
These are inventory references, not a publisher-authored permission or an
evergreen freshness assertion. They must pair with the same Linux manifest
selected by the CLI-runtime member. Older readers refuse the higher schema;
missing, aliased, oversized, orphaned or repeated proof references are refused.
The current plan-admission and client launch paths explicitly refuse this
member until retained selected-kernel backend custody is supported. Recognizing
its structure or verifying its application envelope does not enable execution.
The explicit library preparation API, `launch::canonical_linux::prepare_canonical_linux`,
is separate from archive preview: it snapshots a pinned Unix archive with
bounded streaming I/O, authenticates the original feed and Linux root, verifies
the selected kernel bytes, then applies the signed feed through the existing
rollback-protected consumer store. It reloads effective policy after that update
and whenever checked kernel bytes are requested. Its prepared owner is not a
plan-admission or native-start capability. No command silently opts into that
policy update, and preparation does not remove the launch refusal.

Bundles carrying their own boot assets use the cold-boot path. The current
warm-pool preparation command cannot prepare a parent from an archive's pinned
runtime set, so a portable bundle never substitutes a host-prepared standby.
Repeated launches still reuse the content-addressed installed archive.

#### Booting a signed bundle

A signed `.mvmpkg` boots as the positional source, or through `--manifest`;
the two are the same run:

```sh
mvmctl machine run ./app.mvmpkg -- python -m app
mvmctl machine run --manifest ./app.mvmpkg -- python -m app
```

The archive is verified against the publisher trust store, or against the
current host key when its signed manifest marks it as a local build, and cached
in the bundle registry. The run then continues as
`mvmctl machine run --manifest <bundle-sha256>`, so admission is unchanged: the
plan is synthesized and signed by the host, and the bundle is re-verified at
admit time. A bundle that is already installed is verified again and reused
rather than re-extracted. An unsigned, tampered, or unknown-publisher archive
is refused with the verifier's error before anything boots, and nothing is
written to the registry.

A local build is a development-only exception for a local artifact path. Its
host key is not added to publisher trust, `bundle install` cannot import it,
and registry and application-package ingress cannot supply it. Admission
requires the local-build label and the same host key again; key rotation or a
copied archive therefore fails closed. The signed plan and `plan.admitted`
entry carry `origin=local-build` and the archive's `bundle_sha256`. Diagnostic and
run output calls it `local build, signed by this host's key; not
release-verified`; it is never described as verified, secure, or trusted.

A bundle sealed with `mvmctl build --posture` bounds every launch of it. Before
boot, the run reads the installed bundle's manifest and checks its signature
against the trust store again, without re-hashing the artifacts. It then refuses
a launch that asks for more than the posture allows:

- a network policy that reaches off the host (`--net`, `--allow-host`, `--peer`)
  when the bundle allows no egress;
- a `--volume` when the bundle allows no volumes;
- an interactive, ad-hoc command, or `--profile dev` run of a `sealed-prod`
  bundle.

The refusal is recorded as `plan.failed` with class `bundle-posture-exceeded`.
The posture never grants anything: a bundle that allows egress still boots
deny-all unless the launch asks for egress. A manifest edited on disk after
install fails the signature check and refuses the boot.

#### Environment descriptor

`mvmctl build --environment FILE.json` seals a signed environment descriptor
as the bundle's `environment` member. The descriptor is typed JSON with its own
`descriptor_version` (currently `1`); unknown fields, capabilities, or versions
are refused rather than ignored:

```json
{
  "descriptor_version": 1,
  "pack": { "name": "acme/agent", "version": "1.2.3" },
  "target": "x86_64-linux",
  "entrypoint": { "argv": ["/usr/bin/agent"], "working_dir": "/workspace" },
  "resources": { "cpu_cores": 2, "memory_mb": 2048 },
  "volumes": [{ "name": "workspace", "guest_path": "/workspace" }],
  "secret_slots": [{ "name": "AGENT_TOKEN", "required": true }],
  "capabilities": ["egress", "host_volumes"],
  "services": [{ "name": "indexer", "argv": ["/usr/bin/indexer"] }]
}
```

A bundle carrying the descriptor is stamped bundle schema 5; readers that
predate it refuse it at the schema check. Bundles without one keep the schema
their other members need and verify and launch as before. Verification refuses
a descriptor whose `target` is not the bundle's architecture, and any required
capability (`egress`, `host_volumes`, `interactive_terminal`) the bundle's
`--posture` does not permit — a descriptor that requires a capability needs a
posture beside it. Volumes require `host_volumes`. Secret slots are names only:
a slot carrying a value, or an argv that passes a secret-shaped flag or a slot
inline (`TOKEN=...`, `--api-key=...`), is refused.

At launch of an installed bundle:

- the descriptor's resources become the defaults for whichever of `--cpus` and
  `--memory` the command line did not name; the host's memory ceiling and
  admission budget still apply and refuse rather than clamp;
- a required secret slot with no `--secret` binding refuses the launch; the
  value stays on the host and is substituted at the endpoint, as for any
  binding;
- an image whose recorded entrypoint differs from the descriptor's refuses the
  launch; missing, malformed, or empty entrypoint metadata also refuses an
  ordinary launch. An ad-hoc command replaces the entrypoint explicitly and is
  not compared, but remains subject to the launch's posture and command rules;
- a capability beyond a posture the launch is held to refuses the launch.

The current launcher also refuses a nonempty `services` or `volumes` requirement,
or an `entrypoint.working_dir`. It cannot yet establish the declared application
processes, match required named mounts, or enforce the declared working
directory. These fields remain signed, verified and inspectable, but are not
silently treated as fulfilled. An explicit ad-hoc command does not bypass these
requirements. A descriptor with those fields absent (or empty lists) keeps the
entrypoint, secret and posture checks above.

Transient and persistent starts use the same entrypoint checks. Checkpoint and
fork paths that cannot establish the image entrypoint refuse a descriptor-bearing
bundle rather than treating failed resolution as an explicit override.

These refusals are recorded as `plan.failed` with class
`bundle-environment-refused`. Application `services` are guest processes,
distinct from the broker's host services named by `--host-service`; they are
recorded and shown by `bundle fetch`, not started as broker services. Passing
`--host-service` or `--volume` does not prove these signed requirements and does
not bypass their refusal. Bundles without an environment descriptor retain
ordinary `--volume` behavior under the posture's ceiling.

`.mvmpkg` is the one extension for a runnable artifact. `mvmctl build` writes
the same archive that `bundle install`, `machine check-artifact`, and `run`
read; there is no second container format.

A positional source is unambiguous because the guest command only ever follows
`--`: `mvmctl machine run ./app.mvmpkg` names a bundle, and running a program
called `./app.mvmpkg` is `mvmctl machine run -- ./app.mvmpkg`. As a positional
or after `--manifest`, a path ending in `.mvmpkg` that is not a directory is read
as an archive; every other `--manifest` argument keeps its existing meaning.

### Lineage / time-travel

`mvmctl machine timeline` / `revert` / `rewind` / `advance` are the advanced
lineage and time-travel verbs over the checkpoint and image-node stores.
`timeline` is a read-only navigator; the three restore verbs each launch a
fresh, **re-admitted** VM at a prior (or adjacent) state rather than mutating
one in place. Every verb verifies its target against the signed audit chain up
front and fails closed on an un-audited, tampered, or dangling record — the same
gate `machine checkpoint verify` and `machine checkpoint fork` enforce. A
completed checkpoint restore emits a chain-signed `checkpoint.restored` entry
and an image restore an `image.reverted` entry, each carrying the initiating
verb (`revert` / `rewind` / `advance`) as its `via` label.

Full-VM captures also record the runtime configuration observed while the
backend is paused. An external runtime must match an authenticated, retained
runtime generation; a launch metadata file alone is not sufficient. Restore
and fork authenticate the checkpoint first, then reverify that generation and
the captured runtime evidence before loading it. Older full-VM checkpoints
without this evidence are refused with a recapture instruction. This does not
replace the base-image integrity or admission checks for runtimes baked into
the root filesystem. Retained runtime artifacts and release proofs must remain
available for later restores. Restoring a checkpoint does not turn its inherited
RAM into a newly measured boot; runtime evidence must retain that distinction.

Firecracker runtime observation supports repository-managed devices with
canonical `blk{slot}` identifiers. Capture and restore bind their complete
device layout, including writable devices, and recheck read-only backing
bytes before resuming. The identifiers preserve the managed launch's device
mapping when Firecracker returns restored configuration in a different array
order. This is verified configuration lineage under the protected host-state
boundary, not an independent measurement of loaded guest RAM or MMIO slots.
Arbitrary unmanaged Firecracker device identifiers are refused.

A target is a checkpoint id or a `sha256:<hex>` content-address; a digest may
name a node in the checkpoint store, the image store, or (rarely) both, in which
case `--kind checkpoint\|image` disambiguates it. Image nodes have no id — their
identity is their digest. `--new-id` and `--hypervisor` apply to checkpoint
restores only; an image restore auto-names its VM and re-runs the node's
digest-pinned reference through the admitted `machine run` path.

| Command                                                                                                                                    | Description                                                                                                                                                                                                                                                                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl machine timeline <id\|digest> [--kind checkpoint\|image] [--json]`                                                                 | Render a checkpoint or image node's lineage — ancestors back to genesis plus its immediate children — verifying each hop against the signed audit chain. Read-only: no restore, no admission, no boot. A tampered, un-audited, or dangling hop is marked (and the overall verdict fails), but the timeline still renders so it stays usable for navigation. |
| `mvmctl machine revert <id\|digest> [--kind checkpoint\|image] [--hypervisor <backend>] [--new-id <name>] [--json]`                        | Restore a prior state: launch a fresh, re-admitted VM at the node the target names. Checkpoint restores fork a new VM identity (`--new-id` names it; `--hypervisor` picks the backend, default `firecracker`); image-node restores re-run the node's digest-pinned reference through the admitted run path and auto-name their VM.                          |
| `mvmctl machine rewind <id\|digest> [--kind checkpoint\|image] [--hypervisor <backend>] [--new-id <name>] [--json]`                        | Restore the target's parent — one step back in the lineage. Same re-admission and fail-closed guarantees as `revert`; refuses a genesis root (no parent) or a structurally broken lineage.                                                                                                                                                                  |
| `mvmctl machine advance <id\|digest> [--to <child-digest>] [--kind checkpoint\|image] [--hypervisor <backend>] [--new-id <name>] [--json]` | Restore a child of the target — one step forward. Forward is a tree, so `--to <child-digest>` is required when the target has more than one child (a fork). Same re-admission and fail-closed guarantees as `revert`.                                                                                                                                       |

### Fork / restore

`mvmctl machine fork` and `mvmctl machine restore` are the agent-facing
primitives for branching a running machine or an existing `vm_full` checkpoint
into a fresh child VM. Both capture/branch through the consolidated
`VmBackend`/checkpoint seam and deliver a new identity, authority, and
per-instance secrets; the parent carries no workload authority into the child.
Use `--as <name>` for an explicit child name or `--branch <slug>` for an
auto-generated dev-sandbox name. The lower-level `machine checkpoint fork` and
`machine checkpoint restore` surfaces remain available for power users.

## Sandbox State

| Command                               | Description                                                                       |
| ------------------------------------- | --------------------------------------------------------------------------------- |
| `mvmctl machine sandbox gc`           | Dry-run cleanup of stale sandbox name-registry entries for stopped or expired VMs |
| `mvmctl machine sandbox gc --dry-run` | Explicit dry-run; reports candidates and does not mutate state                    |
| `mvmctl machine sandbox gc --apply`   | Remove stale stopped/expired registry entries and emit a `SandboxGc` audit entry  |
| `mvmctl machine sandbox gc --json`    | Print a machine-readable GC summary with candidates, reasons, and removed count   |

`sandbox gc` never tears down a live VM. Entries that still appear as starting,
running, or paused in a backend listing are skipped; cleanup only removes stale
host registry records.
`--json` does not change the safety mode: cleanup remains dry-run unless
`--apply` is also passed.

## Checkpoint

`mvmctl machine checkpoint` is the advanced checkpoint store surface for
list/remove/fork/diff and explicit class selection. Recovery tiers are
backend-specific; inspect `mvmctl doctor` before requesting one. Unsupported
save/restore and warm-start requests fail with an actionable error rather than
silently selecting a weaker tier.

| Command                                                                                      | Description                                                                                                                                                                                                                                                                   |
| -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl machine checkpoint create <name> [--class fs-quick\|vm-full] [--tag <tag>] [--json]` | Capture a checkpoint. `--class vm-full` saves full machine state (memory + disk) via HVF's `saveMachineStateToURL`. Records content hash in the audit chain.                                                                                                                  |
| `mvmctl machine checkpoint restore <checkpoint> [--json]`                                    | Restore a previously created `vm_full` checkpoint into the original VM identity. Re-hashes content against the recorded metadata before loading.                                                                                                                              |
| `mvmctl machine checkpoint fork <checkpoint> [--new-id <name>] [--boot] [--json]`            | Restore a checkpoint into a new VM identity (new name, separate audit lineage). `vm_full` forks auto-boot; `fs_quick` forks boot only with `--boot`.                                                                                                                          |
| `mvmctl machine checkpoint ls [--json]`                                                      | List checkpoints.                                                                                                                                                                                                                                                             |
| `mvmctl machine checkpoint diff <a> <b> [--json]`                                            | Compare two checkpoint metadata/content manifests.                                                                                                                                                                                                                            |
| `mvmctl machine checkpoint verify <checkpoint> [--json]`                                     | Verify a checkpoint's full lineage against the signed audit chain (recomputed content-address must match both the stored `meta_digest` and the digest signed at creation, at every hop). Exits nonzero on any drift, chain mismatch, missing signed entry, or broken lineage. |
| `mvmctl machine checkpoint rm <checkpoint> [--json]`                                         | Delete a checkpoint and its blobs.                                                                                                                                                                                                                                            |

Checkpoint blobs are stored under the configured checkpoint store (`MVM_HOME` / `~/.mvm` via the core path helpers). The audit chain records `checkpoint.created`, `checkpoint.restored`, and `checkpoint.forked` entries with content hashes; restore and fork refuse tampered checkpoint content before booting.

The rootfs and memory image are stored as 1 MiB chunks shared, by hard link, with every other checkpoint of the same tenant that holds the same bytes; each blob's recorded hash is the digest of its chunk index. A checkpoint from a pre-release that stored those images as whole files is refused by restore and fork, with a message naming it. Remove it with `mvmctl machine checkpoint rm <checkpoint>` and capture the machine again; there is no migration.

## Durable Agent Sessions

`mvmctl agent-session` is the operator surface for durable agent sessions: an
agent session outlives the sandbox that runs it, parking (releasing its
sandbox) and resuming later as a fresh admission. It is deliberately not
spelled `session` — `mvmctl machine session` already means machine-session
residency, a warm VM kept alive across `invoke` calls, which is a different
concept over a different store.

| Command                                                                                                                                                                                                                                | Description                                                                                                                                                                                                                                     |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl agent-session open <id> [--resume-point <sha256:...>] [--member <name>]...`                                                                                                                                                    | Record a new session, resident from the start, at generation 1. Refuses if a record already exists under that id. `--member` is repeatable.                                                                                                     |
| `mvmctl agent-session ls [--json]`                                                                                                                                                                                                     | List every session recorded on this host, one summary line each: id, generation, residency, and — when parked — reason, storage tier and whether the retention deadline is alive or expired.                                                    |
| `mvmctl agent-session show <id> [--json]`                                                                                                                                                                                              | Print one session's recorded state in full: residency, generation, storage tier, park reason, journal cursor, retention deadline and its status, resume point, approval head, members, timestamps. An absent session is an error naming the id. |
| `mvmctl agent-session park <id> --reason <reason> [--journal-cursor <n>] [--approval-head <sha256:...>] [--retain-for <duration>] [--expected-generation <n>] [--json]`                                                                | Release an active session's sandbox. `--reason` is one of `approval-wait`, `idle`, `host-shutdown`, `operator`, `retention-demotion`, and selects the storage tier and the default retention deadline. Emits a `session.parked` chain entry.    |
| `mvmctl agent-session resume <id> --backend <name> --image <ref> --image-sha256 <hex> --cpus <n> --mem-mib <n> [--kernel-sha256 <hex>] [--approval-head <sha256:...>] [--boot [--kernel <path>]] [--expected-generation <n>] [--json]` | Re-admit a parked session under a freshly signed `ExecutionPlan`. Emits a `session.resumed` chain entry.                                                                                                                                        |
| `mvmctl agent-session renew <id> --for <duration> [--expected-generation <n>] [--expected-deadline <unix>] [--json]`                                                                                                                   | Move a parked session's retention deadline to `--for` from now. Extend-only. Emits a `session.renewed` chain entry.                                                                                                                             |
| `mvmctl agent-session replay <id> [--from <checkpoint>] [--as <name>] [--dry-run] [--timeout <secs>]` | Verify the session's step timeline against the signed audit chain, fork-boot a checkpoint on it (default: the session's base, recorded before its first prompt) and re-deliver every prompt recorded after it to the fork's agent, in journal order. Each re-delivery is grant-checked against the fork's plan, chain-audited with `delivery=replay`, and recorded in the fork's ledger so a re-run never sends a prompt twice. The session and its machine are untouched. The fork is a machine in its own right: a prompt to it is recorded and step-checkpointed under the fork's own session, which replays in turn |

`open` is what gives the other four subcommands something to act on: `park` and
`resume` both need a record that already exists, and nothing else on the host
writes one.

`resume` takes the workload material — backend, image reference, rootfs and
kernel SHA-256, vCPUs, memory — as flags because the session record
deliberately does not carry it. An image, a kernel and a sandbox size each
change on their own schedule, and recording them in the record would make it a
second copy of the plan that has to be kept in step with one. Deriving them
from the resume point's supervisor config instead is a later step; taking them
as flags keeps the seam visible rather than guessing.

A resume stops at an admitted plan. It does not restore a memory image and does
not boot a sandbox — the command says so on completion.

`--approval-head` on `resume` is the operator's assertion of where the approval
ledger is _now_. The store refuses when it differs from the head recorded at
park time, so a session cannot silently resume under grants it was never
admitted for. A session parked without a head resumes unfenced, and
`agent-session show` says so in as many words.

### Retention deadlines

A park sets a retention deadline: the time until which the host promises to
keep the parked session resumable. `--retain-for` names it (`30m`, `48h`, `7d`,
at most `30d`). Without it the reason picks a default:

| Reason               | Default | Why                                                 |
| -------------------- | ------- | --------------------------------------------------- |
| `approval-wait`      | 24h     | the longest an approval can live                    |
| `idle`               | 30m     | the standby TTL a resident sandbox is reaped on     |
| `host-shutdown`      | 48h     | starting proposal, not measured                     |
| `operator`           | 48h     | starting proposal, not measured                     |
| `retention-demotion` | 30d     | the record-and-journal tier costs kilobytes to hold |

`renew --for <duration>` moves the deadline to that long from now, and only
ever later. It refuses if the new deadline would end before the current one,
if the deadline has already passed (the session is past its promise), and if
the session is active or closed. `ls` and `show` report the deadline as
`alive` or `expired`. Under `--json` they add a `retention` object with `state`
and either `remaining_secs` or `expired_for_secs`.

A deadline is a promise, not an enforcement. Nothing reclaims a session when its
deadline passes, and an expired session still resumes. No demotion yet actually
releases what a lower storage tier claims to, so no scheduler demotes on expiry.

Successive renewals of one parked session share a generation. A renew retry
therefore needs `--expected-deadline` as well as `--expected-generation` to be
recognised as a replay. The deadline is the value `show` prints. Without both, a
retry is applied as a new renewal.

### Retrying after a lost response

A caller whose `park` or `resume` applied but whose response never arrived
cannot tell that apart from one that did not apply. `--expected-generation`
makes the retry safe. Pass the generation you read the session at (as `show`
prints it) and repeat the command unchanged:

- If that exact transition already applied, the command returns its original
  result marked as a replay — `replay: this park had already applied` in text,
  `"replayed": true` under `--json` — writes nothing, and adds no audit entry.
  A replayed `resume` reports the plan the original was admitted under and
  admits no second one.
- If the same step was taken with different inputs (another `--reason`, other
  plan material, `--boot` added or dropped), the command refuses and names each
  input that differs. It never applies a second transition.
- If the session has since moved past that generation, the command refuses
  naming the current generation and the transition that moved it.

The same rules apply to `renew`, which also needs `--expected-deadline` (see
above).

The identity a retry is compared by is a SHA-256 over a domain-separation tag
and length-prefixed fields: the transition kind, the session, the observed
generation, and every input that decides the outcome — for `park` the reason,
journal cursor, approval head and retention; for `renew` the observed deadline
and the extension; for `resume` the approval head, backend,
image, image and kernel SHA-256, vCPUs, memory, and whether it boots.
Timestamps are not part of it. Only the session's last transition is kept, so a
retry of anything older is refused as superseded.

Without `--expected-generation` the generation is read at call time. That fences
nothing, and a retry cannot be recognised: a second `park` refuses because the
session is no longer active, and a second `resume` refuses because it is no
longer parked.

`resume --boot` is never replayed. A retry of a boot resume that already applied
is refused with a message saying it applied and under which plan: the record
moves before the boot is attempted, so it cannot say whether that boot
succeeded, and answering "booted" from it would claim something it does not
know. Check the machine named after the session directly.

All three chain entries are best-effort: if the entry cannot be written the
transition is still reported as done, with a warning, because the store write
already succeeded and failing afterwards would tell an operator a park did not
happen when it did. A caller that needs the entry must verify the chain
separately.

## File Copy

| Command                                             | Description                                                               |
| --------------------------------------------------- | ------------------------------------------------------------------------- |
| `mvmctl machine cp <host-path> <vm>:/absolute/path` | Copy one regular file from the host into a running VM                     |
| `mvmctl machine cp <vm>:/absolute/path <host-path>` | Copy one regular file from a running VM to the host                       |
| `mvmctl machine cp --force <src> <dst>`             | Overwrite an existing destination                                         |
| `mvmctl machine cp --create-parents <src> <dst>`    | Create destination parent directories                                     |
| `mvmctl machine cp --max-bytes <n> <src> <dst>`     | Refuse copies larger than the byte cap. Default: 16 MiB                   |
| `mvmctl machine cp --json <src> <dst>`              | Print a machine-readable copy summary without host paths or file contents |

Exactly one endpoint must use `VM:/absolute/path` form. Guest paths are
validated by the guest agent's filesystem policy before any read or write. Host
paths and file contents are not written to audit logs; successful copies emit
`VmFileCopy` with direction, guest path, and byte count.
`--json` follows the same redaction rule: the summary includes direction, VM
name, guest path, copied byte count, and effective copy options, but not the
host endpoint.

### Handing results back (`--output`)

`--output HOST_DIR:/GUEST[:SIZE[:MAX_ENTRIES]]` is how a transient run returns
files. It is not a share: nothing on the host is visible to the guest. The guest
gets a new, empty ext4 disk mounted writable at `/GUEST` (which must sit under
the same guest-mount allow-roots as `--mount`), and the workload writes there.
When the workload exits — whatever its exit code — its filesystem is flushed,
the VM is torn down, and the host reads the disk image in-process. There is no
protocol with the guest to speak.

Collection accepts only regular files and directories. It refuses, and writes
nothing, when the disk holds a symlink, device node, FIFO, or socket; a name
that is empty, `.`, `..`, not UTF-8, or contains `/` or NUL; a directory entry
whose type disagrees with its inode; a path deeper than 64 components or longer
than 4096 bytes; more file bytes than `SIZE`; or more entries than
`MAX_ENTRIES`. The refusal names the rule or bound that fired. `HOST_DIR` must
be absent or empty and its parent must exist; files are created exclusively
through directory handles that never follow a link, so nothing is overwritten
and nothing lands outside `HOST_DIR`. File permissions are not carried over
(files are `0644`, directories `0755`).

A file hard-linked under two names inside the disk is collected as two
independent host files, each counted against `SIZE` — the ext4 reader does not
expose inode identity, so the link cannot be refused, but the host never
receives an alias.

The grant — guest path, resolved `HOST_DIR`, and both bounds — is recorded in
the signed execution plan before boot. After collection a chain-signed
`plan.outputs` audit entry records `outcome=collected` with `manifest_sha256`,
`entry_count`, `total_bytes`, and `tree_sha256` (the identity `--asset` would
compute for `HOST_DIR`, so a later run consuming these files names them the
same way), or `outcome=refused` with the rule's `reason`. The full manifest —
every `(path, size, sha256)` sorted by path — is written beside the outputs as
`HOST_DIR.manifest.json`, which must not already exist.

```bash
mvmctl machine run --image alpine --output ./results:/data/out:16M \
  -- sh -c 'echo done > /data/out/status.txt'
cat ./results/status.txt ./results.manifest.json
```

### Run examples

Read-only sized disk mounts require an existing ext4 image. A missing or empty
read-only image is refused, not created or formatted.

```bash
mvmctl run -- uname -a                                # default image
mvmctl run --manifest minimal -- /bin/true            # named template
mvmctl run --mount .:/work:ro -- ls /work            # snapshot current dir into an image, RO
mvmctl run -e DEBUG=1 -- env | grep DEBUG             # env var injection
mvmctl run --launch-plan ./launch.json                # launch-plan entrypoint
```

### Launch-plan shape

`--launch-plan` accepts either of two JSON shapes — the shape is
auto-detected. Only the entrypoint is consumed (image selection
still comes from `--manifest` or the bundled default in v1). Both
shapes were historically produced by the `mvmforge` toolchain
([migration guide](/guides/mvmforge-migration/)); `mvmctl dev compile`
is the canonical producer today.

**LaunchPlan artifact** (top-level `entrypoint`):

```json
{
  "artifact_format_version": "1.0",
  "workload_id": "hello",
  "entrypoint": {
    "command": ["python", "main.py"],
    "working_dir": "/app",
    "env": { "PORT": "8080" }
  },
  "env": { "LOG_LEVEL": "info" }
}
```

**Workload IR manifest** (top-level `apps[]`):

```json
{
  "apps": [
    {
      "name": "hello",
      "entrypoint": {
        "command": ["python", "main.py"],
        "working_dir": "/app",
        "env": { "PORT": "8080" }
      },
      "env": { "LOG_LEVEL": "info" }
    }
  ]
}
```

Multi-app IR manifests are rejected — that's an orchestration concern
that belongs in `mvmd`, not in `mvmctl run`. Env precedence (lowest →
highest): top-level/app `env` → `entrypoint.env` → CLI `--env`.
Launch-plan env is checked like `--env`: a key must be a plain shell name
(`[A-Za-z_][A-Za-z0-9_]*`), and a loader, shell, interpreter, or
password-manager session variable refuses the run unless `--allow-env NAME`
re-admits it by exact name.

### Snapshot restore

When the request boots a registered template (`--manifest <name>`) and
that template has a compatible recovery artifact, `mvmctl run` uses the
selected backend's advertised recovery tier instead of cold-booting.

The snapshot path activates only when _all_ of the following hold:

- the image source is a **registered template** (the bundled default
  image has no template snapshot to restore from);
- there are **no** live directory shares (extra drives would mismatch the
  snapshot's recorded drive layout);
- the active backend reports snapshot support.

Recovery tiers are not interchangeable. Unsupported live-memory,
machine-state, disk-only, or standby requests fail with an actionable error;
the CLI does not silently fall back to a weaker tier. See the [Sandboxed
Exec](/guides/exec/) guide for the full background.

## Volumes

| Command                                                                                               | Description                                                                              |
| ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `mvmctl machine volume create <name>`                                                                 | Create a locked mvm-managed encrypted local volume archive                               |
| `mvmctl machine volume create <name> --root <absolute-dir>`                                           | Create the mvm-managed encrypted volume under a specific root                            |
| `mvmctl machine volume create <name> --host-backed`                                                   | Create the previous host-backed managed directory, requiring encrypted backing storage   |
| `mvmctl machine volume unlock <name>`                                                                 | Decrypt a managed volume into its plaintext mount directory                              |
| `mvmctl machine volume lock <name>`                                                                   | Seal a managed volume back into its encrypted archive and remove plaintext               |
| `mvmctl machine volume catalog`                                                                       | List managed local volumes                                                               |
| `mvmctl machine volume catalog --json`                                                                | List managed local volumes as JSON                                                       |
| `mvmctl machine volume mount <vm> --volume <name> --guest <absolute-path>`                            | Register an unlocked managed local virtio-fs volume mount for a VM. Read-only by default |
| `mvmctl machine volume mount <vm> --volume <name> --host <absolute-dir> --guest <absolute-path>`      | Register an ad-hoc encrypted host directory as a virtio-fs volume mount                  |
| `mvmctl machine volume mount <vm> --volume <name> --host <absolute-dir> --guest <absolute-path> --rw` | Register the volume read-write                                                           |
| `mvmctl machine volume ls <vm>`                                                                       | List registered volume mounts                                                            |
| `mvmctl machine volume ls <vm> --json`                                                                | List registered volume mounts as JSON                                                    |
| `mvmctl machine volume unmount <vm> <guest-path>`                                                     | Remove a registered volume mount                                                         |

Guest destinations must be at or under `/data` or `/work`. Every destination
component must be a real directory, not a symlink, including components inside
earlier attached volumes. Mounts use pinned directory descriptors rather than
reopening a validated pathname. This requires Linux 5.2+ mount APIs; unavailable
support fails closed. See [Persistent workspaces](/guides/persistent-workspaces/)
for local sources and tenant-managed `mvmd` volumes.

Managed local volumes are encrypted by mvm at rest. `volume create` writes a
locked AES-256-GCM encrypted archive plus wrapped per-volume data key metadata
in `~/.mvm/volumes/registry.json`; it does not leave a plaintext directory
behind. `volume unlock` decrypts that archive into a private plaintext mount
directory, `volume mount` refuses the volume while it is locked, and
`volume lock` reseals the directory and removes plaintext after use.

Ad-hoc `--host` mounts and `--host-backed` managed volumes keep the previous
host-backed model: the exact host directory must live on encrypted backing
storage, either a macOS volume that `diskutil` reports as encrypted or a Linux
filesystem whose backing device sits on dm-crypt/LUKS. Those commands fail
closed when mvm cannot confirm that backing storage.

## Default microVM Image

When an image-taking command is invoked without `--flake` or `--manifest`,
`mvmctl` falls back to a bundled minimal image (busybox + the guest agent).
This applies to:

- `mvmctl run -- <cmd>` — boots a fresh transient microVM and runs `<cmd>`
- `mvmctl machine run` — boots a long-running microVM with the same image

The image is the bundled default — a minimal `mkGuest` rootfs shipped
with mvm. Built via Nix on first use, cached at
`~/.mvm/cache/default-microvm/` (kernel + rootfs). To customize, pass
`--manifest` or `--flake` pointing at your own project's `mkGuest`
output (see [Building MicroVM Images](/guides/building-microvm-images)).

Build resolution order on first use:

1. **Builder VM.** mvm bootstraps or reuses the project Linux builder VM,
   runs Nix evaluation and `nix build` inside it, and extracts the rootfs.
   No host-side Nix is required, and there is no interactive step to
   perform first — the builder VM is headless and builds unattended.
   `mvmctl bootstrap` can pre-warm it ahead of time if you'd rather not
   wait on the first build.
2. **Prebuilt artifacts (offline).** If the host is fully offline and the
   builder image is not available, mvm can use the prebuilt
   `default-microvm` artifacts from the GitHub release matching the
   `mvmctl` version, hash-verified per the `*-checksums-sha256.txt`
   manifest (security claim 6).

See [Builder VM](/guides/builder-vm/) for the host-orchestrated build
flow and the distinction between build time and runtime boot time.

## Cache

| Command                              | Description                                                                                                                                                                                                                                       |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl cache info`                  | Show cache directory path, disk usage, and a per-entry footprint breakdown (entries belonging to a removed subsystem are flagged `retired`). Sizes are allocated blocks with symlinks and repeated hardlinks counted once, so they match `du -sh` |
| `mvmctl cache prune`                 | Remove stale temp files; report (but don't delete) retired top-level cache dirs                                                                                                                                                                   |
| `mvmctl cache prune --dry-run`       | Show what would be removed without deleting                                                                                                                                                                                                       |
| `mvmctl cache prune --orphan-builds` | Also sweep orphaned builds — built artifacts whose source `mvm.toml` is gone (equivalent to `mvmctl manifest prune --orphans`)                                                                                                                    |
| `mvmctl cache prune --orphan-dirs`   | Also remove retired top-level cache dirs — leftovers from a subsystem mvm no longer has. Only names on the built-in retired list are candidates; a cache still in use is never removed                                                            |
| `mvmctl cache prune --deep`          | Reclaim regenerable caches too — Stage 0 blobs, the prebuilt default microVM image, pulled OCI layers (each costs a re-fetch/rebuild next time). Implies `--orphan-dirs` and `--stage0-store`                                                     |
| `mvmctl cache prune --stage0-store`  | Remove only the Stage 0 Nix store image, keeping the builder image it produced. The next bootstrap starts cold. Refuses while a bootstrap is running                                                                                              |
| `mvmctl cache repair`                | Clear a degraded builder VM store so the next build cold-rebuilds it. Refuses while a Stage 0 bootstrap is in flight; auto-stops a running builder VM first                                                                                       |
| `mvmctl cache repair --force`        | Clear the store even while a Stage 0 bootstrap lock is held (use only if the lock is stale, e.g. after a crash)                                                                                                                                   |

## Workload Authoring and Inspection

These verbs operate on a workload before and after it runs, rather than on a
running microVM.

| Command                                | Description                                                                                                                                                               |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl init`                          | Scaffold a new project (`mvm.toml` alongside your `flake.nix`)                                                                                                            |
| `mvmctl generate sdk <script>`         | Generate a runnable project from an SDK-decorated `.py`/`.ts` source: parses the decorator, emits `flake.nix` + `launch.json`, bundles the source tree into `--out <dir>` |
| `mvmctl template list`                 | List available templates (bundled plus cached remote)                                                                                                                     |
| `mvmctl template search <query>`       | Search the remote registry for matching templates                                                                                                                         |
| `mvmctl template info <name>`          | Show details for one bundled or remote template                                                                                                                           |
| `mvmctl generate template <name> <dir>` | Scaffold a remote template, including local policy files and versioned signed-pack group includes; referenced packs must already be installed and verifiable |
| `mvmctl deploy <ir.json> --boot-artifact <path>` | Build, seal, and record a workload into a local deployment directory (`image.tar.gz`, `rootfs.ext4`, `deploy.json`); optionally ship it to mvmd with `--mvmd-url` |
| `mvmctl deploy --from-ir <path> --boot-artifact <path>` | Read the Workload IR from a file instead of a positional path or stdin; a boot artifact is still required |
| `mvmctl deployments ls`                | Inventory of recorded local deployments (`--workload <ir-hash>` to filter, `--json` for machine output); unreadable records surface as named skips                        |
| `mvmctl prepare`                       | Report whether a verified runtime pack is ready for instant launch                                                                                                        |
| `mvmctl plugin list`                   | List the coding agents mvm can emit an integration for                                                                                                                    |
| `mvmctl plugin install <agent>`        | Write that agent's integration files into the project (`--dir`, `--dry-run`, `--force`). Emits config only — mvm runs no agent-facing server                              |
| `mvmctl bench`                         | Measure this host's launch latency against the published budgets, printing each percentile beside the budget it is judged against                                         |
| `mvmctl bench --lane <lane>`           | Pick the lane: `prepared-cold` (default), `prepared-cold-mount-hit`, `mount-miss`, `artifact-miss`, `warm-claim`                                                          |
| `mvmctl bench --runs <n> --warmup <n>` | Sample counts. Below 20 measured runs the report is indicative only, not publication-grade                                                                                |
| `mvmctl bench --json`                  | Emit the versioned report JSON — the same shape the CI gate produces, so the two are comparable                                                                           |
| `mvmctl bench -- <launch>`             | Measure a specific launch instead of the reproducible default (`run --no-detect -- /bin/true`)                                                                            |
| `mvmctl explain <run>`                 | Explain a run and its egress refusals from the chain-signed audit log: each refused destination, its count, and how to allow it where a grant can                           |
| `mvmctl explain <run> --review [--project PATH]` | Open the same Grant / Skip review used after a foreground run. Only grantable denials from a verified audit chain are offered; selected grants are shown as a draft and require a second confirmation before `mvm.toml` changes. `PATH` is a project directory or its manifest file; a foreground run that cannot review in place prints this command with its plan id |
| `mvmctl watch <ir.json>`               | Rebuild a workload when its local inputs change                                                                                                                           |

## Packs, Bundles, and Dependencies

Pack discovery reads only root `index.json` with `schema_version: 2`. Versions
are catalog objects containing `version` and `manifest_sha256`; search displays
their version strings. Pull checks the catalog digest against exact manifest
bytes before adoption or installation. This untrusted discovery hash does not
replace publisher signatures or existing authenticated installed pins.

| Command                                                   | Description                                                                                                                                                       |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl pack ls [--json]`                                 | List pinned registry products with their kind (`application` or `policy`) and whether each is installed                                                                                                          |
| `mvmctl pack rm ns/name[@version]`                        | Remove a registry product's cache entry and lock pin; a supplied version must match the pin. An application's installed bundle stays in the shared bundle store                                                                           |
| `mvmctl pack update ns/name[@version]`                    | Re-pull a signed workload pack and its signed profile dependencies, adopting a newer published version when available                                             |
| `mvmctl pack system list [--kind KIND] [--json]`          | List every recorded builder, runtime, image-project, or extension pack version, marking each active one                                                            |
| `mvmctl pack system rollback KIND [--to VERSION]`        | Point a system pack class's active version at an already-cached one                                                                                                |
| `mvmctl pack system prune [--keep-recent N] [--dry-run]`   | Reclaim non-active system pack versions beyond the newest N per key                                                                                                |
| `mvmctl pack system download KIND`                        | Fetch a system pack version into the cache without changing the active one; no system pack class is published yet                                                  |
| `mvmctl pack system update KIND`                          | Fetch and activate a system pack version; no system pack class is published yet                                                                                    |
| `mvmctl pack info ns/name[@version] [--json]`             | Re-verify a pinned registry product. Legacy packs show publisher, policy, image, and payload details; applications show the authenticated descriptor and independently verified local bundle archive identities |
| `mvmctl pack verify ns/name[@version] [--json]`           | Recheck the exact pin, current publisher and revocation policy, and legacy payload or application bundle archive; report verification scope or fail closed, without fetching or installing |
| `mvmctl pack lock SPEC.json --mvm-revision COMMIT [--out FILE \| --stdout]` | Resolve an authored `mvm.pack-spec/v1` document against its source tree and write the frozen `pack.lock.json` beside it: spec, source snapshot and lowered-workload digests, compiler version and the pinned mvm commit. A uv `pyproject.toml` + `uv.lock` at the source root is resolved here for the pack's target and its single `python3NN` runtime package: one sha256-pinned manylinux wheel per runtime dependency, recorded in the lowered workload. Non-registry sources, markers the target does not decide, an unsatisfied `requires-python` and packages without a compatible wheel are refused by name. The spec is read as data; no author code runs |
| `mvmctl pack compile SPEC.json --out DIR [--lock FILE]` | Compile a pack spec into a flake artifact only when its lock still matches; a missing lock or any stale field (named in the error) is refused before anything is written. A pack with uv dependencies also gets `pack-build.json`, the resolved wheel set the flake fetches and installs at build time |
| `mvmctl pack search [QUERY] [--json]`                     | Search the pack registry and mark installed packs; same behavior as `mvmctl search`                                                                               |
| `mvmctl pack pull ns/name[@version] [--json]`             | Authenticate, install, and pin a registry product. Application descriptors additionally bind an independently trusted bundle; application JSON reports `status: "installed"`, `installed: true`, descriptor `manifest_sha256`, `bundle_sha256`, and `key_id` only after the reference commit. Same trust policy and behavior as `mvmctl pull` |
| `mvmctl pack registry ls`                                 | Compatibility spelling of `pack ls`                                                                                                                               |
| `mvmctl pack registry rm ns/name[@version]`               | Compatibility spelling of `pack rm`                                                                                                                               |
| `mvmctl pack registry update ns/name[@version]`           | Compatibility spelling of `pack update ns/name[@version]`                                                                                                         |
| `mvmctl pack registry revocations update --document PATH --bundle PATH [--official]` | Verify and cache a signed revocation feed. Without `--official`, use the operator-configured release identity with at most 48-hour validity. With `--official`, require the dedicated `tinylabscom/mvm-packs` `registry-pack-revocations.yml` identity with at most 30-day validity. Both paths reject expired feeds and advance a rollback-resistant checkpoint. |
| `mvmctl search [QUERY]`                                   | Search the signed pack registry, marking installed packs (`--json`)                                                                                               |
| `mvmctl pull ns/name[@version]`                           | Fetch, verify against the publisher trust policy, install, and pin a signed registry pack and every pack its signed profile references. A built-image pack also downloads its fixed-name immutable release assets, checks their descriptor-pinned lengths and digests, and verifies rootfs and provenance signatures before installation; admission rechecks the installed bytes. A schema-v2 application descriptor is authenticated under the same publisher policy, revocation feed and pins, then its archive is acquired within the signed size bound, independently bundle-verified, installed and pinned. Text output reads `installed ns/name@version (manifest DIGEST, bundle SHA256)`, and `--json` prints `reference`, `manifest_sha256`, `bundle_sha256`, `key_id`, `status: "installed"` and `installed: true`. `pack update` prints the same text line for an application. Without `$MVM_HOME/registry/publishers.toml`, the built-in policy accepts the exact renamed `mvm-packs` workflow identity for `agent/` and `runtime/`. The former identity is accepted only for the nine exact historical versioned manifest reference/byte-digest pairs listed in [pack authoring](/guides/pack-authoring/#decide-who-may-publish), and only before 2026-11-06 00:00 UTC; the exception is checked after real Sigstore verification identifies the signer. Explicit operator publisher policy is not constrained by that built-in digest exception or cutoff. The reserved `mvm/` namespace accepts only the current exact workflow identity; operator policy may deny but never replace it. A fresh feed under the separate built-in MVM release identity is required for `mvm/` installation and execution; built-image packs outside `mvm/` require independent operator-configured revocation trust. |
| `mvmctl bundle fetch`                                     | Verify a `.mvmpkg` from a path, an `https://` URL, or an `oci://` registry reference against the local trust store                                                |
| `mvmctl bundle install`                                   | Verify and atomically install a `.mvmpkg` (from any `fetch` source) into `~/.mvm/bundles/<sha>/`, streaming each artifact through its hash check rather than loading the archive into memory                                                                  |
| `mvmctl bundle push <file> <ref>`                         | Verify a `.mvmpkg` against the local trust store, publish it to an image registry, and print its `oci://…@sha256:` reference                                      |
| `mvmctl bundle gc`                                        | Prune installed bundles — a specific `<SHA>` or `--all`                                                                                                           |
| `mvmctl deps inspect`                                     | Show a sealed application-dep volume's SBOM, CVE, and hash-chained metadata without spawning a VM                                                                 |
| `mvmctl deps audit`                                       | Re-verify a sealed dep volume against its recorded chain                                                                                                          |
| `mvmctl deps capture` / `install`                         | Capture or install application dependencies into a sealed volume                                                                                                  |
| `mvmctl pool warm [COUNT]`                                | Optional: pre-spawn standby microVMs so even the first run of an image claims a warm one                                                                          |
| `mvmctl pool status [--json]`                             | Report standby pool occupancy                                                                                                                                     |

Archive output is create-only: `mvmctl build --out` refuses an existing file,
symlink or directory without overwriting it. Use a new destination for a
rebuild. Archives are written to invocation-private staging on the destination
filesystem; concurrent attempts at the same destination cannot both publish
successfully.

The pack source path checks the staged archive's manifest, hash and frozen build identity
before publishing it. Validation failures discard only that invocation's staging,
never an archive found later at the requested output path. Cleanup errors are
reported rather than silently ignored. An input-observation report describes the
frozen build inputs, not successful archive publication; it can remain if final
archive publication is refused.

Optional debug summaries are also create-only. Their contents are prepared before
archive publication, but the summary file is published afterward so an alias can
never occupy or replace the archive destination. If summary publication fails,
the error states that the archive was published; the valid archive is retained.

Application descriptors use the same catalog digest, publisher policy, and pins
as legacy packs, but require a current independently signed revocation feed.
Applications in `mvm/` use the built-in official feed; other namespaces require
explicit operator revocation trust and a verified cached feed with at most
48 hours of signed validity. Missing trust or feed, expired data, revoked
signers/digests, rollback, equivocation, or a feed identity matching the descriptor
publisher refuses acquisition and use. Legacy policy-only packs retain their
optional operator-feed behavior. Their bundles must already have an
independently enrolled key in `$MVM_HOME/trusted-publishers/`; naming a key in a
descriptor never enrolls it. Pull accepts canonical HTTPS or digest-pinned OCI
sources, limits acquisition to the descriptor's signed byte size and at most
4 GiB, and checks the exact archive SHA-256, independent bundle signature,
asserted key ID, and descriptor-to-bundle architecture match. OCI sources also
require the production registry allowlist, including when reusing a cached archive.
Cached archives are reverified and extracted files are rebuilt from verified
bytes so their content-addressed directory name is not treated as proof.

Source hosts must be plain ASCII. A locator whose host is internationalized
(for example `bücher.example`) or written in its `xn--` punycode form is
refused; publish the registry or bundle host under an ASCII name instead.

The application reference is committed in the pack lock only after complete bundle
installation and publication of the original descriptor evidence. An interrupted
pull or failure before the atomic reference rename may leave complete verified,
unreferenced cache content, but does not adopt the new application reference.
Bundle and descriptor files and directories are synced before committing the pin;
the pin's directory is synced afterward. An error in that final sync can leave
the complete reference committed with uncertain durability; retry the pull to
reverify rather than assume rollback. These filesystem syncs do not certify
hardware power-loss behavior. Installation is not a launch
grant: host/backend compatibility and current admission checks remain required at
execution; `mvmctl run <ref>` launches an installed application (see `run`).
Applications cannot satisfy a policy-pack dependency.

`pack info` and `pack verify` reopen the original application descriptor and
signature under the current pin, publisher policy, and mandatory current
independent revocation feed. An unversioned reference selects its pinned version; an explicit
different version refuses rather than selecting another catalog entry. They
then check the cached archive's exact size, digest, independent bundle-author
signature, key ID, and architecture binding through the normal bundle verifier.
A missing archive refuses with a `pull` hint: inspection never downloads,
installs, advances a pin, or enrolls a key.

Application JSON has `kind: "application"` and
`verification_scope: "descriptor_and_bundle_archive"`, with separate descriptor
and bundle digests. This scope does not certify extracted-file custody, backend
compatibility, or launch admission. Legacy inspection output is unchanged.
The canonical safe local descriptor reader is currently Unix-only; unsupported
platforms fail closed rather than opening unchecked metadata.

Locked pack inputs to `mvmctl build` never receive the contributor build's automatic
local-checkout `mvm` override: the compiled GitHub input remains the lock's pinned
commit even when `mvmctl` was compiled from a local checkout. Each invocation owns
its compile directory, checked builder-input snapshot and private template slot
until health checking and export finish. The snapshot is verified before builder
preparation and immediately before submission to the canonical one-shot builder;
it is verified again after builder consumption.
The disk-input staging filter must preserve every locked file and mode or the
build is refused. Locked builds do not reuse a resident builder's unrelated
`/work` or the contributor-source cache. Ordinary contributor builds retain their
automatic source overrides.

Portable pack production requires the CLI-version-matched signed release runtime
archive, checksum, and both original signature bundles, plus a current signed
Linux image-set revocation feed already applied to the producer. A locally built
Source runtime is not a substitute. Production captures one owned closure before
builder effects and uses its same verified runtime/initramfs for health and
export; it refuses a built kernel that differs from the canonical Linux selection.
The archive retains the original Linux publisher and feed proofs. Consumer
verification does not build, download, or seed a missing runtime. The canonical
consumer launch refusal described above remains in force until that launch lane
is enabled through its separate integration gates. Re-exporting an installed
bundle with protected boot members is refused rather than silently dropping them.
Producer health supports HVF's verified kernel descriptor route and same-host
Linux Firecracker. Firecracker receives a procfs reference to the held unlinked
descriptor and opens it synchronously during boot configuration, before the
producer releases that borrow. This route requires an already-loadable ELF or
arm64 Image; it never extracts a compressed kernel or consults sibling caches.
Other health backends are refused before runtime acquisition or builder effects.
A caller-provided kernel continuity digest is not admission or publisher
authority, and the procfs reference is not an enduring runtime measurement.
After a producer health attempt, its private build/boot input directories are
retained on success, failure, and unwind: the health API's workload status and
stop acknowledgment are not independent evidence that no native reader remains.
Diagnostics name the retained paths. Remove them only after independently
confirming the relevant VM has exited; this retention is not a health or cleanup
receipt.

`mvmctl build PACK.json --input-observation PATH` explicitly opts into bounded diagnostic
evidence about the frozen Nix input graph. The builder captures raw flake
metadata for the same `/work` reference and output attribute, resolves `mvm`
through the root input edge, and consumes that captured graph with
`--reference-lock-file` and `--no-update-lock-file`. It does not change or write
the frozen source tree. Unlocked graph nodes, a mismatched pinned revision,
missing or malformed evidence, and oversized output are refused. Direct root
edges are supported; a root `mvm` follows edge is refused rather than guessed.
This diagnostic requires Nix 2.31.5, whose reference-lock write semantics were
checked against the pinned builder package source. Other versions are refused.
The one supported unhashed relative node is mvm's non-flake `mvm-workspace`:
its actual input edge must point to `path:..` with parent input path `["mvm"]`.
The selected mvm source must be the pinned, NAR-hashed GitHub repository with
`dir=nix`, so `nix/..` stays inside that same immutable repository source.
Other relative paths, parents, redirects and cycles are refused; this is
inherited content identity, not acceptance of an arbitrary unhashed path.

The JSON report is at most 1 MiB (raw metadata at most 512 KiB), includes the
exact consuming lock bytes, source/input and command hashes, job identity and
the returned Nix store path, and is published only after the pack operation
succeeds. Output hashes describe the guest-produced members before host verity
sidecar generation; the host checks those member bytes in staging and in the
selected cache. The transport report is removed before shared artifact-cache
promotion. This does not establish erasure of backend transport copies or
guaranteed cleanup after filesystem errors or process termination. `PATH` must
not already exist and is never overwritten. Without this flag the ordinary
build remains unchanged. This unsigned diagnostic is not a
signing attestation or admission credential; it does not prove a trusted
builder, health boot, or external reproduction.
`output_stage` is `builder-produced-before-host-sealing`; `output_sha256`
records the builder's kernel, rootfs, and present optional image members.
These streamed hashes must match both extracted output and the selected cache
artifacts, even when the Nix store path matches. They describe builder-produced
bytes, not later sealing/export transformations or final signed archive hashes.

The private slot retains the builder's returned revision and refuses a changed
`current` selection at health/export boundaries. This is invocation ownership,
not support for launching arbitrary historical revisions through public manifest
aliases. Temporary source and slot records are removed when the invocation ends;
the archive records the exact pack lock as provenance, not a temporary source
path. The sealed posture, health exit requirement and before/after artifact
digests remain mandatory.

Concurrent invocations must use distinct `--out` destinations. Private build slots
do not make archive promotion or rollback safe for a shared output path; that
separate ownership repair is tracked in
[#4432](https://github.com/tinylabscom/mvm/issues/4432).

For a built-image pack, `pull` authenticates its descriptor before fetching the
exact public GitHub release assets, verifies their sizes, hashes, rootfs
signature and provenance, then publishes the complete payload atomically.
Installed-pack verification and admission repeat these checks. Registry mirrors
do not redirect image release origins, and private image releases are unsupported.
Currently, `pull` refuses built-image packs before downloading payload assets
because no compatible released image verifier is trusted. The built-image launch
path also refuses until that prerequisite and an authenticated CLI runtime release
are prepared; a source runtime or legacy bundle is not a substitute.

A selected built image carries its exact pack pin, not a saved host payload path.
Each transient or persistent start reopens the installed descriptor, publisher
policy, applied image-set revocations and retained base proof. Final image and
runtime bytes are checked against the admitted plan immediately before backend
handoff, and the normal runtime lifecycle retains authenticated material for the
VM and persistent reopen. Built images require a `standard` or `restrictive`
profile and cold residency; warm-pool and snapshot claims are not enabled for this
source. SDK sidecar attachments are refused until their selected bytes have a
release-backed assembly contract. Source packs keep their separate manifest path;
the persisted slot must match their signed source descriptor.

These gates do not establish a published built-pack or released-client boot
witness. See
[pack authoring](/guides/pack-authoring/#built-image-release-assets) for resource
limits and the split registry/release inventory.

On Linux and other non-HVF hosts, the default residency remains `parked`
(`warm_pool_size=0`). `pool warm` prepares capacity but does not change that
policy. For a prepared, unnamed launch of a warm-eligible shape, enable claims
explicitly:

```bash
mvmctl image pull alpine
mvmctl pool warm --image alpine          # optional pre-warm
MVM_RESIDENCY=warm mvmctl machine run --image alpine -- /bin/true   # claims it
```

Without a source flag, `pool warm` warms the most recently pulled images,
bounded by the residency standby target (at least one). With no pull history
it warms the default image. `pool warm --default` selects the default image
regardless of pull history; it conflicts with the explicit source flags.

`pool warm` takes the same source a launch names: `--image`, `--manifest`
(a manifest, a built slot, an installed bundle sha256 or a signed `.mvmpkg`
archive) or `--flake` with an optional `--flake-profile`. An archive is
verified and installed exactly as `machine run` does it. Standbys are keyed by
the verified bundle or slot digest and the image digest, so a launch of a
different artifact, or of the same rootfs under the host runtime, never claims
one. A bundle produced from an OCI image and pinning its own boot assets keeps its cold
path: the guest runtime it pins predates the claim handshake. `pool warm`
refuses that bundle before preparing a standby, rather than creating capacity
that no launch can claim.

Remove any explicit `warm_pool_size=0` configuration override: an explicit
size takes precedence over `MVM_RESIDENCY`. Eligible launches attempt a claim
when standbys are enabled. If no compatible standby is ready, the launch
declares a cold boot rather than reporting it as a warm claim. Named launches,
launches with standbys disabled, and volume shapes no late-volume slot can
serve retain their cold path.

On Firecracker, a launch with up to four read-only directory mounts
(`--mount DIR:PATH:ro`) claims the same standby a launch without them would.
Every standby boots four read-only placeholder slots; the claim re-checks each
mount against the shares its signed plan admitted, including the content digest
the plan pinned, points a slot at the launch's own materialized image before the
child resumes, and has the guest mount it read-only by its label before the
claim commits. The guest's mount helper exists only in a standby's guest and
exits on that first restore, before any workload process starts. A writable
mount, a disk volume, or more than four mounts keeps the cold path, as does
every volume launch on other backends.

A launch that allows egress (`--allow-host`, `--net`) claims a standby warmed
with `pool warm --egress`, or the one an earlier egress-allowing run left
behind. That standby's guest starts its egress client but holds no policy and
no destinations; the claim spawns the child's own endpoint under the policy its
signed plan recorded, and refuses any other. A launch whose endpoint must
terminate TLS for its own destinations (a bound secret or an intercepted route)
keeps its cold path, because a shared standby cannot hold a certificate minted
for them.

Pack inspection reports `official_status: "established"` only for a fully verified
`mvm/` pack whose signer matches the reserved MVM publisher identity and whose
independently signed MVM revocation feed is fresh. Other packs report
`"not_established"`; an operator-configured feed cannot confer official status.
Built-image packs outside `mvm/` require an operator-configured, independently
signed fresh feed. Its JSON `revocation_scope` is `mvm_release_identity` for
verified official packs and `operator_configured_only` otherwise. A signature
proves identity and integrity, not safety.

The workload pack commands `pack ls`, `pack rm`, and `pack update ns/name[@version]`
use the signed registry-pack cache and lockfile. Existing `pack registry`
commands remain available. The former system-cache commands are now grouped
under `pack system`; their original `pack list`, `pack rollback`, `pack prune`,
`pack download KIND`, and `pack update KIND` spellings remain compatible.
`pack update` selects the system cache only for the exact class names
`builder`, `runtime`, `dev-image`, and `extension`; a namespaced reference
selects a workload pack. Other targets are rejected. This command migration
does not change pack trust or establish any pack as official.

#### Install a signed local candidate

`mvmctl pack registry install-local ns/name@version --manifest-sha256 SHA256
--manifest PATH --bundle PATH --files DIRECTORY` acquires an already-produced
candidate without registry lookup, dependency downloads, or runtime launch.
The exact version and SHA-256 of the signed manifest bytes are required.
`--manifest` and `--bundle` must each be single-link regular files no larger
than 1 MiB; paths are limited to 4096 bytes and 64 components. Symlinks,
hardlinks, special files, and parent traversal are refused.

`--files` is the ready root containing exactly the signed inventory: ordinary
manifest files plus every built-image descriptor asset at its original name,
without an additional release-directory prefix. The shared Core limits remain
4096 payload files and 32 GiB total (with tighter built-asset limits). Metadata,
publisher trust, revocations, and the compiled built-image verifier pin are
checked before large payload copying. The private snapshot is checked before
installation. Dependencies must already be trusted, installed, and locked
locally; cycles and graphs exceeding 128 packs are refused.

Local acquisition never replaces a conflicting pin or repairs an invalid
existing cache entry. Registry pin writers serialize installation and pin
updates, and cache publication is atomic and no-clobber. There is no unsigned
flag, alternate trust policy, or network fallback. A built candidate still
requires the independently signed fresh revocation feed and the released
verifier pin accepted by Core; local transport does not supply those proofs.

### Bundles in image registries

`mvmctl bundle push ./app.mvmpkg oci://registry.example/team/app:v1` stores the
bundle as one artifact manifest: `artifactType` is
`application/vnd.mvm.bundle.v1`, the config is the empty descriptor, and the
single layer (`application/vnd.mvm.bundle.v1.tar`) is the archive itself, which
already carries its signature. Push refuses a bundle that does not verify
against the local trust store, skips blobs the registry already holds, and
prints the digest-pinned reference.

`bundle fetch` and `bundle install` accept `oci://<registry>/<repository>:<tag>`
and `oci://<registry>/<repository>@sha256:<digest>`. Only the `oci://` prefix
selects a registry; any other string that is not an `https://` or `http://` URL
is a local path, even one shaped like `host/name:tag`. The manifest is held to
the pinned digest and to the digest the registry advertises, the layer to its
descriptor digest and size, and both to size caps. A blob redirect is followed
to any origin, without credentials, at most five times, and never from HTTPS to
HTTP. The registry is only a transport: the bundle is accepted or refused by the
same signature check as a local file. A pull by tag reports the digest it
resolved to, and `bundle install` records the resolved reference in its audit
entry.

`--prod` on `fetch` and `install`:

- refuses `--allow-http`, for every source;
- for an `oci://` source, refuses a tag instead of a digest, and refuses a
  registry the OCI registry policy (`MVM_OCI_POLICY`, the same policy
  `mvmctl image pull --prod` enforces) does not allow. Both checks run before
  the registry is contacted;
- does not restrict a local path or an `https://` URL further. Those carry no
  mutable name to pin; what is installed is identified by its sha256 and must
  pass the signature check like any other source.

Registry authentication:

| Mode                       | How it is configured                                           | Behaviour                                                                                                                                                   |
| -------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Anonymous with token realm | No token variable set                                          | On a `401` bearer challenge, fetches a token from the challenge realm without credentials and reuses it for that registry and repository only               |
| Static bearer token        | `MVM_OCI_BEARER_TOKEN_<REGISTRY>`, else `MVM_OCI_BEARER_TOKEN` | Sent as `Authorization: Bearer`. If the registry refuses it, the command fails and names the token realm; the token is never exchanged for an anonymous one |

`<REGISTRY>` is the registry host upper-cased with `.`, `-` and `:` replaced by
`_`. Credentials and issued tokens are only sent to the registry they were
configured or issued for, never to a redirect target. A token realm must be
HTTPS, or the registry's own origin when the registry is reached over plain
HTTP. `MVM_OCI_BEARER_TOKEN` is not host-specific, so it is not sent over plain
HTTP; `--allow-http` uses only the registry-specific variable. Username and
password credentials are not configurable from the CLI.

## Security

> Plan 40 dropped the standalone `mvmctl security status` verb. Posture checks now live inside `mvmctl doctor`.

## Utilities

| Command                          | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mvmctl shell-init`              | Print shell configuration (completions + dev aliases) to stdout                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `mvmctl completions <bash\|zsh>` | Print a completion script. `shell-init`'s eval block calls this; the hidden `--emit-completions` flag it used to carry is gone                                                                                                                                                                                                                                                                                                                                                                    |
| `mvmctl ops metrics`             | Show runtime metrics (Prometheus text format)                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `mvmctl ops metrics --json`      | Show runtime metrics as JSON                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `mvmctl ops mcp stdio`           | Serve capability-derived `MvmClient` tools as newline-delimited MCP JSON-RPC over local stdin/stdout                                                                                                                                                                                                                                                                                                                                                                                              |
| `mvmctl ops mcp stdio --machine <name>` | Also offer `mvm.drive.{open,write,events}` and `mvm.drive.files.{read,write,list}`, bound to that machine, when its signed plan carries a drive grant. Without the grant they are not listed; a grant whose host-signed record is missing or does not match the plan refuses to start                                                                                                                                                                                                             |
| `mvmctl env uninstall`           | Remove an `install.sh` installation: its entries in `MVM_INSTALL_DIR`, the `current` link and every release directory in `MVM_INSTALL_LIB_DIR`. Runs the same script as `curl -fsSL https://runmvm.com/uninstall.sh \| sh`. Refuses while a machine is running, and stops the host-agent daemons only after confirming each recorded PID runs an installed `mvm-host-agent`. Asks before removing `~/.mvm` when interactive and keeps it otherwise. Exits nonzero when it finds nothing to remove |
| `mvmctl env uninstall --purge`   | Also remove `~/.mvm` (or `MVM_HOME`) without asking                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `mvmctl env uninstall --dry-run` | Print what would be removed without removing anything                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `mvmctl env uninstall --force`   | Skip the running-machine check and host-agent daemon shutdown — for an install whose `mvmctl` predates the check, once its machines are stopped                                                                                                                                                                                                                                                                                                                                                   |

## Global Options

## Capture

Inspect a project environment, produce a reviewable capture report, resolve it to the canonical MVM IR, render Nix artifacts, and optionally verify them in the Linux builder VM.

### `mvmctl capture project`

Inspect a project directory and emit a versioned capture report.

| Option            | Description                                                           |
| ----------------- | --------------------------------------------------------------------- |
| `<path>`          | Project directory to inspect                                          |
| `--output <path>` | Output file for the capture report (required)                         |
| `--run "<cmd>"`   | Explicit command to record for later tracing/verification; repeatable |

### `mvmctl capture resolve`

Resolve a capture report into the canonical MVM IR.

| Option            | Description                                 |
| ----------------- | ------------------------------------------- |
| `<report>`        | Capture report to resolve                   |
| `--output <path>` | Output file for the canonical IR (required) |

### `mvmctl capture verify`

Render `flake.nix`, `launch.json`, and `workload.json` from the canonical IR and record verification status.

| Option                 | Description                                                                                                                                                                                                                                                                        |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `<environment>`        | Canonical IR file produced by `capture resolve`                                                                                                                                                                                                                                    |
| `--manifest-dir <dir>` | Directory containing the project source (defaults to the current directory)                                                                                                                                                                                                        |
| `--out-dir <dir>`      | Directory for rendered Nix artifacts and `verification.json` (defaults to a temp directory)                                                                                                                                                                                        |
| `--run "<cmd>"`        | Verification command to record or execute; repeatable                                                                                                                                                                                                                              |
| `--exec-in-builder-vm` | Build the rendered flake inside the Linux builder VM via `mvmctl __builder-shell-job`. Requires a bootstrapped builder VM. Default behavior records the command without executing it                                                                                               |
| `--boot-and-replay`    | Boot a microVM inside the Linux builder VM and replay the verification command as the guest entrypoint. Requires a bootstrapped builder VM with working microVM support. Mutually exclusive with `--exec-in-builder-vm`; default behavior records the command without executing it |

Output files written to `--out-dir`:

- `flake.nix` — Nix flake defining the guest image.
- `launch.json` — resolved entrypoint and metadata.
- `workload.json` — host-side workload IR.
- `verification.json` — canonical IR plus a `verification` array with one record per `--run` command.

See the capture guide for security boundaries and limitations.

## Global Options

All commands accept these global options:

| Option                        | Description                                                             |
| ----------------------------- | ----------------------------------------------------------------------- |
| `--log-format <human\|json>`  | Log format: human (default) or json (structured)                        |
| `--fc-version <VERSION>`      | Override Firecracker version (e.g., v1.14.0)                            |
| `--verbose` (alias `--debug`) | Show verbose `[mvm]` progress messages. Implied when `RUST_LOG` is set. |

## Environment Variables

`MVM_SOURCE_HELPER_BASE_URL` selects the exact base containing the source
commit's platform archive and matching `.bundle`, with no implicit fallback or
other probes. Signatures and `SOURCE_COMMIT` remain mandatory. Older fixed-URL
clients can use it only when matching signed artifacts actually exist there;
unpublished commits require explicit local build mode or separately authorized
backfill. By default, current clients use the `source-builds-` plus full-SHA
prerelease and consult legacy `source-builds` only on archive HTTP 404. See
[source-build recovery](/contributing/development/).
`MVM_SKIP_COSIGN_VERIFY` does not authorize installation of source host helpers.

| Variable                                  | Description                                                                                                                                                                                                                                                                                                                                                                                 | Default                          |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| `MVM_HOME`                                | The single root for all mvm state (data, cache, config, run, state, share, vms)                                                                                                                                                                                                                                                                                                             | `~/.mvm`                         |
| `MVM_FC_VERSION`                          | Firecracker version (auto-normalized to `vMAJOR.MINOR`)                                                                                                                                                                                                                                                                                                                                     | Latest stable                    |
| `MVM_FC_ASSET_BASE`                       | S3 base URL for Firecracker assets                                                                                                                                                                                                                                                                                                                                                          | AWS default                      |
| `MVM_FC_ASSET_ROOTFS`                     | Override rootfs filename                                                                                                                                                                                                                                                                                                                                                                    | Auto-detected                    |
| `MVM_FC_ASSET_KERNEL`                     | Override kernel filename                                                                                                                                                                                                                                                                                                                                                                    | Auto-detected                    |
| `MVM_BUILDER_MODE`                        | Legacy pool-build mode. Only `host` is supported; `vsock` and `auto` fail closed because the retired Firecracker path attached a TAP NIC. This does not select the current builder VMM; use `MVM_BUILDER_BACKEND` for that.                                                                                                                           | `host`                           |
| `MVM_BUILDER_BACKEND`                     | Builder VMM selection: `hvf`, `firecracker`, `qemu`, or the optional `libkrun` integration. Platform defaults are Apple Silicon macOS 26+ → `hvf` and Linux-with-KVM → `firecracker`; every other host → `qemu`. libkrun is never auto-detected or used as a fallback; macOS 13–25 release installs carry its preview tier for explicit selection, while source builds still require the contributor integration setup. | Platform default                 |
| `MVM_BUILDER_LOCK_WAIT_SECS`              | Seconds to wait for the shared Nix store image lock when another build holds it; set to `0` to fail fast instead of queueing                                                                                                                                                                                                                                                                | `3600` (1 hour)                  |
| `MVM_IMAGES_DIR`                          | Contributor builds only: path to a local `mvm-images` checkout, reported by `mvmctl doctor` as the `local-dev` image source. Never discovered automatically; a path that is not a checkout is an error, not a fallback. A release build refuses it before any command runs, and a production admission refuses to boot while it is set. Image builds do not read it yet                     | Unset                            |
| `MVM_NO_PERSISTENT_BUILDER`               | Set to `1` to disable automatic routing through a persistent-builder session                                                                                                                                                                                                                                                                                                                | Unset                            |
| `MVM_WORKLOAD_KERNEL_VARIANT`             | Dev tier only: `workload-k8s` makes `machine run` boot the verified `workload-k8s` kernel from the local kernel cache (`mvmctl kernel build --which workload-k8s`) instead of the sealed workload kernel, with or without a local image checkout; a cache miss warns and boots the sealed kernel. Any other value selects the sealed kernel                                                 |
| `MVM_TEMPLATE_REGISTRY_ENDPOINT`          | S3-compatible endpoint URL for template push/pull. Only a build with the `template-registry-s3` feature reads it; release binaries are built without it and refuse when the endpoint is set.                                                                                                                                                                                                | None                             |
| `MVM_TEMPLATE_REGISTRY_BUCKET`            | S3 bucket name for templates                                                                                                                                                                                                                                                                                                                                                                | None                             |
| `MVM_TEMPLATE_REGISTRY_ACCESS_KEY_ID`     | S3 access key ID                                                                                                                                                                                                                                                                                                                                                                            | None                             |
| `MVM_TEMPLATE_REGISTRY_SECRET_ACCESS_KEY` | S3 secret access key                                                                                                                                                                                                                                                                                                                                                                        | None                             |
| `MVM_TEMPLATE_REGISTRY_PREFIX`            | Key prefix inside the bucket                                                                                                                                                                                                                                                                                                                                                                | `mvm`                            |
| `MVM_TEMPLATE_REGISTRY`                   | Base URL of the remote template index and files used by `mvmctl template search` and remote scaffolds (`https://` or `file://`)                                                                                                                                                                                                                                                              | `https://raw.githubusercontent.com/tinylabscom/mvm-packs/main` |
| `MVM_PACK_REGISTRY`                       | Base URL of the signed pack registry `mvmctl pack search`, `pack pull`, and `pack update ns/name` read (`https://` or `file://`). The original top-level and `pack registry` spellings share this setting. Packs from another registry still have to verify under the publisher trust policy | `https://raw.githubusercontent.com/tinylabscom/mvm-packs/main` |
| `MVM_TEMPLATE_REGISTRY_REGION`            | S3 region                                                                                                                                                                                                                                                                                                                                                                                   | `us-east-1`                      |
| `OPENAI_API_KEY`                          | Enables LLM-backed template planning for `template init --prompt`                                                                                                                                                                                                                                                                                                                           | None                             |
| `MVM_TEMPLATE_PROVIDER`                   | Prompt planning provider: `auto`, `openai`, `local`, or `heuristic`                                                                                                                                                                                                                                                                                                                         | `auto`                           |
| `MVM_TEMPLATE_OPENAI_MODEL`               | OpenAI model used for prompt planning                                                                                                                                                                                                                                                                                                                                                       | `gpt-5.2`                        |
| `MVM_TEMPLATE_OPENAI_BASE_URL`            | Override OpenAI API base URL for prompt planning                                                                                                                                                                                                                                                                                                                                            | `https://api.openai.com`         |
| `MVM_TEMPLATE_LOCAL_MODEL`                | Local AI model name sent to an OpenAI-compatible local endpoint                                                                                                                                                                                                                                                                                                                             | `qwen2.5-coder-7b-instruct`      |
| `MVM_TEMPLATE_LOCAL_BASE_URL`             | Base URL for an OpenAI-compatible local AI endpoint such as LocalAI or `llama.cpp` server                                                                                                                                                                                                                                                                                                   | None                             |
| `MVM_TEMPLATE_LOCAL_API_KEY`              | Optional API key for the local AI endpoint                                                                                                                                                                                                                                                                                                                                                  | None                             |
| `MVM_TEMPLATE_LOCAL_PROBE_TARGETS`        | Comma-separated base URLs to probe for a local OpenAI-compatible endpoint in `auto` mode (overrides defaults `http://127.0.0.1:11434` and `http://127.0.0.1:8080`)                                                                                                                                                                                                                          | Defaults                         |
| `MVM_TEMPLATE_NO_LOCAL_PROBE`             | Set to `1` to skip the local-endpoint probe in `auto` mode (CI / sandboxed environments where loopback connects can hang)                                                                                                                                                                                                                                                                   | Unset                            |
| `MVM_PRODUCTION`                          | Enable production mode checks                                                                                                                                                                                                                                                                                                                                                               | `false`                          |
| `MVM_OCI_POLICY`                          | OCI production policy TOML used by `mvmctl image pull --prod` and `mvmctl run --image --prod`                                                                                                                                                                                                                                                                                               | `$MVM_HOME/oci-policy.toml`      |
| `MVM_OCI_BEARER_TOKEN_<HOST>`             | Bearer token for one OCI registry host (`ghcr.io` -> `MVM_OCI_BEARER_TOKEN_GHCR_IO`)                                                                                                                                                                                                                                                                                                        | Unset                            |
| `MVM_OCI_BEARER_TOKEN`                    | Global fallback bearer token for OCI registry pulls                                                                                                                                                                                                                                                                                                                                         | Unset                            |
| `RUST_LOG`                                | Logging level (e.g., `debug`, `mvm=trace`)                                                                                                                                                                                                                                                                                                                                                  | `info`                           |
| `MVM_PHASE_TIMING`                        | Set to `1`/`true` to print a transient run's per-phase launch breakdown to stderr as two greppable lines: `[mvm] phase-timing:` for the coarse buckets, plus `[mvm] phase-timing-detail:` for whichever sub-phases were measured. Set to `tree` for the same spans rendered as one nested, aligned report grouped by containment — easier to read, but not a stable format to parse         | Unset                            |
| `MVM_FAILURE_DIAGNOSTICS` | Diagnostic harness opt-in: exactly `1` emits bounded, typed failure observations on blocking stderr. Not production telemetry or custody proof. See the [diagnostic data policy](https://github.com/tinylabscom/mvm/blob/main/specs/contracts/diagnostic-data-policy.md#opt-in-launch-failure-observations) for the closed schema and loss limits. | Unset (off) |
| `MVM_E2E_FAILURE_MANIFEST` | Documented-launch conformance harness only: selected private manifest destination in an existing trusted parent directory; enables the typed child observations above. Collection is bounded, but legacy stdout/stderr buffering remains unbounded. Records are spoofable observations and never gate acceptance; see the diagnostic data policy above. | Unset (off) |
| `MVM_E2E_FAILURE_AUTHORIZATION` | Harness export only: original fresh-initialization step output, exactly matching the source manifest path. Required by `scripts/e2e-failure-manifest.py --export` before reading observations; missing authorization exports only an empty absent diagnostic. | Unset |
| `MVM_E2E_FAILURE_EXPORT` | Harness export only: exact fresh private snapshot destination in a trusted existing directory. `--export` validates the closed source schema and serializes bounded observations with `finalization: "unverified"`; never copies raw source bytes or claims durable finalization or suite success. Existing destinations are refused. | Unset |
| `MVM_LAUNCH_SAMPLE_JSON`                  | Path a transient run writes its machine-readable launch sample to — build profile, backend, guest sizing, artifact paths, the expensive work the launch performed, and every phase span. Read by the release-only cold-launch benchmark; setting it turns the measurement on without the stderr output.                                                                                     | Unset                            |
| `MVM_DEV_FLAKE_URL`                       | Escape hatch for the dev-build's chained `--override-input mvm` target. When set, suppresses the default chained override. (Legacy from the previous iteration's dual-flake layout; today's same-flake-for-both-modes design rarely needs it.)                                                                                                                                              | Unset                            |
| `MVM_SRC`                                 | Override the source repo path passed to `nix build` during dev builds                                                                                                                                                                                                                                                                                                                       | Workspace root                   |
| `MVM_BUILDER_AGENT_BIN`                   | Override the path to the builder-agent binary baked into the builder VM image                                                                                                                                                                                                                                                                                                               | Auto-detected from build closure |
| `MVM_BUILDER_AGENT_PORT`                  | Vsock port the builder agent listens on                                                                                                                                                                                                                                                                                                                                                     | `54_321`                         |
| `MVM_BUILDER_VM_TIMEOUT_SECS`             | Wall-clock cap for one-shot libkrun builder VM runs before the supervisor is killed                                                                                                                                                                                                                                                                                                         | `1800`                           |
| `MVM_TENANT_KEY_<ID>`                     | Compatibility hook for tenant-scoped key material consumed by shared policy/keystore primitives. Fleet operators should configure tenant keys through `mvmd`.                                                                                                                                                                                                                               | None                             |
| `MVM_TENANT_KEY_LOCAL`                    | Explicitly selects the 32-byte key (64 hex characters) that encrypts sealed instance snapshots and host-domain checkpoints. When set it is the only key source consulted, so a malformed value refuses `machine pause` and `machine resume` rather than falling back to another key. Without it, the keystore entry `mvm/local`, then `/var/lib/mvm/keys/local.key`, then `~/.mvm/keys/local.key` (32 raw bytes, mode 0600 or 0400) are used; `mvmctl bootstrap` and the first `pool warm` create the last when none holds a key. See [Snapshots](/working/snapshots/). | Provisioned under `~/.mvm/keys/` |
| `MVM_ALLOW_UNENCRYPTED_SNAPSHOT`          | Set to `1` to resume, once, an instance snapshot sealed unencrypted by an older `mvmctl` while a snapshot key is configured. Affects resume only; a pause always encrypts. | Unset |
| `MVM_ALLOW_UNENCRYPTED_VOLUME_STORAGE`    | Set to `1` on a development host to place unlocked managed-volume plaintext, writable `HOST.img:/GUEST:SIZE:rw` disk images, and host directory snapshots on storage that is not verified encrypted (no FileVault on macOS; no dm-crypt/LUKS under ext4 on Linux). Each use is recorded as `volume_storage_override` in the local audit log, and is refused if that cannot be written. `--prod` refuses a run that sets it. See [Persistent workspaces](/guides/persistent-workspaces/#where-unlocked-plaintext-may-live). | Unset (refuse) |
| `MVM_SKIP_COSIGN_VERIFY`                  | Set to `1` to bypass cosign signature verification on prebuilt-image downloads and on the runtime-overlay / SDK-sidecar release archives. Documented emergency-rotation escape only; never set in CI or production.                                                                                                                                                                         | Unset                            |
| `MVM_SKIP_HASH_VERIFY`                    | Set to `1` to bypass SHA-256 verification on prebuilt-image downloads. Documented escape hatch only; never set in CI or production.                                                                                                                                                                                                                                                         | Unset                            |
| `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE`        | `build` or `download`. A source build assembles its guest runtime pieces from its tree either way; `build` keys its OCI guest runtime by the source rather than the version and opts bootstrap into source-built host helpers and, with an image checkout, the local builder image. A release binary assembles from its release's guest runtime; `build` there fails for want of a checkout. The image set supplies no guest runtime under either value. | `download`                       |
| `MVM_COLD_BUILD`                          | `refuse` makes `machine run` fail instead of building when a cache is cold (as `--no-build` does); `auto` builds without the first-run notice (as `--build` does). Either flag wins over the variable. Other verbs ignore it.                                                                                                                                                               | Build, with one notice           |
