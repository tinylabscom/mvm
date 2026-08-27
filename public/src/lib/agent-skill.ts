// One document telling a coding agent how to actually use mvm, served at both
// /skill.md and /agents.md because agents look for one or the other and there
// is no reason to make that a coin flip.
//
// Every command here is checked against the CLI's clap definitions and the
// pages linked at the bottom. Nothing goes in that has not been run or read
// out of the source — a plausible-looking command that does not exist costs an
// agent more than no command at all.
export const AGENT_SKILL = `<!-- mvm skill for coding agents. Also served at /agents.md. -->
<!-- Complete documentation index, every page with a description: /llms.txt -->

# Using mvm

mvm runs a command inside a real Linux microVM on the machine you are already
on: one CLI, no account, no control plane, nothing leaves the host unless a
policy admits it. \`mvmctl run --image alpine -- uname -a\` pulls the image,
boots a VM, runs the command, and tears the VM down.

What separates it from a process sandbox is the shape of the boundary. A
workload microVM boots with **no network interface at all** — the guest has a
vsock channel and nothing else. Outbound traffic leaves over that channel to a
host-side endpoint that is default-deny, so the host originates every
connection and can refuse, substitute, or log it. And every launch is admitted
from a signed \`ExecutionPlan\` and appended to a chain-signed audit log, so
what ran is a question with an answer after the fact.

## Install

\`\`\`bash
curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh
\`\`\`

Pin a version, or build from a checkout:

\`\`\`bash
MVM_VERSION=v0.16.1 curl -fsSL https://raw.githubusercontent.com/tinylabscom/mvm/main/install.sh | sh
cargo install mvmctl
\`\`\`

You do not need Nix on the host. Flake-backed builds run inside a Linux builder
VM that mvmctl starts and reuses for you. There is no self-update command —
reinstall the way you installed.

Host setup runs automatically on first use; run it explicitly with:

\`\`\`bash
mvmctl bootstrap
\`\`\`

## Verify before you trust the host

\`\`\`bash
mvmctl doctor
mvmctl doctor --workflow cli-run     # only the checks an image-backed run needs
mvmctl doctor --json                 # machine-readable
\`\`\`

A healthy run prints \`Prerequisites\`, \`Tools\`, \`Platform\`, and
\`Security posture\` sections — each check as \`<name>: OK (<info>)\` — followed
by the backend capability table and the line \`All checks passed.\`, and exits
0. An unhealthy run prints \`Issues found:\` and exits nonzero; \`--json\`
carries the same verdict as \`all_ok\`. Check the exit status, not the prose.

\`--workflow\` takes \`cli-run\`, \`python-sdk\`, \`typescript-sdk\`,
\`bundle-run\`, or \`dev-shell\`, and fails only on prerequisites that workflow
actually needs.

## Run something

The shortest path — a transient VM, one command, torn down after:

\`\`\`bash
mvmctl run --image alpine -- uname -a
mvmctl image inspect alpine          # what was pulled, and its provenance
\`\`\`

A named machine you keep around:

\`\`\`bash
mvmctl machine start alpine-dev --image alpine
mvmctl machine exec alpine-dev -- uname -a
mvmctl machine ls
mvmctl machine stop alpine-dev
\`\`\`

From a Nix flake, which is the reproducible path:

\`\`\`bash
mvmctl machine build --flake . --profile minimal
mvmctl machine run --flake .
mvmctl machine run --flake . --mount .:/work -- ls /work
\`\`\`

Then read back what the audit log says happened:

\`\`\`bash
mvmctl trust audit verify
mvmctl explain
\`\`\`

Two naming traps worth knowing: \`mvmctl build\` is the build-time command
group (\`compile\`, \`validate\`, \`kernel\`), **not** the image build — that is
\`mvmctl machine build\`. And there is no top-level \`mvmctl ls\`; the list verb
is \`mvmctl machine ls\`.

## Wire mvm into your agent

\`\`\`bash
mvmctl plugin list
mvmctl plugin install <target> --dry-run
\`\`\`

This writes the integration file for a supported agent into the project. There
is no server to stand up: the tool an agent should call is \`mvmctl\` itself,
and it already audits every launch.

## Platform support

| Host | Architecture | Backend | Status |
|---|---|---|---|
| Linux with \`/dev/kvm\` | x86_64, aarch64 | Firecracker | Supported; strongest local target |
| macOS Apple Silicon | aarch64 | HVF on macOS 26+, libkrun on 13–25 | Supported |
| Linux without \`/dev/kvm\` | x86_64, aarch64 | QEMU (TCG) | Dev/test only, never auto-selected |
| WSL2 with nested KVM | x86_64, aarch64 | libkrun | Supported workload path |
| Windows, native | any | none | Not supported; use WSL2 |
| macOS, Intel | x86_64 | none | Not supported |

There is no container backend on the runtime path. Do not run untrusted code on
the QEMU TCG tier.

## Where to look next

- /llms.txt — every documentation page, with a description, grouped by section.
  Append \`.md\` to any page path to get it as plain markdown.
- /getting-started/happy-paths.md — a three-command path per audience.
- /reference/cli-commands.md — the full verb surface.
- /guides/network-egress-policy.md — how to grant the egress a workload needs.
- /guides/secrets-and-credentials.md — reference-first credential delivery.
- /security/claim-ledger.md — which security claims are enforced, and by what.
- /reference/platform-support.md — the authoritative version of the table above.
`;
