/**
 * The docs navigation, in one place.
 *
 * Starlight consumes this from `astro.config.mjs` to render the sidebar, and
 * `src/pages/llms.txt.ts` consumes it to order and group the machine-readable
 * index. Keeping both readers on one array is what stops the agent-facing
 * index from drifting away from the navigation humans see.
 */

export interface SidebarLink {
  label: string;
  slug: string;
}

export interface SidebarGroup {
  label: string;
  items: SidebarLink[];
}

export const sidebar: SidebarGroup[] = [
  {
    label: "Getting Started",
    // Order: shortest path to "it's running" first, deep background later —
    // run your first thing before architecture / threat-model detail.
    items: [
      { label: "Installation", slug: "getting-started/installation" },
      { label: "First-Use Happy Paths", slug: "getting-started/happy-paths" },
      { label: "Quick Start", slug: "getting-started/quickstart" },
      { label: "Python quickstart", slug: "getting-started/python-quickstart" },
      { label: "Node.js quickstart", slug: "getting-started/nodejs-quickstart" },
      { label: "Rust quickstart", slug: "getting-started/rust-quickstart" },
      { label: "Your First MicroVM", slug: "getting-started/first-microvm" },
      { label: "Connect an LLM", slug: "getting-started/connect-an-llm" },
      { label: "Nix for mvm", slug: "getting-started/nix-for-mvm" },
      { label: "Core concepts", slug: "getting-started/core-concepts" },
      { label: "Design principles", slug: "getting-started/design-principles" },
    ],
  },
  {
    label: "Install",
    items: [
      { label: "Linux", slug: "install/linux" },
      { label: "macOS", slug: "install/macos" },
      { label: "Windows (WSL2)", slug: "install/windows" },
    ],
  },
  {
    label: "Working in the MicroVM",
    items: [
      { label: "Overview", slug: "working" },
      { label: "Sandbox management", slug: "working/sandbox-management" },
      { label: "Lifecycle states", slug: "working/lifecycle-states" },
      { label: "Run commands & processes", slug: "working/commands" },
      { label: "Filesystem operations", slug: "working/filesystem" },
      { label: "Network & exposing ports", slug: "working/network" },
      { label: "Persistence, pause & resume", slug: "working/persistence" },
      { label: "Cold mode", slug: "working/cold-mode" },
      { label: "Snapshots", slug: "working/snapshots" },
    ],
  },
  {
    label: "Tutorials",
    items: [
      { label: "Overview", slug: "tutorials" },
      { label: "Agent Sandbox", slug: "tutorials/agent-sandbox" },
      { label: "Coding Agent", slug: "tutorials/coding-agent" },
      { label: "Code Execution", slug: "tutorials/code-execution" },
      { label: "File Transfer", slug: "tutorials/file-transfer" },
      { label: "LLM Tool Integration", slug: "tutorials/llm-tool-integration" },
      { label: "Browser Automation", slug: "tutorials/browser-automation" },
      { label: "Desktop Automation", slug: "tutorials/desktop-automation" },
      { label: "Interactive Terminal", slug: "tutorials/interactive-terminal" },
      { label: "Any Language", slug: "tutorials/any-language" },
      { label: "Services and Ports", slug: "tutorials/services-and-ports" },
      { label: "Long-running Services", slug: "tutorials/long-running-services" },
      { label: "Error Handling", slug: "tutorials/error-handling" },
      { label: "Cold-Mode Recovery", slug: "tutorials/cold-mode-recovery" },
    ],
  },
  {
    label: "Console",
    items: [
      { label: "Overview", slug: "console" },
      { label: "Attach to a microVM", slug: "console/attach" },
      { label: "Transparent rebuilds", slug: "console/transparent-rebuild" },
    ],
  },
  {
    label: "Templates",
    items: [
      { label: "Overview", slug: "templates" },
      { label: "Create a template", slug: "templates/create" },
      { label: "Build & list", slug: "templates/build" },
      { label: "Lifecycle", slug: "templates/lifecycle" },
    ],
  },
  {
    label: "Guides",
    items: [
      { label: "Overview", slug: "guides" },
      { label: "Writing Nix Flakes", slug: "guides/nix-flakes" },
      { label: "Nix and OCI", slug: "guides/nix-and-oci" },
      { label: "From dev loop to attested image", slug: "guides/develop-to-attested" },
      { label: "From Workload IR to MicroVM Image", slug: "guides/ir-to-image" },
      { label: "Building MicroVM Images", slug: "guides/building-microvm-images" },
      { label: "Building from Source", slug: "guides/building-from-source" },
      { label: "Builder VM", slug: "guides/builder-vm" },
      { label: "Custom kernels", slug: "guides/kernels" },
      { label: "Sandboxed Exec", slug: "guides/exec" },
      { label: "Machine use cases", slug: "guides/machine-use-cases" },
      { label: "Machine limitations", slug: "guides/machine-limitations" },
      { label: "Policy Profiles", slug: "guides/policy-profiles" },
      { label: "Config & Secrets", slug: "guides/config-secrets" },
      { label: "Secrets and Credentials", slug: "guides/secrets-and-credentials" },
      { label: "Persistent Workspaces", slug: "guides/persistent-workspaces" },
      { label: "Audit and Receipts", slug: "guides/audit-and-receipts" },
      { label: "Workload Output Streaming", slug: "guides/workload-output-streaming" },
      { label: "Workload Input", slug: "guides/workload-input" },
      { label: "Fleet Stream Edges", slug: "guides/fleet-stream-edges" },
      { label: "Observability and Results", slug: "guides/observability-and-results" },
      { label: "Manifests", slug: "guides/manifests" },
      { label: "Networking", slug: "guides/networking" },
      { label: "Network Egress Policy", slug: "guides/network-egress-policy" },
      { label: "AI Agent Integration", slug: "guides/ai-agent-integration" },
      { label: "Agent Tool Contract", slug: "guides/agent-tool-contract" },
      { label: "Image Registry Configuration", slug: "guides/image-registry-configuration" },
      { label: "macOS Sandbox Debugging", slug: "guides/macos-sandbox-debugging" },
      { label: "Dev Image", slug: "guides/dev-image" },
      { label: "Verify Release", slug: "guides/verify-release" },
      { label: "Airgapped Bootstrap", slug: "guides/airgapped-bootstrap" },
      { label: "Troubleshooting", slug: "guides/troubleshooting" },
      { label: "Windows: WSL2 walkthrough", slug: "guides/windows-wsl2" },
      { label: "Windows: troubleshooting", slug: "guides/windows-troubleshooting" },
    ],
  },
  {
    label: "Examples",
    items: [
      { label: "Overview", slug: "examples" },
      { label: "Sandbox for an AI agent", slug: "examples/ai-agent-sandbox" },
      { label: "CI/CD ephemeral builder", slug: "examples/ci-cd-ephemeral-builder" },
      { label: "Reproducible dev VM from a flake", slug: "examples/dev-vm-from-flake" },
      { label: "Code interpreter pattern", slug: "examples/code-interpreter" },
    ],
  },
  {
    label: "Security",
    items: [
      { label: "Capability status", slug: "security/capability-status" },
      { label: "The security review", slug: "security/security-review" },
      { label: "Matryoshka Model", slug: "security/matryoshka" },
      { label: "Security claim ledger", slug: "security/claim-ledger" },
      { label: "Threat model", slug: "security/threat-model" },
      { label: "CI-enforced claims", slug: "security/ci-claims" },
      { label: "Verified boot", slug: "security/verified-boot" },
      { label: "Sandbox parity status", slug: "security/sandbox-parity-status" },
    ],
  },
  {
    label: "Architecture",
    items: [
      { label: "Overview", slug: "architecture/overview" },
      { label: "Core Components", slug: "architecture/core-components" },
      { label: "Boot flow", slug: "architecture/boot-flow" },
      { label: "Control surfaces", slug: "architecture/control-surfaces" },
      { label: "Security and Isolation", slug: "architecture/security-isolation" },
      { label: "Networking and Storage", slug: "architecture/networking-storage" },
    ],
  },
  {
    label: "Resources",
    items: [
      { label: "Docs for agents", slug: "llms-index" },
      { label: "FAQ", slug: "resources/faq" },
      { label: "Changelog", slug: "resources/changelog" },
    ],
  },
  {
    label: "SDK",
    items: [
      { label: "Overview", slug: "sdk" },
      { label: "Runtime SDK", slug: "sdk/runtime" },
      { label: "Runtime modes", slug: "sdk/runtime-modes" },
      { label: "SDK security model", slug: "sdk/security-model" },
      { label: "Operations cookbook", slug: "sdk/operations-cookbook" },
      { label: "Decorator SDK", slug: "sdk/decorator" },
      { label: "Declaration workflow", slug: "sdk/declaration-workflow" },
      { label: "Declaration cookbook", slug: "sdk/declaration-cookbook" },
      { label: "Sandbox types", slug: "sdk/sandbox-types" },
      { label: "Lifecycle matrix", slug: "sdk/lifecycle-matrix" },
      { label: "Errors & metrics", slug: "sdk/errors-metrics" },
      { label: "SDK Reference", slug: "sdk/reference" },
      { label: "Python SDK", slug: "sdk/python" },
      { label: "Node.js SDK", slug: "sdk/nodejs" },
      { label: "Rust SDK", slug: "sdk/rust" },
    ],
  },
  {
    label: "Reference",
    items: [
      { label: "CLI Commands", slug: "reference/cli-commands" },
      { label: "Evidence archive format", slug: "reference/mvmev-format" },
      { label: "Programmatic Use", slug: "reference/programmatic-use" },
      { label: "Architecture", slug: "reference/architecture" },
      { label: "Isolation Tiers", slug: "reference/isolation-tiers" },
      { label: "Platform Support", slug: "reference/platform-support" },
      { label: "Filesystem & Drives", slug: "reference/filesystem" },
      { label: "Guest Agent", slug: "reference/guest-agent" },
      { label: "Limits & Resources", slug: "reference/limits" },
      { label: "Launch Performance", slug: "reference/performance" },
      { label: "Releases & downloads", slug: "reference/releases" },
    ],
  },
  {
    label: "Contributing",
    items: [{ label: "Development Guide", slug: "contributing/development" }],
  },
];
