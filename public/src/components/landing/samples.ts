export type Sample = {
  id: string;
  label: string;
  language: string;
  /** Repo-relative path. */
  source: string;
  code: string;
};

export const SAMPLES: Sample[] = [
  {
    id: "python-hello",
    label: "Python",
    language: "python",
    source: "examples/python/hello-app/app.py",
    code: `@mvm.app(
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu=1, memory_mb=256),
    env={"HELLO_BANNER": mvm.literal("hi there")},
    before_start="export FOO=1",
)
def greet(name: str) -> str:
    return f"hello {name}"`,
  },
  {
    id: "walk-define",
    label: "Python",
    language: "python",
    source: "examples/python/hello-env/app.py",
    code: `@mvm.app(
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu=1, memory_mb=256),
    env={"NAME": "danny"},
    before_start="export FOO=1",
)
def main() -> None:
    print(f"hello {os.environ['NAME']}")`,
  },
  {
    id: "walk-build",
    label: "Build",
    language: "bash",
    source: "examples/python/hello-env/README.md",
    code: `mvmctl build compile examples/python/hello-env/app.py --out /tmp/hello-env`,
  },
  {
    id: "walk-run",
    label: "Run",
    language: "bash",
    source: "examples/python/hello-env/README.md",
    code: `mvmctl machine run --flake /tmp/hello-env --entrypoint`,
  },
  {
    id: "walk-result",
    label: "Result",
    language: "bash",
    source: "examples/python/hello-env/README.md",
    code: `# expect: "hello danny"`,
  },
  {
    id: "declare-typescript",
    label: "TypeScript",
    language: "typescript",
    source: "crates/mvm-sdk/sdks/typescript/README.md",
    code: `import * as mvm from "@runmvm/mvm";

mvm.workload({ id: "hello" });

export const greet = mvm.app({
  image: mvm.node_image({ node: "22" }),
  resources: mvm.resources({ cpu: 1, memory_mb: 256 }),
})((name: string): string => \`hello \${name}\`);`,
  },
  {
    id: "sdk-python",
    label: "Python",
    language: "python",
    source: "crates/mvm-sdk/sdks/python/README.md",
    code: `import mvm as mv

vm = mv.Machine.run("alpine:latest", allow_hosts=["example.com:443"], ttl_seconds=600)
print(vm.name, vm.build_mode, vm.inspect()["status"])
vm.stop()`,
  },
  {
    id: "sdk-node",
    label: "Node.js",
    language: "typescript",
    source: "crates/mvm-sdk/sdks/typescript/README.md",
    code: `import { Machine } from "@runmvm/mvm";

const vm = Machine.run("alpine:latest", { allowHosts: ["example.com:443"], ttlSeconds: 600 });
console.log(vm.name, vm.inspect().status);
vm.stop();`,
  },
  {
    id: "sdk-rust",
    label: "Rust",
    language: "rust",
    source: "public/src/content/docs/getting-started/rust-quickstart.md",
    code: `use mvm_client::{LaunchRequest, LifecycleMode, LocalBackend, MvmClient, RootfsSource};

// inside an async context:
let client = LocalBackend::new();

let image: RootfsSource = "docker.io/library/nginx:1.27".parse()?;
let request = LaunchRequest::builder(LifecycleMode::Transient, image)
    .name("web")
    .cpus(2)
    .memory_mib(512)
    .port("8080:80")
    .allow_egress("api.example.com", 443)
    .ttl_seconds(1800)
    .build()?;

let launched = client.launch(request).await?;
println!("started {} under plan {}", launched.machine.name, launched.plan_id);`,
  },
  {
    id: "cli-run",
    label: "CLI",
    language: "bash",
    source: "public/src/content/docs/reference/cli-commands.md",
    code: `mvmctl machine run --net --image <ref> -- <cmd>...`,
  },
];
