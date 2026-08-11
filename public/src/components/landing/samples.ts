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
    id: "walk-build",
    label: "Build",
    language: "bash",
    source: "examples/python/hello-app/README.md",
    code: `mvmctl build compile examples/python/hello-app/app.py --out /tmp/hello-app`,
  },
  {
    id: "walk-run",
    label: "Run",
    language: "bash",
    source: "examples/python/hello-app/README.md",
    code: `mvmctl machine run --flake /tmp/hello-app --entrypoint`,
  },
  {
    id: "walk-result",
    label: "Result",
    language: "bash",
    source: "examples/python/hello-app/README.md",
    code: `# expect: "hello ari"`,
  },
  {
    id: "sdk-python",
    label: "Python",
    language: "python",
    source: "crates/mvm-sdk/sdks/python/README.md",
    code: `import mvm as mv

result = mv.Machine.run(
    image="alpine:latest",
    command=["uname", "-a"],
    net=True,
    allow_hosts=["example.com:443"],
)
print(result.stdout)`,
  },
  {
    id: "sdk-node",
    label: "Node.js",
    language: "typescript",
    source: "crates/mvm-sdk/sdks/typescript/README.md",
    code: `import { Machine } from "@runmvm/mvm";

const result = Machine.run({
  image: "alpine:latest",
  command: ["uname", "-a"],
  net: true,
  allowHosts: ["example.com:443"],
});
console.log(result.stdout);`,
  },
  {
    id: "sdk-rust",
    label: "Rust",
    language: "rust",
    source: "crates/mvm-sdk/README.md",
    code: `use mvm_sdk::{Machine, MachineCheckArtifact, MachineRun};

let result = MachineRun::builder()
    .image("alpine")
    .net(true)
    .command(["uname", "-a"])
    .run()?;`,
  },
  {
    id: "cli-run",
    label: "CLI",
    language: "bash",
    source: "public/src/content/docs/reference/cli-commands.md",
    code: `mvmctl machine run --net --image <ref> -- <cmd>...`,
  },
];
