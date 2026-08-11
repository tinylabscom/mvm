export type Sample = {
  id: string;
  label: string;
  language: string;
  /** Repo-relative path, or the literal "cli-help". */
  source: string;
  /** Present iff source === "cli-help": argv after `mvmctl`. */
  helpArgs?: string[];
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
];
