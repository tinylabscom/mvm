import { Tabs, TabsList, TabsTrigger, TabsContent } from "../ui/tabs";

const quickStart = `# Bootstrap everything
mvmctl dev

# Build a microVM image from a Nix flake
mvmctl build --flake .

# Boot a headless Firecracker VM
mvmctl run --flake . --cpus 2 --memory 1024

# Check health via vsock
mvmctl vm ping`;

const nixFlake = `{
  inputs = {
    mvm.url = "github:auser/mvm?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux";
      pkgs = import nixpkgs { inherit system; };
    in {
      packages.\${system}.default = mvm.lib.\${system}.mkGuest {
        name = "my-app";
        packages = [ pkgs.curl ];

        services.my-app = {
          command = "\${pkgs.python3}/bin/python3 -m http.server 8080";
        };

        healthChecks.my-app = {
          healthCmd = "\${pkgs.curl}/bin/curl -sf http://localhost:8080/";
          healthIntervalSecs = 5;
        };
      };
    };
}`;

const template = `# Scaffold a new template
mvmctl template init my-service --local

# Register and build
mvmctl template create my-service
mvmctl template build my-service

# Run from template
mvmctl run --template my-service

# Warm snapshot for instant restart
mvmctl template warm my-service
# Subsequent runs: <1s startup`;

export function CodeExample() {
  return (
    <section className="px-6 py-24 sm:px-8">
      <div className="mx-auto max-w-4xl">
        <h2 className="mb-12 text-center text-2xl font-semibold text-heading sm:text-3xl">
          Get Running in Minutes
        </h2>
        <Tabs defaultValue="quickstart">
          <TabsList>
            <TabsTrigger value="quickstart">Quick Start</TabsTrigger>
            <TabsTrigger value="flake">Nix Flake</TabsTrigger>
            <TabsTrigger value="template">Templates</TabsTrigger>
          </TabsList>
          <TabsContent value="quickstart">
            <pre className="overflow-x-auto rounded-xl border border-border bg-page p-6 font-mono text-sm leading-relaxed text-heading sm:p-8">
              <code>{quickStart}</code>
            </pre>
          </TabsContent>
          <TabsContent value="flake">
            <pre className="overflow-x-auto rounded-xl border border-border bg-page p-6 font-mono text-sm leading-relaxed text-heading sm:p-8">
              <code>{nixFlake}</code>
            </pre>
          </TabsContent>
          <TabsContent value="template">
            <pre className="overflow-x-auto rounded-xl border border-border bg-page p-6 font-mono text-sm leading-relaxed text-heading sm:p-8">
              <code>{template}</code>
            </pre>
          </TabsContent>
        </Tabs>
      </div>
    </section>
  );
}
