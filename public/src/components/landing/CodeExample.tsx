import { Tabs, TabsList, TabsTrigger, TabsContent } from "../ui/tabs";
import { CodeBlock } from "../ui/code-block";

const quickStart = `# Bootstrap everything
mvmctl dev

# Build a microVM image from a Nix flake
mvmctl build --flake .

# Boot a headless Firecracker VM
mvmctl up --flake . --cpus 2 --memory 1024

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

const template = `# Scaffold from a preset (minimal, python, http, postgres, worker)
mvmctl init my-service --preset python

# Build the manifest at ./my-service
mvmctl build my-service

# Inspect manifest slot, sizes, snapshot status
mvmctl manifest info my-service

# Run from the manifest
mvmctl up my-service

# Build with snapshot for instant restart (<2s boot)
mvmctl build my-service --snapshot`;

export function CodeExample() {
  return (
    <section className="w-full border-y border-edge/50 bg-raised px-6 py-28 sm:px-8 lg:py-36">
      <div className="mx-auto max-w-5xl">
        <h2 className="mb-16 text-center text-2xl font-semibold text-title sm:text-3xl lg:mb-20">
          Get Running in Minutes
        </h2>
        <Tabs defaultValue="quickstart">
          <TabsList>
            <TabsTrigger value="quickstart">Quick Start</TabsTrigger>
            <TabsTrigger value="flake">Nix Flake</TabsTrigger>
            <TabsTrigger value="template">Templates</TabsTrigger>
          </TabsList>
          <TabsContent value="quickstart">
            <CodeBlock language="bash" code={quickStart} />
          </TabsContent>
          <TabsContent value="flake">
            <CodeBlock language="nix" code={nixFlake} />
          </TabsContent>
          <TabsContent value="template">
            <CodeBlock language="bash" code={template} />
          </TabsContent>
        </Tabs>
      </div>
    </section>
  );
}
