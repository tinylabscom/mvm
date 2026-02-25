Do we have 100% test coverage? What do we need to test next?

---

When we build a tenant, I don't think we need to make the pool build against a fresh agent, we need to launch it with tenant volumes, but not rebuild the fresh image everytime, I don't think. I think the runtime is what makes the runtime unique. What I mean is we should be able to reuse `aibutler/openclaw` (or the name) for different tenants where the tenant itself isn't aibutler (or `aibutler/openclaw`). That's just the image name. We should be able to reuse that image across any tenant and the tenant should launch an image of openclaw with volumes that are unique to them, not to the image

---

This is a multi-tenant architecture. Each tenant gets their own "customized" microvm version of a template based upon their own secrets and customization, etc. Some templates require multiple types of microvms. For example, openclaw requires a gateway microvm and agent workers. That's considered a pool. So for tenants to get access to their own openclaw, they have access to a pool of microvms. 

Tenant's customizations come from their pool infrastructure so that when a tenant makes a request to our service, if a gateway (the thing that handles inbound requests) isn't running for that tenant, we boot up the microvm and then pass it on to the agent handling device (the other image in openclaw's templated pool) so that from the user's perspective, their setup never changed, but ours optimizes use because we enable sleep/wake infrastructure.

---

Now that we have our nix templates building, we'll want to make it so that they load a tenant's secrets and configuration. How do we start doing that? Where do these secrets and configuration values exist (and they need to be encrypted).

---

I have a `template.toml` in that directory `/Users/auser/work/tinylabs/aibutler/nix/openclaw` -- can we use this to run our build? This way we can have an easy way to make changes to our build in a file?

---

Also when I build the flake, I get this error. Can we update the actual `nix` files so they actually produce a clean build:

cargo run -- build --flake ./nix/openclaw/ --role worker
   Compiling mvm-runtime v0.3.0 (/Users/auser/work/personal/microvm/kv/mvm/crates/mvm-runtime)
   Compiling mvm-cli v0.3.0 (/Users/auser/work/personal/microvm/kv/mvm/crates/mvm-cli)
   Compiling mvm v0.3.0 (/Users/auser/work/personal/microvm/kv/mvm)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 5.42s
     Running `target/debug/mvm build --flake ./nix/openclaw/ --role worker`

[mvm] Step 1/2: Building flake /Users/auser/work/personal/microvm/kv/mvm/nix/openclaw (profile=minimal, role=worker)
[mvm] No manifest found, using legacy attribute: /Users/auser/work/personal/microvm/kv/mvm/nix/openclaw#packages.aarch64-linux.tenant-minimal
[mvm] Building: nix build /Users/auser/work/personal/microvm/kv/mvm/nix/openclaw#packages.aarch64-linux.tenant-minimal
warning: creating lock file "/Users/auser/work/personal/microvm/kv/mvm/nix/openclaw/flake.lock":
• Added input 'flake-utils':
    'github:numtide/flake-utils/11707dc' (2024-11-13)
• Added input 'flake-utils/systems':
    'github:nix-systems/default/da67096' (2023-04-09)
• Added input 'microvm':
    'github:astro/microvm.nix/b67e3d8' (2026-02-22)
• Added input 'microvm/nixpkgs':
    follows 'nixpkgs'
• Added input 'microvm/spectrum':
    'git+https://spectrum-os.org/git/spectrum?ref=refs/heads/main&rev=c5d5786d3dc938af0b279c542d1e43bce381b4b9' (2025-10-03)
• Added input 'nixpkgs':
    'github:NixOS/nixpkgs/50ab793' (2025-06-30)
error: flake 'git+file:///Users/auser/work/personal/microvm/kv/mvm?dir=nix/openclaw' does not provide attribute 'packages.aarch64-linux.packages.aarch64-linux.tenant-minimal', 'legacyPackages.aarch64-linux.packages.aarch64-linux.tenant-minimal' or 'packages.aarch64-linux.tenant-minimal'
Error: nix build failed for /Users/auser/work/personal/microvm/kv/mvm/nix/openclaw#packages.aarch64-linux.tenant-minimal

Caused by:
    Command failed (exit 1)