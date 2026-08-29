For all these commands add appropriate bdd flags
pip install zigbuild 0.13.0
make sure there is an app.py dirctory in the examples we are running
Crtl c doesn't work in the itneractive shell forward the ctrl c key code
The home directory should be read write -  
interactive read/write directory works / doesn't work from non-interactive  
mvmctl machine run --image alpine --cpus 2 --memory 512M \
  --allow-host example.com:80 -- wget  example.com  
Connecting to 127.0.0.1:1080 (127.0.0.1:1080)
wget: can't open 'index.html': Read-only file system

mvmctl machine run --flake "$PWD/examples/sleeper" -- ./app does't work
here is the error - mvmctl machine run --flake "$PWD/examples/sleeper" -- ./app
⠙ Preparing the builder VM (one-time setup) — 0s elapsed[mvm] Stage 0 build log streams to /Users/aneyzberg/.mvm/cache/builder-vm/vms/mvm-stage0-1786503333720-63111/console.log — `tail -f` it to watch progress (or re-run with `-v` to stream it here)
⠋ Preparing the builder VM (one-time setup) — 10s elapsedbuilder egress endpoint pid=63125 exited with status signal: 15 (SIGTERM)
Error: ensuring the builder VM image before flake build

Caused by:
    0: building the source-checkout builder VM image via root-dir Stage 0
    1: Stage 0 root-dir build: nix build failed inside builder sandbox: nix build failed inside the Stage 0 guest; console log at /Users/aneyzberg/.mvm/cache/builder-vm/vms/mvm-stage0-1786503333720-63111/console.log
       warning: unable to download 'https://github.com/NixOS/nixpkgs/archive/8fd9daa3db09ced9700431c5b7ad0e8ba199b575.tar.gz': proxy handshake error (97) cannot complete SOCKS5 connection to github.com. (1); retrying in 539 ms (attempt 2/5)
       warning: unable to download 'https://github.com/NixOS/nixpkgs/archive/8fd9daa3db09ced9700431c5b7ad0e8ba199b575.tar.gz': proxy handshake error (97) cannot complete SOCKS5 connection to github.com. (1); retrying in 1209 ms (attempt 3/5)
       warning: unable to download 'https://github.com/NixOS/nixpkgs/archive/8fd9daa3db09ced9700431c5b7ad0e8ba199b575.tar.gz': proxy handshake error (97) cannot complete SOCKS5 connection to github.com. (1); retrying in 2133 ms (attempt 4/5)
       error:
              … while evaluating the attribute 'nixpkgs.result'
                at «flakes-internal»/call-flake.nix:94:7:
                  93|     {
                  94|       result =
                    |       ^
                  95|         if node.flake or true then
              … in the condition of the assert statement
                at «flakes-internal»/call-flake.nix:96:11:
                  95|         if node.flake or true then
                  96|           assert builtins.isFunction flake.outputs;
                    |           ^
                  97|           result
              (stack trace truncated; use '--show-trace' to show the full, detailed trace)
              error: Failed to open archive (Source threw exception: error: unable to download 'https://github.com/NixOS/nixpkgs/archive/8fd9daa3db09ced9700431c5b7ad0e8ba199b575.tar.gz': proxy handshake error (97) cannot complete SOCKS5 connection to github.com. (1))
       stage0-init: build failed: nix build exit 1
       [    9.423485] reboot: Power down


mvmctl build kernel build --which workload --source compile
[mvm] Stage 0 build log streams to /Users/aneyzberg/.mvm/cache/builder-vm/vms/mvm-stage0-1786503841525-64050/console.log — `tail -f` it to watch progress (or re-run with `-v` to stream it here)
builder egress endpoint pid=64064 exited with status signal: 15 (SIGTERM)
Error: Stage 0 kernel build: nix build failed inside builder sandbox: nix build failed inside the Stage 0 guest; console log at /Users/aneyzberg/.mvm/cache/builder-vm/vms/mvm-stage0-1786503841525-64050/console.log
warning: unable to download 'https://github.com/NixOS/nixpkgs/archive/8fd9daa3db09ced9700431c5b7ad0e8ba199b575.tar.gz': proxy handshake error (97) cannot complete SOCKS5 connection to github.com. (1); retrying in 566 ms (attempt 2/5)
warning: unable to download 'https://github.com/NixOS/nixpkgs/archive/8fd9daa3db09ced9700431c5b7ad0e8ba199b575.tar.gz': proxy handshake error (97) cannot complete SOCKS5 connection to github.com. (1); retrying in 1188 ms (attempt 3/5)
warning: unable to download 'https://github.com/NixOS/nixpkgs/archive/8fd9daa3db09ced9700431c5b7ad0e8ba199b575.tar.gz': proxy handshake error (97) cannot complete SOCKS5 connection to github.com. (1); retrying in 2666 ms (attempt 4/5)
error:
       … while evaluating the attribute 'nixpkgs.result'
         at «flakes-internal»/call-flake.nix:94:7:
           93|     {
           94|       result =
             |       ^
           95|         if node.flake or true then
       … in the condition of the assert statement
         at «flakes-internal»/call-flake.nix:96:11:
           95|         if node.flake or true then
           96|           assert builtins.isFunction flake.outputs;
             |           ^
           97|           result
       (stack trace truncated; use '--show-trace' to show the full, detailed trace)
       error: Failed to open archive (Source threw exception: error: unable to download 'https://github.com/NixOS/nixpkgs/archive/8fd9daa3db09ced9700431c5b7ad0e8ba199b575.tar.gz': proxy handshake error (97) cannot complete SOCKS5 connection to github.com. (1))
stage0-init: build failed: nix build exit 1
[    9.632072] reboot: Power down


mvmctl machine build --flake . 
⠋ Preparing the builder VM (one-time setup) — 0s elapsed[mvm] Stage 0 build log streams to /Users/aneyzberg/.mvm/cache/builder-vm/vms/mvm-stage0-1786505360113-66126/console.log — `tail -f` it to watch progress (or re-run with `-v` to stream it here)
⠋ Preparing the builder VM (one-time setup) — 10s elapsedbuilder egress endpoint pid=66140 exited with status signal: 15 (SIGTERM)
Error: ensuring the builder VM image before the flake build (Stage 0 bootstrap)

Caused by:
    0: building the source-checkout builder VM image via root-dir Stage 0
    1: Stage 0 root-dir build: nix build failed inside builder sandbox: nix build failed inside the Stage 0 guest; console log at /Users/aneyzberg/.mvm/cache/builder-vm/vms/mvm-stage0-1786505360113-66126/console.log
       warning: unable to download 'https://github.com/NixOS/nixpkgs/archive/8fd9daa3db09ced9700431c5b7ad0e8ba199b575.tar.gz': proxy handshake error (97) cannot complete SOCKS5 connection to github.com. (1); retrying in 687 ms (attempt 2/5)
       warning: unable to download 'https://github.com/NixOS/nixpkgs/archive/8fd9daa3db09ced9700431c5b7ad0e8ba199b575.tar.gz': proxy handshake error (97) cannot complete SOCKS5 connection to github.com. (1); retrying in 1288 ms (attempt 3/5)
       warning: unable to download 'https://github.com/NixOS/nixpkgs/archive/8fd9daa3db09ced9700431c5b7ad0e8ba199b575.tar.gz': proxy handshake error (97) cannot complete SOCKS5 connection to github.com. (1); retrying in 2547 ms (attempt 4/5)
       error:
              … while evaluating the attribute 'nixpkgs.result'
                at «flakes-internal»/call-flake.nix:94:7:
                  93|     {
                  94|       result =
                    |       ^
                  95|         if node.flake or true then
              … in the condition of the assert statement
                at «flakes-internal»/call-flake.nix:96:11:
                  95|         if node.flake or true then
                  96|           assert builtins.isFunction flake.outputs;
                    |           ^
                  97|           result
              (stack trace truncated; use '--show-trace' to show the full, detailed trace)
              error: Failed to open archive (Source threw exception: error: unable to download 'https://github.com/NixOS/nixpkgs/archive/8fd9daa3db09ced9700431c5b7ad0e8ba199b575.tar.gz': proxy handshake error (97) cannot complete SOCKS5 connection to github.com. (1))
       stage0-init: build failed: nix build exit 1
       [    9.786672] reboot: Power down


mvmctl compile app.py
error: unrecognized subcommand

