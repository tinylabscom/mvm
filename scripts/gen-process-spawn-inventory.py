#!/usr/bin/env python3
"""Regenerate the table in specs/contracts/process-spawn-inventory.md.

    python3 scripts/gen-process-spawn-inventory.py            # rewrite the doc
    python3 scripts/gen-process-spawn-inventory.py --check    # fail on drift

Scans production Rust (not #[cfg(test)], tests/, examples/, benches/, build.rs,
xtask, third_party) for every process-creation form, groups sites by file, and
adds the hand-written class/purpose in ANNOTATIONS. A file with sites and no
annotation fails the run, so a new spawn cannot land unclassified. The static
reachability columns need `cargo tree --offline` and a name-based call graph;
see the doc for what they do and do not prove.
"""
import collections, json, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "specs/contracts/process-spawn-inventory.md")
BEGIN, END = "<!-- inventory:begin -->", "<!-- inventory:end -->"

SPAWN = re.compile(
    r'\b(?:std::process::|tokio::process::|process::)?Command::new\s*\(\s*(?P<arg>[^)]*)'
    r'|\b(?P<fac>helper_command_with|helper_command|scrub_command|wrap_checked)\s*\(\s*(?P<farg>[^,)\n]{0,50})'
    r'|\blibc::(?P<libc>fork|vfork|execv\w*|execl\w*|posix_spawn\w*|system|popen)\b'
    r'|(?<![.\w])(?:nix::unistd::|libc::)?(?P<raw>fork\s*\(\s*\)|vfork\s*\(\s*\)|execve\s*\(\s*[&*\w]'
    r'|execv\s*\(\s*[&*\w]|execvp\s*\(\s*[&*\w]|execvpe\s*\(\s*[&*\w]|execveat_raw\s*\()'
    r'|\blibc::syscall\s*\(\s*libc::(?P<sys>SYS_(?:execve|execveat|clone|clone3|fork|vfork))'
    r'|\b(?:libc::)?(?P<pty>openpty|forkpty|posix_openpt)\s*\(')
# Commands built elsewhere and spawned here: found by hand, kept in the doc.
SKIP_DIRS = {"target", ".git", "node_modules", "tests", "examples", "benches", "fuzz",
             "xtask", ".agent-memory", "sdks", "third_party"}


def strip(src):
    """Blank comments (keeping newlines and string contents)."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            while i < n and src[i] != "\n":
                i += 1
        elif src.startswith("/*", i):
            d, i = 1, i + 2
            while i < n and d:
                if src.startswith("/*", i):
                    d, i = d + 1, i + 2
                elif src.startswith("*/", i):
                    d, i = d - 1, i + 2
                else:
                    if src[i] == "\n":
                        out.append("\n")
                    i += 1
        elif c == '"':
            out.append(c)
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\":
                    out.append(src[i])
                    i += 1
                out.append(src[i])
                i += 1
            out.append('"')
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def block_end(s, j):
    d, p = 0, j
    while p < len(s):
        if s[p] == "{":
            d += 1
        elif s[p] == "}":
            d -= 1
            if d == 0:
                return p
        p += 1
    return len(s)


def test_ranges(s):
    spans = []
    for m in re.finditer(r"#\[cfg\((?:all\()?test\b[^\]]*\]|#\[test\]|#\[tokio::test[^\]]*\]", s):
        j, k = s.find("{", m.end()), s.find(";", m.end())
        if j == -1 or (k != -1 and k < j):
            continue
        spans.append((m.start(), block_end(s, j)))
    return spans


def source_files():
    files = []
    for top in ("crates", "src"):
        for dp, dn, fn in os.walk(os.path.join(ROOT, top)):
            dn[:] = [d for d in dn if d not in SKIP_DIRS]
            files += [os.path.join(dp, f) for f in fn if f.endswith(".rs")]
    return sorted(files)


def test_only_files(files, raw):
    t = set()
    for p in files:
        s = raw[p]
        if re.search(r"^\s*#!\[cfg\(test\)\]", s, re.M):
            t.add(p)
        b = os.path.splitext(os.path.basename(p))[0]
        d = os.path.dirname(p)
        for m in re.finditer(r"#\[cfg\((?:all\()?test\b[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", s):
            n = m.group(1)
            t.update([os.path.join(d, n + ".rs"), os.path.join(d, n, "mod.rs"),
                      os.path.join(d, b, n + ".rs"), os.path.join(d, b, n, "mod.rs")])
        base = os.path.basename(p)
        if base in ("tests.rs", "test_support.rs") or base.endswith(("_tests.rs", "_test.rs")) or base.startswith("test_"):
            t.add(p)
    stems = [os.path.splitext(x)[0] + os.sep for x in t]
    return t | {p for p in files if any(p.startswith(x) for x in stems)}


def scan():
    files = source_files()
    raw = {p: strip(open(p, errors="replace").read()) for p in files}
    tests = test_only_files(files, raw)
    sites, defs = [], []
    for p in files:
        if p in tests:
            continue
        rel = os.path.relpath(p, ROOT)
        s, tr = raw[p], test_ranges(raw[p])
        lines = s.splitlines()
        fdefs = []
        for m in re.finditer(r"\bfn\s+(\w+)", s):
            if any(a <= m.start() <= b for a, b in tr):
                continue
            j, k = s.find("{", m.end()), s.find(";", m.end())
            if j == -1 or (k != -1 and k < j):
                continue
            fdefs.append((m.group(1), s.count("\n", 0, m.start()) + 1, s.count("\n", 0, block_end(s, j)) + 1))
        defs.append((rel, fdefs, s, tr))
        if os.path.basename(rel) == "build.rs":
            continue
        for m in SPAWN.finditer(s):
            if any(a <= m.start() <= b for a, b in tr):
                continue
            ln = s.count("\n", 0, m.start()) + 1
            text = lines[ln - 1]
            if "write!" in text or "format!" in text:
                continue
            if re.search(r"\bfn\s+\w+", text) and not m.group("arg") and not m.group("libc"):
                continue
            kind = ("Command::new" if m.group("arg") is not None else m.group("fac")
                    or ("libc::" + m.group("libc") if m.group("libc")
                        else ("raw:" + re.match(r"\w+", m.group("raw")).group(0) if m.group("raw")
                              else (m.group("sys") or m.group("pty")))))
            inner = [f for f in fdefs if f[1] <= ln <= f[2]]
            fn = min(inner, key=lambda f: f[2] - f[1])[0] if inner else None
            sites.append(dict(file=rel, line=ln, kind=kind, fn=fn))
    return sites, defs


def crate_of(rel):
    p = rel.split("/")
    if p[0] == "crates":
        return p[2] if p[1] == "deps" else p[1]
    return "mvmctl"


def closures():
    out = {}
    for c in ("mvm-client", "mvm-hostlib", "mvm-sdk"):
        r = subprocess.run(["cargo", "tree", "--offline", "-p", c, "-e", "normal", "--prefix", "none"],
                           cwd=ROOT, capture_output=True, text=True)
        out[c] = {l.split()[0] for l in r.stdout.splitlines() if l.startswith(("mvm", "libkrun", "runmvm"))}
    return out


def traced(sites, defs):
    """Name-based forward call graph from every fn in the three entry crates.

    Names defined in more than two files are not followed (too ambiguous), and
    trait-object dispatch is invisible, so this is a lower bound.
    """
    nodes, namefiles = [], collections.defaultdict(set)
    for rel, fdefs, s, tr in defs:
        for n, a, b in fdefs:
            namefiles[n].add(rel)
    lines_of = {}
    for rel, fdefs, s, tr in defs:
        lines = s.splitlines()
        for n, a, b in fdefs:
            body = "\n".join(lines[a - 1:b])
            nodes.append((n, rel, a, b, {c for c in re.findall(r"\b(\w+)\s*(?:::<[^>]*>)?\s*\(", body) if c != n and len(namefiles.get(c, ())) <= 2}))
    byname = collections.defaultdict(list)
    for i, (n, *_r) in enumerate(nodes):
        byname[n].append(i)
    res = {}
    for key, pref in (("mvm-client", "crates/mvm-client/src/"), ("mvm-hostlib", "crates/mvm-hostlib/src/"), ("mvm-sdk", "crates/mvm-sdk/src/")):
        seen = {i for i, nd in enumerate(nodes) if nd[1].startswith(pref)}
        todo = list(seen)
        while todo:
            for c in nodes[todo.pop()][4]:
                for t in byname.get(c, ()):
                    if t not in seen:
                        seen.add(t)
                        todo.append(t)
        res[key] = {(nodes[i][1], nodes[i][0]) for i in seen}
    return res


# file (under crates/) -> (class, purpose). Authority comes from the crate and
# the overrides below.
A = {
    # guest: runs inside a workload microVM
    "mvm-agentd/src/bin/mvm-guest-agent/health.rs": ("guest workload", "workload health check via /bin/sh"),
    "mvm-agentd/src/bin/mvm-guest-agent/interactive.rs": ("guest workload", "detached workload process and its exit reporter"),
    "mvm-agentd/src/bin/mvm-oci-entrypoint.rs": ("guest workload", "exec the OCI image entrypoint"),
    "mvm-agentd/src/bin/mvm-runner.rs": ("guest workload", "start the language runtime for a workload"),
    "mvm-agentd/src/bin/mvm-seccomp-apply.rs": ("guest workload", "exec the workload under its seccomp filter"),
    "mvm-agentd/src/console.rs": ("guest workload", "dev-image PTY console: openpty, fork, execve of the shell"),
    "mvm-agentd/src/crng_reseed/helper.rs": ("guest helper", "re-exec self as the entropy-reseed helper"),
    "mvm-agentd/src/entrypoint.rs": ("guest workload", "run the declared entrypoint"),
    "mvm-agentd/src/exec_stream.rs": ("guest workload", "exec / streamed exec of a requested command (dev verbs)"),
    "mvm-agentd/src/guest_bootstrap.rs": ("guest init", "busybox setup at boot, egress client, PTY device provisioning"),
    "mvm-agentd/src/guest_net.rs": ("guest init", "loopback/DHCP bring-up through busybox and udhcpc"),
    "mvm-agentd/src/late_volumes.rs": ("guest helper", "re-exec self as the late-volume mount helper"),
    "mvm-agentd/src/lifecycle_hooks.rs": ("guest workload", "before_/after_ lifecycle hook scripts"),
    "mvm-agentd/src/process_rpc.rs": ("guest workload", "process-control RPC start of a requested program"),
    "mvm-agentd/src/tool_helper.rs": ("guest helper", "fork and execveat of a mediated tool invocation"),
    "mvm-agentd/src/tool_install.rs": ("guest helper", "start the declared-command tool helper before privilege drop"),
    "mvm-agentd/src/worker_pool.rs": ("guest workload", "warm worker-pool process"),
    "mvm-setpriv/src/lib.rs": ("guest helper", "privilege-drop-and-exec of the target command"),
    # builder VM
    "mvm-agentd/src/bin/mvm-builder-agent.rs": ("builder job", "run a builder job's command"),
    "mvm-agentd/src/builder_agent.rs": ("builder job", "run a builder job's command"),
    "mvm-agentd/src/builder_build.rs": ("builder job", "nix build and artifact staging via sh"),
    "mvm-builder-guest/src/bin/mvm-host-vm-init.rs": ("builder init", "builder VM PID 1: busybox/mount/network setup, nix-store, mkfs, workload netns, agent fork"),
    "mvm-builder-guest/src/bin/mvm-host-vm-init/boot_stage.rs": ("builder init", "exec the next boot stage"),
    "mvm-builder-guest/src/bin/mvm-host-vm-init/builder_hooks.rs": ("builder init", "fsck and loop-device hooks"),
    "mvm-builder-guest/src/bin/mvm-host-vm-init/install.rs": ("builder job", "dependency install job (uv/pnpm)"),
    "mvm-builder-guest/src/bin/mvm-host-vm-init/workload.rs": ("builder init", "start Firecracker for a nested workload"),
    "mvm-builder-guest/src/bin/stage0-init.rs": ("builder init", "Stage 0 bootstrap: network, mkfs, nix"),
    "mvm-builder-guest/src/bin/stage0-init/kernel_emit.rs": ("builder job", "nix build of the emitted kernel"),
    "mvm-builder-guest/src/bin/stage0-init/store_gc.rs": ("builder job", "nix store garbage collection"),
    "mvm-builder-guest/src/builderd.rs": ("builder job", "builderd runs job argv and the rootfs runner"),
    # host libraries
    "mvm-backends/src/driver/fc.rs": ("systemd-run / sudo", "signal a Firecracker process through sudo kill on Linux"),
    "mvm-backends/src/driver/hvf.rs": ("hypervisor supervisor", "spawn mvm-hvf-supervisor for an HVF VM (cold and restore)"),
    "mvm-backends/src/driver/hvf_restore.rs": ("hypervisor supervisor", "spawn mvm-hvf-supervisor for a snapshot restore"),
    "mvm-backends/src/driver/libkrun.rs": ("hypervisor supervisor", "spawn mvm-libkrun-supervisor"),
    "mvm-backends/src/driver/qemu.rs": ("hypervisor", "launch QEMU"),
    "mvm-backends/src/driver/qemu_process.rs": ("mvmctl self re-exec", "start `mvmctl __qemu-vsock-bridge`"),
    "mvm-backends/src/fc/idle_pool.rs": ("process control", "setsid-detached idle standby holder"),
    "mvm-build/src/builder_egress_process.rs": ("mvmctl self re-exec", "start `mvmctl __builder-egress-supervisor`"),
    "mvm-build/src/builder_vm_bootstrap.rs": ("mvmctl self re-exec", "run the bootstrap helper to prepare the builder image"),
    "mvm-build/src/builder_vm_image.rs": ("storage tool", "host mkfs of the builder store image"),
    "mvm-build/src/builder_vm_runtime.rs": ("storage tool", "debugfs read of a builder image"),
    "mvm-build/src/builder_vm_transport.rs": ("toolchain", "cargo build of the network endpoint binary"),
    "mvm-build/src/embed_toolchain.rs": ("toolchain", "probe rustup/cargo/rustc/zig/python3 for the pinned embed toolchain"),
    "mvm-build/src/guest_agent_build.rs": ("toolchain", "cargo / rustup build of guest binaries from this tree"),
    "mvm-build/src/libkrun_builder.rs": ("hypervisor supervisor", "cargo build of helpers, libkrun builder supervisor (explicit libkrun only)"),
    "mvm-build/src/provenance_mark.rs": ("storage tool", "debugfs read of image provenance mark"),
    "mvm-build/src/qemu_builder.rs": ("hypervisor", "QEMU builder: timeout-wrapped boot, zstd, mkfs.ext4, debugfs"),
    "mvm-build/src/runtime_overlay.rs": ("network fetch", "curl download of a release artifact"),
    "mvm-build/src/stage0.rs": ("archive tool", "native tar -xJf of the Stage 0 root tarball (pure-Rust path is the alternative)"),
    "mvm-capture/src/collect/package.rs": ("capture probe", "dpkg / dpkg-query / nix-locate package ownership"),
    "mvm-capture/src/collect/trace.rs": ("capture probe", "strace under timeout to trace a project command"),
    "mvm-capture/src/verify.rs": ("mvmctl self re-exec", "run `mvmctl __builder-shell-job` to verify a capture"),
    "mvm-core/src/crypto/key_rotation.rs": ("storage tool", "cryptsetup luksChangeKey"),
    "mvm-core/src/env_hygiene.rs": ("factory", "the sanctioned Command constructor: scrubs denied env, then everything above calls it"),
    "mvm-core/src/host_storage_encryption.rs": ("host probe", "diskutil / findmnt / tune2fs / lsblk encryption-at-rest probes"),
    "mvm-core/src/platform/platform.rs": ("host probe", "sw_vers and nix presence probe"),
    "mvm-core/src/spawn_scope.rs": ("systemd-run", "wrap a VMM spawn in a systemd transient scope; kill and systemctl show"),
    "mvm-fs/src/oci_to_rootfs/ext4.rs": ("storage tool", "mke2fs to materialize an OCI rootfs (Linux)"),
    "mvm-fs/src/oci_to_rootfs/verity.rs": ("storage tool", "veritysetup format of a rootfs (Linux)"),
    "mvm-runtime/src/host_shell.rs": ("shell script", "bash -c for ShellEnvironment host commands"),
    "mvm-runtime/src/microvm/run_info.rs": ("process control", "kill of a recorded VM pid"),
    "mvm-runtime/src/storage/backend.rs": ("storage tool", "dmsetup thin-pool operations"),
    "mvm-runtime/src/storage/volume/encrypted_linux.rs": ("storage tool", "cryptsetup, mount, umount, mkfs.ext4 for an encrypted volume"),
    "mvm-vmm/src/host/aux_bin.rs": ("helper bin", "`--contract-version` probe of a helper; cargo build of helpers from source"),
    "mvm-vmm/src/host/broker_services_spawn.rs": ("helper bin", "spawn the per-VM host-services broker"),
    "mvm-vmm/src/host/gpu_endpoint_spawn.rs": ("helper bin", "spawn the per-VM GPU endpoint"),
    "mvm-vmm/src/host/linux_env.rs": ("shell script", "bash -c in the Linux environment (run / run_visible)"),
    "mvm-vmm/src/host/network_endpoint_spawn.rs": ("helper bin", "spawn the per-VM network endpoint (the egress gate)"),
    "mvm-vmm/src/host/network_endpoint_spawn/collector.rs": ("helper bin", "spawn the egress telemetry collector"),
    "mvm-vmm/src/host/network_endpoint_spawn/owned.rs": ("helper bin", "spawn an owned network endpoint"),
    "mvm-vmm/src/host/shell/exec.rs": ("shell script", "run_in_vm / run_host: bash -c and direct program exec for every ShellEnvironment caller"),
    "mvm-client/src/secret/source.rs": ("password manager", "run the user's configured secret-source CLI (op, etc.) to read a credential"),
    # host daemons
    "mvm-hostd/src/bin/mvm-host-agent.rs": ("helper bin", "re-exec self as a worker process"),
    "mvm-hostd/src/bin/mvm-hvf-supervisor.rs": ("codesign / self re-exec", "ad-hoc codesign of the binary, then re-exec self signed"),
    "mvm-hostd/src/bin/mvm-network-endpoint.rs": ("helper bin", "keeper re-execs the endpoint binary for a long-lived VM"),
    "mvm-hostd/src/health_probe.rs": ("mvmctl self re-exec", "`mvmctl machine restart` after a failed healthcheck (embedder-refused)"),
    "mvm-hostd/src/supervisor/firewall/linux_nft.rs": ("net (nft)", "install host nftables rules"),
    "mvm-hostd/src/supervisor/services/spawn.rs": ("helper bin", "ProcessSpawner: start a signed, integrity-checked host service binary"),
    # CLI
    "mvm-cli/src/bench/cold_launch_runner.rs": ("mvmctl self re-exec", "`mvmctl pool status` / launch for the bench harness"),
    "mvm-cli/src/bootstrap.rs": ("host probe", "wsl.exe on Windows hosts"),
    "mvm-cli/src/commands/bootstrap.rs": ("helper bin", "builder egress supervisor runs the endpoint binary"),
    "mvm-cli/src/commands/build/kernel.rs": ("mvmctl self re-exec", "`mvmctl` subcommands for kernel build steps (run_self)"),
    "mvm-cli/src/commands/build/sandbox_record.rs": ("user script", "interpreter for user workload record mode (user_script_command)"),
    "mvm-cli/src/commands/deps/audit.rs": ("toolchain", "pip-audit / pnpm audit of app deps"),
    "mvm-cli/src/commands/env/artifact_verify.rs": ("network fetch", "curl of the pinned image-set manifest"),
    "mvm-cli/src/commands/env/builder_vm/vm_helpers.rs": ("host probe", "ps to find builder processes"),
    "mvm-cli/src/commands/env/uninstall.rs": ("shell script", "sh -c uninstall step"),
    "mvm-cli/src/commands/image/trust.rs": ("toolchain", "cosign verify"),
    "mvm-cli/src/commands/ops/config.rs": ("user editor", "$EDITOR for `mvmctl config edit`"),
    "mvm-cli/src/commands/ops/secret.rs": ("user opener", "xdg-open / open of an OAuth URL"),
    "mvm-cli/src/commands/pool/refill.rs": ("mvmctl self re-exec", "detached `mvmctl` pool refill helper"),
    "mvm-cli/src/commands/seccomp_audit.rs": ("fork + execvpe", "audit a program under a seccomp filter (filtered env)"),
    "mvm-cli/src/commands/vm/sdk_no_vm.rs": ("user script", "run an SDK wrapper script without a VM"),
    "mvm-cli/src/doctor/security_checks.rs": ("host probe", "fdesetup / findmnt / lsblk posture checks"),
    "mvm-cli/src/doctor/toolchain.rs": ("host probe", "`<tool> --version` probes in doctor"),
    "mvm-cli/src/host_binaries/payload_build.rs": ("toolchain", "cargo zigbuild of the embedded host binaries (refusal is in host_binaries/source.rs)"),
    "mvm-cli/src/update.rs": ("mvmctl self re-exec", "`--version` smoke test and `bootstrap` of the freshly installed mvmctl"),
    # dev only
    "mvm-conformance/src/vmm_reaper.rs": ("test harness", "ps / kill / sudo to reap leaked VMMs in conformance runs"),
}
# Authority by crate when a row says nothing more specific.
AUTH = {
    "mvm-agentd": "guest", "mvm-setpriv": "guest", "mvm-builder-guest": "builder VM",
    "mvm-cli": "CLI (`mvmctl`)", "mvm-hostd": "host daemon role",
    "mvm-conformance": "dev harness, not shipped",
}
AUTH_OVERRIDE = {f: "builder VM" for f in (
    "mvm-agentd/src/bin/mvm-builder-agent.rs", "mvm-agentd/src/builder_agent.rs", "mvm-agentd/src/builder_build.rs")}
AUTH_OVERRIDE["mvm-hostd/src/bin/mvm-hvf-supervisor.rs"] = "per-VM supervisor bin"
AUTH_OVERRIDE["mvm-hostd/src/bin/mvm-network-endpoint.rs"] = "per-VM endpoint bin"
AUTH_OVERRIDE["mvm-hostd/src/bin/mvm-host-agent.rs"] = "host daemon bin"
AUTH_OVERRIDE["mvm-cli/src/commands/bootstrap.rs"] = "CLI hidden verb"
LIB_AUTH = "library: caller's process (CLI, daemon, embedder)"


def gate_places():
    t = open(os.path.join(ROOT, "xtask/src/check_helper_env_hygiene.rs")).read()
    body = t[t.index("const RAW_SITES"):t.index("const HELPER_SPAWNS")]
    return {(f, fn): w for w, f, fn, _ in re.findall(r'(guest|builder|on_host)\(\s*"([^"]+)",\s*"([^"]+)",\s*"((?:[^"\\]|\\.)*)"', body)}


def guard(rel, kinds, places, fns):
    g = []
    if any(k in ("helper_command", "helper_command_with") for k in kinds):
        g.append("`helper_command` env scrub")
    if any(k == "Command::new" or k.startswith(("raw:", "libc::")) for k in kinds):
        pl = {places.get((rel, f)) or next((w for (gf, _), w in places.items() if gf == rel and None in fns), None) for f in fns}
        g.append("RAW_SITES (" + "/".join(sorted(p for p in pl if p)) + ")" if pl - {None} else "UNCLASSIFIED raw spawn")
    src = open(os.path.join(ROOT, rel)).read()
    if "refuse_cli_spawn" in src or "CliSpawn::" in src:
        g.append("embedder refusal")
    if "network_endpoint" in rel or "gpu_endpoint" in rel:
        g.append("check-single-network-path")
    if crate_of(rel) in ("mvm-client", "mvm-hostlib", "mvm-sdk"):
        g.append("check-no-cli-shellout")
    return "; ".join(g)


def render():
    sites, defs = scan()
    clos, tr = closures(), traced(sites, defs)
    places = gate_places()
    by = collections.OrderedDict()
    for s in sites:
        by.setdefault(s["file"], []).append(s)
    missing = [f for f in by if f.replace("crates/", "", 1) not in A]
    if missing:
        sys.exit("unannotated spawn files (add to ANNOTATIONS in this script):\n  " + "\n  ".join(missing))
    stale = [f for f in A if "crates/" + f not in by]
    if stale:
        sys.exit("annotations with no spawn site left:\n  " + "\n  ".join(stale))
    rows = []
    for f, v in by.items():
        k = f.replace("crates/", "", 1)
        c = crate_of(f)
        cls, why = A[k]
        auth = AUTH_OVERRIDE.get(k) or AUTH.get(c, LIB_AUTH)
        linked = "".join(l for l, n in (("C", "mvm-client"), ("H", "mvm-hostlib"), ("S", "mvm-sdk")) if c in clos[n]) or "-"
        t = "".join(l for l, n in (("C", "mvm-client"), ("H", "mvm-hostlib"), ("S", "mvm-sdk"))
                    if any((f, x["fn"]) in tr[n] for x in v)) or "-"
        kinds = [x["kind"] for x in v]
        t = "".join(ch for ch in t if ch in linked)
        t = t or "-"
        rows.append((c, k.split("/", 1)[1], len(v), cls, why, auth, linked, t, guard(f, kinds, places, {x["fn"] for x in v})))
    rows.sort(key=lambda r: (r[0], r[1]))
    cc = collections.Counter()
    for r in rows:
        cc[r[0]] += r[2]
    out = ["| Crate | Module (under `src/` unless a crate root file) | Sites | Class | Purpose | Authority | Linked | Traced | Guard |",
           "|---|---|--:|---|---|---|:-:|:-:|---|"]
    for r in rows:
        out.append("| %s | `%s` | %d | %s | %s | %s | %s | %s | %s |" % r)
    out += ["", "Totals: %d production sites in %d files." % (sum(cc.values()), len(rows)), "",
            "| Crate | Sites |", "|---|--:|"] + ["| %s | %d |" % kv for kv in sorted(cc.items())]
    kinds = collections.Counter(s["kind"] for s in sites)
    out += ["", "By construct: " + ", ".join("`%s` %d" % kv for kv in sorted(kinds.items())) + "."]
    return "\n".join(out)


def main():
    table = render()
    doc = open(DOC).read()
    a, b = doc.index(BEGIN) + len(BEGIN), doc.index(END)
    new = doc[:a] + "\n" + table + "\n" + doc[b:]
    if "--check" in sys.argv:
        if new != doc:
            sys.exit("process-spawn-inventory.md is stale; run scripts/gen-process-spawn-inventory.py")
        return
    open(DOC, "w").write(new)


if __name__ == "__main__":
    main()
