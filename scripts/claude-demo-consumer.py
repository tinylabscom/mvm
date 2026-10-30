#!/usr/bin/env python3
"""Operator-gated public Claude witness. A live invocation can incur one model charge."""

import importlib.util
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
import uuid


spec = importlib.util.spec_from_file_location(
    "claude_preflight", Path(__file__).with_name("claude-demo-preflight.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
require = base.require
Blocked = base.Blocked
PROMPT = b"tell me a joke\n"
MODEL = "claude-haiku-4-5-20251001"
BUDGET = {"max_requests": 1, "max_spend_microusd": 500000, "model": MODEL}
UNBOUND = "00000000-0000-0000-0000-000000000000"


def live_prerequisites(args):
    require(os.environ.get("MVM_TEST_CLAUDE_DEMO") == "1"
            and args.authorize_model_request,
            "live dispatch requires opt-in and --authorize-model-request")
    require(args.budget_usd == "0.50", "only the explicitly authorized $0.50 ceiling is supported")
    require(args.check_readiness, "live dispatch requires --check-readiness and exact public pins")
    base.witness.validate_platform("hvf", platform.system(), platform.machine(), False, os.getuid())
    for name in ("runtime_archive_sha256", "rootfs_sha256", "rootfs_roothash",
                 "runtime_overlay_roothash", "kernel_sha256"):
        base.sha256(getattr(args, name))
    require(bool(args.runtime_version), "expected runtime version missing")
    base.released_cli(args.cli, args.cli_sha256)
    immutable = getattr(stat, "UF_IMMUTABLE", 0) | getattr(stat, "SF_IMMUTABLE", 0)
    require(bool(getattr(args.cli.stat(), "st_flags", 0) & immutable),
            "live CLI must have an OS immutable flag; runner never changes permissions or flags")


def signed_prerequisites(info, args):
    source = info.get("bundle", {}).get("source")
    parsed = urlsplit(args.archive_url)
    require(source == args.archive_url and parsed.scheme == "https" and parsed.hostname
            and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment,
            "verified public archive URL assertion mismatch or credential-bearing URL")
    manifest = info.get("bundle_manifest")
    require(isinstance(manifest, dict), "released CLI must expose the verified bundle manifest")
    environments = [member for member in manifest.get("members", [])
                    if member.get("class") == "environment"]
    require(len(environments) == 1, "one verified signed environment is required")
    environment = environments[0]
    require(environment.get("pack") == {"name": "agent/claude", "version": "2.0.0"},
            "signed environment application identity mismatch")
    require(environment.get("target") == "aarch64-linux", "signed guest target mismatch")
    policy = environment.get("policy", {})
    require(policy.get("allow_hosts") == ["api.anthropic.com:443"]
            and policy.get("request_budget") == BUDGET,
            "signed environment must enforce the one-request Anthropic-only $0.50 ceiling")
    require(environment.get("secret_slots") == [{"name": "ANTHROPIC_API_KEY", "required": True}],
            "signed environment must require exactly the Anthropic host binding")
    require(bool(environment.get("entrypoint", {}).get("argv")), "signed default entrypoint missing")
    require(manifest.get("verity", {}).get("roothash") == args.rootfs_roothash,
            "signed rootfs root hash mismatch")
    for role, expected in (("kernel", args.kernel_sha256), ("rootfs", args.rootfs_sha256)):
        artifacts = [artifact for artifact in manifest.get("artifacts", [])
                     if artifact.get("role") == role]
        require(len(artifacts) == 1 and artifacts[0].get("sha256") == expected,
                f"signed {role} identity mismatch")


def reserve_attempt(args, evidence):
    path = args.mvm_home / "claude-demo-attempt.json"
    record = {"schema_version": 1, "cli_sha256": args.cli_sha256,
              "descriptor_sha256": args.descriptor_sha256, "evidence": str(evidence),
              "budget": BUDGET}
    # Reserve before spawning, durably. Neither failure nor interruption releases it.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(record, stream)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(args.mvm_home, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return path


def persist(evidence, report):
    (evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")


def dispatch_once(args, env, evidence, report):
    marker = reserve_attempt(args, evidence)
    report.update(status="custody_unconfirmed", attempt_reservation=str(marker),
                  model_request_attempted=None, native_dispatch_attempted=True,
                  cleanup_authorized=False)
    record = {"label": "joke", "argv": [str(args.cli), "run", "agent/claude"],
              "stdin_sha256": base.hashlib.sha256(PROMPT).hexdigest(),
              "stdout": "joke.stdout", "stderr": "joke.stderr"}
    report["commands"].append(record)
    persist(evidence, report)
    # Regular private log files keep the original CLI independent of this
    # observer's lifetime. No group kill, numeric signal, stop or credential cleanup.
    read_fd, write_fd = os.pipe()
    with os.fdopen(read_fd, "rb") as stdin, os.fdopen(write_fd, "wb") as prompt, \
            (evidence / "joke.stdout").open("xb") as stdout, \
            (evidence / "joke.stderr").open("xb") as stderr:
        # This fixed 14-byte payload fits in an empty pipe. Make bytes and EOF
        # ready before exec: the CLI intentionally ignores idle inherited pipes.
        prompt.write(PROMPT)
        prompt.close()
        process = subprocess.Popen(record["argv"], cwd=evidence, env=env,
                                   stdin=stdin, stdout=stdout, stderr=stderr,
                                   start_new_session=True)
        record["owner_pid_observation_only"] = process.pid
        persist(evidence, report)
        try:
            record["returncode"] = process.wait(timeout=args.run_timeout)
        finally:
            persist(evidence, report)
    require(record["returncode"] == 0, "joke command failed; retain original owner and evidence")
    paths = [evidence / "joke.stdout", evidence / "joke.stderr"]
    require(all(path.stat().st_size <= base.witness.LIMIT for path in paths),
            "native output exceeded evidence limit; full private files retained")
    require(paths[0].read_bytes().strip(), "native stdout response was empty")


def unique_event(entries, name):
    matches = [entry for entry in entries if entry.get("event") == name]
    require(len(matches) == 1, f"expected exactly one canonical {name} event")
    return matches[0]


def assert_evidence(args, verification, entries, host_entries):
    plan_id = verification.get("plan_id")
    require(verification.get("tenant") == "local" and verification.get("verdict") == "VERIFIED"
            and verification.get("late_entries") == 0 and verification.get("seals"),
            "canonical session verification is not complete")
    require(entries and all(entry.get("plan_id") == plan_id
                            and entry.get("tenant") == "local" for entry in entries),
            "session entries are not correlated to the verified plan")
    require(host_entries and all(entry.get("plan_id") == UNBOUND
                                 and entry.get("tenant") == "local" for entry in host_entries),
            "host audit entries are not from the verified local unbound stream")
    require(not any(entry.get("event") in ("plan.failed", "plan.admission_refused") for entry in entries),
            "session contains a canonical launch failure")
    admitted = unique_event(entries, "plan.admitted")
    launched = unique_event(entries, "plan.launched")
    exited = unique_event(entries, "plan.exited")
    completed = unique_event(entries, "plan.native_completed")
    require(launched.get("labels", {}).get("backend") == "hvf"
            and exited.get("labels", {}).get("backend") == "hvf"
            and exited.get("labels", {}).get("exit_code") == "0"
            and exited.get("labels", {}).get("captured") == "true",
            "automatic native HVF launch and captured zero exit are not established")
    require(admitted.get("labels", {}).get("kernel_sha256") == args.kernel_sha256
            and admitted.get("image_sha256") == args.rootfs_sha256,
            "admitted image/kernel identities mismatch")
    require(admitted.get("caller_commitment"), "native caller commitment missing")
    labels = completed.get("labels", {})
    require(labels.get("bundle_sha256") == args.archive_sha256, "completed bundle identity mismatch")
    proof = json.loads(labels.get("native_completion", "null"))
    require(isinstance(proof, dict), "original-owner native completion missing")
    for field in ("rootfs_sha256", "rootfs_roothash", "runtime_archive_sha256",
                  "runtime_version", "runtime_overlay_roothash"):
        require(proof.get(field) == getattr(args, field), f"native identity mismatch: {field}")
    instance = proof.get("instance", {})
    require(isinstance(instance, dict), "original native instance evidence is malformed")
    vm = instance.get("vm_id")
    nonce = instance.get("boot_nonce")
    require(isinstance(vm, str) and vm and isinstance(nonce, list) and len(nonce) == 32
            and all(type(byte) is int and 0 <= byte <= 255 for byte in nonce) and any(nonce),
            "original native generation identity missing")
    network = proof.get("network_policy", {})
    require(isinstance(network, dict), "effective native network evidence is malformed")
    require(network.get("type") == "allowlist"
            and network.get("rules") == [{"host": "api.anthropic.com", "port": 443}]
            and not network.get("peers") and not network.get("routes")
            and network.get("ai", {}).get("request_budget") == BUDGET,
            "completed native owner did not retain the required effective network ceiling")
    reservations = [entry for entry in host_entries if entry.get("event") == "host.ai.budget_reserved"]
    samples = [entry for entry in host_entries if entry.get("event") == "host.ai.usage"]
    require(len(reservations) == 1 and len(samples) == 1,
            "requires one reservation and one provider response; no retries or extra requests")
    reservation = reservations[0].get("labels", {})
    sample = samples[0].get("labels", {})
    budget_id = reservation.get("budget_id")
    require(isinstance(budget_id, str) and str(uuid.UUID(budget_id)) == budget_id
            and uuid.UUID(budget_id).int != 0,
            "endpoint budget lifetime identity missing")
    require(reservation.get("vm") == vm and sample.get("vm") == vm
            and sample.get("budget_id") == budget_id,
            "endpoint lifetime and original-owner run identity do not correlate")
    require(json.loads(reservation.get("request_budget", "null")) == BUDGET
            and reservation.get("host") == "api.anthropic.com"
            and reservation.get("port") == "443"
            and reservation.get("reserved_requests") == "1"
            and 0 < int(reservation.get("reserved_spend_microusd", "0")) <= 500000,
            "canonical pre-forward enforcement reservation mismatch")
    require(json.loads(reservation.get("secret_bindings", "null")) == [args.binding_name],
            "the admitted attempt did not use the expected host-held binding")
    substitutions = [entry for entry in host_entries if entry.get("event") == "secret.substituted"]
    require(len(substitutions) == 1
            and substitutions[0].get("labels", {}).get("name") == args.binding_name
            and substitutions[0].get("labels", {}).get("destination") == "api.anthropic.com"
            and substitutions[0].get("labels", {}).get("auth_type") == "bearer",
            "canonical credential-substitution handoff evidence missing")
    forwards = [entry for entry in host_entries if entry.get("event") == "secret.forward_outcome"]
    require(len(forwards) == 1
            and forwards[0].get("labels", {}).get("destination") == "api.anthropic.com"
            and forwards[0].get("labels", {}).get("outcome") == "completed"
            and forwards[0].get("labels", {}).get("via") == "direct",
            "complete direct Anthropic response delivery is not established")
    require(sample.get("provider") == "anthropic" and sample.get("host") == "api.anthropic.com"
            and sample.get("port") == "443" and sample.get("method") == "POST"
            and sample.get("path") == "/v1/messages" and sample.get("status") == "200"
            and sample.get("budget_exceeded") == "false"
            and sample.get("model") in (None, MODEL),
            "successful correlated Anthropic model response evidence missing")
    spent = int(reservation["reserved_spend_microusd"])
    output_tokens = int(sample.get("output_tokens", "0"))
    require(spent > 400000 and (spent - 400000) % 5 == 0
            and 0 < output_tokens <= (spent - 400000) // 5 <= 20000,
            "reported output does not fit the conservative exact-model reservation")
    return {"plan_id": plan_id, "audit_session_id": plan_id, "run_id": vm,
            "native_boot_nonce": nonce, "endpoint_budget_id": budget_id,
            "native_completion": proof, "audit_verdict": verification,
            "requested_model": MODEL, "reported_model": sample.get("model"),
            "reported_output_tokens": output_tokens, "reserved_spend_microusd": spent,
            "host_binding": args.binding_name}


def collect(args, runner, env):
    sessions = json.loads(runner.run("sessions", [
        args.cli, "trust", "audit", "sessions", "--json"], env)["stdout"])
    require(sessions.get("tenant") == "local" and sessions.get("ledger", {}).get("intact") is True,
            "canonical session ledger is not intact")
    require(len(sessions.get("sessions", [])) == 1, "isolated consumer must have exactly one session")
    plan_id = sessions["sessions"][0]["plan_id"]
    require(isinstance(plan_id, str) and plan_id.startswith("sha256:")
            and base.sha256(plan_id.removeprefix("sha256:")), "invalid session plan identity")
    verification = json.loads(runner.run("audit-verify", [
        args.cli, "trust", "audit", "verify", plan_id, "--json"], env)["stdout"])
    require(verification.get("plan_id") == plan_id, "audit verifier returned another session")
    def events(label, selector):
        rows = json.loads(runner.run(label, [
            args.cli, "trust", "audit", "show", selector, "--json"], env)["stdout"])
        return [row["envelope"]["entry"] for row in rows]
    return assert_evidence(args, verification, events("session-events", plan_id),
                           events("endpoint-events", UNBOUND))


def main():
    parser = base.parser()
    parser.description = __doc__
    parser.add_argument("--authorize-model-request", action="store_true")
    parser.add_argument("--budget-usd", required=True)
    parser.add_argument("--archive-url", required=True)
    parser.add_argument("--run-timeout", type=int, default=180)
    for name in ("runtime-version", "runtime-archive-sha256", "runtime-overlay-roothash",
                 "rootfs-sha256", "rootfs-roothash", "kernel-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    evidence = Path(tempfile.mkdtemp(prefix="mvm-claude-consumer-", dir="/tmp"))
    report = {"status": "blocked", "commands": [], "demo_acceptance": False,
              "model_request_attempted": False, "guest_boot_witnessed": False,
              "custody_verified": False, "credential_cleanup_attempted": False}
    runner = base.witness.Runner(evidence, report)
    try:
        require(1 <= args.run_timeout <= 300, "run timeout must be in 1..300 seconds")
        live_prerequisites(args)
        env = base.preflight(args, runner, report)
        signed_prerequisites(report["verified_application"], args)
        runner.run("cli-signature", ["/usr/bin/codesign", "--verify", "--strict", args.cli], env)
        identity = base.released_cli(args.cli, args.cli_sha256)
        dispatch_once(args, env, evidence, report)
        report["correlation"] = collect(args, runner, env)
        verified = json.loads(runner.run("verify-after", [
            args.cli, "pack", "verify", base.REFERENCE, "--json"], env)["stdout"])
        base.assert_application(verified, args)
        signed_prerequisites(verified, args)
        require(base.released_cli(args.cli, args.cli_sha256) == identity,
                "released executable identity changed during witness")
        report.update(status="passed", demo_acceptance=True,
                      model_request_attempted=True, guest_boot_witnessed=True,
                      custody_verified=True)
    except (Exception, KeyboardInterrupt) as error:
        report["status"] = "blocked"
        report["blocker"] = str(error) if isinstance(error, Blocked) else type(error).__name__
        if report.get("native_dispatch_attempted"):
            report["recovery"] = (
                "Retain consumer HOME, original CLI owner and all evidence. "
                "Do not retry, signal a numeric PID, or delete credentials based on process absence.")
    finally:
        persist(evidence, report)
    print(json.dumps({"status": report["status"], "evidence": str(evidence),
                      "demo_acceptance": report["demo_acceptance"]}))
    return 0 if report["demo_acceptance"] else 1


if __name__ == "__main__":
    sys.exit(main())
