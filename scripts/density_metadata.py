#!/usr/bin/env python3
"""Describe a density run without treating configuration as measured evidence."""

import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def probe(*command: str) -> str | None:
    """Unavailable host tools leave missing metadata, never invented values."""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=5, check=True
        )
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def fingerprint(path: Path) -> dict:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return {"status": "measured", "sha256": digest.hexdigest()}
    except OSError:
        return {"status": "unavailable", "sha256": None}


def linux_cpu(cpuinfo: Path = Path("/proc/cpuinfo")) -> str | None:
    """The first `model name`; aarch64 kernels publish none, which stays missing."""
    try:
        for line in cpuinfo.read_text().splitlines():
            key, _, value = line.partition(":")
            if key.strip() == "model name" and value.strip():
                return value.strip()
    except OSError:
        pass
    return None


def linux_os_build(
    os_release: Path = Path("/etc/os-release"), kernel: str | None = None
) -> str | None:
    """`PRETTY_NAME (kernel release)`, or whichever half is available."""
    pretty = None
    try:
        for line in os_release.read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                pretty = line.split("=", 1)[1].strip().strip('"') or None
    except OSError:
        pass
    kernel = platform.release() if kernel is None else kernel
    if pretty and kernel:
        return f"{pretty} ({kernel})"
    return pretty or kernel


def collect(root: Path, summary: dict[str, str], environ: dict[str, str]) -> dict:
    system = platform.system()
    working_tree_status = probe(
        "git", "-C", str(root), "--no-optional-locks",
        "status", "--porcelain", "--untracked-files=normal",
    )
    native_guard_bypassed = environ.get("MVM_HVF_DENSITY_ALLOW_UNSUPPORTED") == "1"
    busy_guard_bypassed = environ.get("MVM_HVF_DENSITY_ALLOW_BUSY_HOST") == "1"
    artifacts = {
        key: fingerprint(Path(summary[key]))
        for key in ("mvmctl", "network_endpoint")
    }
    if summary["backend"] == "hvf":
        artifacts["supervisor"] = fingerprint(Path(summary["supervisor"]))
    arch = {"arm64": "aarch64"}.get(platform.machine(), platform.machine())
    artifacts["cached_kernel"] = fingerprint(
        Path(summary["cache_dir"]) / "kernels" / arch / "workload/vmlinux"
    )
    return {
        "schema_version": 1,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "status": "metadata_only",
        "source": {
            "revision": probe("git", "-C", str(root), "rev-parse", "HEAD"),
            "dirty": None if working_tree_status is None else bool(working_tree_status),
            "note": "Source revision does not attest the provenance of reused binaries.",
        },
        "host": {
            "os": system,
            "kernel_release": platform.release(),
            "architecture": platform.machine(),
            "logical_cpus": os.cpu_count(),
            "memory_mib": int(summary["host_memory_mib"]),
            "os_build": (
                probe("sw_vers", "-buildVersion") if system == "Darwin"
                else linux_os_build() if system == "Linux" else None
            ),
            "hardware_model": probe("sysctl", "-n", "hw.model") if system == "Darwin" else None,
            "cpu": (
                probe("sysctl", "-n", "machdep.cpu.brand_string") if system == "Darwin"
                else linux_cpu() if system == "Linux" else None
            ),
            "power": probe("pmset", "-g", "batt") if system == "Darwin" else None,
        },
        "configuration": {
            key: summary[key] for key in (
                "run_id", "image", "backend", "launch_mode", "standby_form", "endpoint_form",
                "waves", "memory", "cpus", "settle_seconds", "idle_sample_seconds",
                "custom_workload", "build_profile",
            )
        },
        "guards": {
            "native_host_bypassed": native_guard_bypassed,
            "busy_host_bypassed": busy_guard_bypassed,
        },
        "artifacts": artifacts,
        "boundaries": {
            "first_use_preparation": "outside_measured_wave",
            "receipt_latency": "launch_timestamp_to_completion_receipt_file_mtime",
            "receipt_latency_includes": "CLI startup, admission, execution and receipt publication",
            "agent_readiness": "not_measured_separately",
            "workload_readiness": "not_measured_separately",
            "rss": "host_wide_matching_processes; KiB; shared pages may be counted repeatedly",
            "idle": "host_wide_matching_processes; see idle-sample artifacts for availability",
            "physical_footprint": "macOS per-process byte charges; see physical-memory-*.json for availability",
            "artifact_hashes": "file_identity_only_not_signature_verification",
        },
        "evidence": {
            "classification": "non_native_or_fixture" if native_guard_bypassed else "native_requested",
            "completion": "not_asserted; inspect launch failures, timing availability and cleanup",
        },
    }


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: density_metadata.py REPO_ROOT SUMMARY_TSV", file=sys.stderr)
        return 64
    summary = dict(
        line.split("\t", 1)
        for line in Path(sys.argv[2]).read_text().splitlines()[1:]
    )
    print(json.dumps(collect(Path(sys.argv[1]), summary, os.environ), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
