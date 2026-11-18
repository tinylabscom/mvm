#!/usr/bin/env python3
"""Snapshot per-process memory charges, never equating summed RSS with host RAM.

macOS reports physical footprint; Linux reports proportional set size. The two
are different quantities and the capture names which one it holds.
"""

import json
import struct
import sys
import time
from pathlib import Path

from density_idle import Libproc, component_of

PROC_ROOT = Path("/proc")


def memory_from_rusage(raw: bytes) -> tuple[int, int, int]:
    """Resident bytes, physical-footprint bytes and birth time from rusage_info_v4.

    sys/resource.h places these after the 16-byte UUID and six uint64 fields.
    Birth time distinguishes reused PIDs when comparing snapshots.
    """
    return struct.unpack_from("<QQQ", raw, 64)


def kib_field(text: str, name: str) -> int:
    for line in text.splitlines():
        if line.startswith(name + ":"):
            return int(line.split(":", 1)[1].split()[0]) * 1024
    raise ValueError(f"smaps_rollup has no {name} line")


def program_of(directory: Path) -> str:
    return (directory / "cmdline").read_bytes().split(b"\0", 1)[0].decode(errors="replace")


def collect_linux(proc_root: Path) -> dict:
    started = time.monotonic_ns()
    records = []
    unclassified = 0
    for directory in proc_root.iterdir():
        if not directory.name.isdigit():
            continue
        pid = int(directory.name)
        try:
            component = component_of(program_of(directory))
        except OSError:
            unclassified += 1
            continue
        if component is None:
            continue
        row = {
            "pid": pid,
            "component": component,
            "status": "unavailable",
            "resident_bytes": None,
            "proportional_set_size_bytes": None,
        }
        try:
            rollup = (directory / "smaps_rollup").read_text()
            if component_of(program_of(directory)) != component:
                raise OSError("process identity changed during sampling")
            row.update(
                status="measured",
                resident_bytes=kib_field(rollup, "Rss"),
                proportional_set_size_bytes=kib_field(rollup, "Pss"),
            )
        except (OSError, ValueError):
            pass
        records.append(row)
    partial = unclassified > 0 or any(row["status"] != "measured" for row in records)
    return {
        "schema_version": 1,
        "status": "partial" if partial else "measured",
        "quantity": "proportional_set_size",
        "scope": "host_wide_matching_processes",
        "source": "/proc/<pid>/smaps_rollup",
        "units": "bytes",
        "capture_started_monotonic_ns": started,
        "capture_finished_monotonic_ns": time.monotonic_ns(),
        "semantics": "per-process charges, not an exclusive host-memory total",
        "unclassified_processes": unclassified,
        "processes": records,
    }


def collect(reader: Libproc) -> dict:
    started = time.monotonic_ns()
    records = []
    unclassified = 0
    for pid in reader.pids():
        try:
            component = component_of(reader.program(pid))
        except OSError:
            unclassified += 1
            continue
        if component is None:
            continue
        try:
            _, _, first_birth = memory_from_rusage(reader.rusage(pid))
            confirmed_component = component_of(reader.program(pid))
            resident, footprint, born = memory_from_rusage(reader.rusage(pid))
            if first_birth != born or confirmed_component != component:
                raise OSError("process identity changed during sampling")
            records.append({
                "pid": pid,
                "component": component,
                "status": "measured",
                "resident_bytes": resident,
                "physical_footprint_bytes": footprint,
                "process_start_abstime": born,
            })
        except (OSError, struct.error):
            records.append({
                "pid": pid,
                "component": component,
                "status": "unavailable",
                "resident_bytes": None,
                "physical_footprint_bytes": None,
                "process_start_abstime": None,
            })
    partial = unclassified > 0 or any(row["status"] != "measured" for row in records)
    return {
        "schema_version": 1,
        "status": "partial" if partial else "measured",
        "quantity": "physical_footprint",
        "scope": "host_wide_matching_processes",
        "source": "proc_pid_rusage RUSAGE_INFO_V4",
        "units": "bytes",
        "capture_started_monotonic_ns": started,
        "capture_finished_monotonic_ns": time.monotonic_ns(),
        "semantics": "per-process charges, not an exclusive host-memory total",
        "unclassified_processes": unclassified,
        "processes": records,
    }


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[2] not in ("before", "settled", "after-cleanup"):
        print("usage: density_memory.py WAVE_DIR before|settled|after-cleanup", file=sys.stderr)
        return 64
    if sys.platform == "darwin":
        try:
            report = collect(Libproc())
        except OSError:
            report = {"schema_version": 1, "status": "unavailable", "reason": "libproc_failed"}
    elif sys.platform.startswith("linux"):
        try:
            report = collect_linux(PROC_ROOT)
        except OSError:
            report = {"schema_version": 1, "status": "unavailable", "reason": "procfs_unreadable"}
    else:
        report = {"schema_version": 1, "status": "unavailable", "reason": "unsupported_platform"}
    path = Path(sys.argv[1]) / f"physical-memory-{sys.argv[2]}.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
