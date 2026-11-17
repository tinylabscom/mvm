#!/usr/bin/env python3
"""Snapshot macOS process memory charges, never equating summed RSS with host RAM."""

import json
import struct
import sys
import time
from pathlib import Path

from density_idle import Libproc, component_of


def memory_from_rusage(raw: bytes) -> tuple[int, int, int]:
    """Resident bytes, physical-footprint bytes and birth time from rusage_info_v4.

    sys/resource.h places these after the 16-byte UUID and six uint64 fields.
    Birth time distinguishes reused PIDs when comparing snapshots.
    """
    return struct.unpack_from("<QQQ", raw, 64)


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
    if sys.platform != "darwin":
        report = {"schema_version": 1, "status": "unavailable", "reason": "unsupported_platform"}
    else:
        try:
            report = collect(Libproc())
        except OSError:
            report = {"schema_version": 1, "status": "unavailable", "reason": "libproc_failed"}
    path = Path(sys.argv[1]) / f"physical-memory-{sys.argv[2]}.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
