#!/usr/bin/env python3
"""Summarize per-launch receipt latency, refusing missing or wrong-mode samples."""

import json
import math
import sys
from pathlib import Path


def percentile(values: list[float], percent: int) -> float:
    """Nearest-rank percentile, including small waves without extrapolation."""
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * percent / 100) - 1]


def summarize(
    wave_dir: Path, wave: int, mode: str, image: str, cpus: int, memory: str
) -> str:
    if wave < 1:
        raise ValueError("wave count must be positive")
    if mode not in ("cold", "warm"):
        raise ValueError(f"invalid launch mode: {mode}")
    details = []
    names = set()
    for line in (wave_dir / "launches.tsv").read_text().splitlines():
        fields = line.split("\t")
        if len(fields) != 5:
            raise ValueError("launch record must have five tab-separated fields")
        name, _, _, _, started = fields
        if not name or "/" in name or "\\" in name or name in names:
            raise ValueError(f"invalid or repeated launch label: {name!r}")
        names.add(name)
        started_ns = int(started)
        if started_ns <= 0:
            raise ValueError(f"{name}: invalid launch timestamp")
        receipt = wave_dir / f"{name}.receipt.json"
        parsed = json.loads(receipt.read_text())
        if parsed["payload"]["schema_version"] != 1:
            raise ValueError(f"{name}: unexpected receipt schema")
        invocation = parsed["payload"]["invocation"]
        if (invocation["image"], invocation["cpus"], invocation["memory"]) != (
            image, cpus, memory
        ):
            raise ValueError(f"{name}: receipt launch shape does not match")
        # The signed invocation has no machine_name. The harness gives each
        # invocation a unique receipt and sample path, paired by launch label.
        sample = wave_dir / f"{name}.sample.json"
        measured = json.loads(sample.read_text())
        if measured["schema_version"] != 4:
            raise ValueError(f"{name}: unexpected launch sample schema")
        if measured["launch_mode"] != mode:
            raise ValueError(f"{name}: expected {mode} launch, got {measured['launch_mode']}")
        elapsed_ns = receipt.stat().st_mtime_ns - started_ns
        if elapsed_ns < 0:
            raise ValueError(f"{name}: receipt predates launch")
        if sample.stat().st_mtime_ns < started_ns:
            raise ValueError(f"{name}: sample predates launch")
        details.append((name, elapsed_ns / 1_000_000))

    if len(details) != wave:
        raise ValueError(f"expected {wave} receipt/sample pairs, got {len(details)}")
    (wave_dir / "boot-receipt-ms.tsv").write_text(
        "machine\telapsed_ms\n"
        + "".join(f"{name}\t{elapsed:.3f}\n" for name, elapsed in details)
    )
    durations = [elapsed for _, elapsed in details]
    return "".join(
        f"wave_{wave}_boot_receipt_p{percent}_ms\t{percentile(durations, percent):.3f}\n"
        for percent in (50, 95, 99)
    )


def main() -> int:
    if len(sys.argv) != 7:
        print(
            "usage: density_timings.py WAVE_DIR WAVE_COUNT MODE IMAGE CPUS MEMORY",
            file=sys.stderr,
        )
        return 64
    try:
        print(
            summarize(
                Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3],
                sys.argv[4], int(sys.argv[5]), sys.argv[6],
            ),
            end="",
        )
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"density boot timing unavailable: {error}", file=sys.stderr)
        return 71
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
