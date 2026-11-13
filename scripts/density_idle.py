#!/usr/bin/env python3
"""Sample idle CPU, wakeups, threads and descriptors of a density wave's host processes.

Linux only: every figure is read from procfs. Wakeups are voluntary context
switches summed over a process's threads, so a thread that blocks and is woken
counts once per wake.
"""

import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

COMPONENTS = (
    "mvm-hvf-supervisor",
    "firecracker",
    "mvm-network-endpoint",
    "mvm-mailbox",
    "mvm-host-agent",
    "mvm-signer-helper",
    "mvm-host-signer",
    "mvm-audit-signer",
    "mvm-broker",
    "mvmctl",
)
UNAVAILABLE = "unavailable:linux_procfs_only"


@dataclass(frozen=True)
class ProcessSample:
    component: str
    threads: int
    descriptors: int
    cpu_ticks: int
    voluntary_switches: int


def component_of(program: str) -> str | None:
    """Match the program's own file name, never a path or an argument.

    A wave's output directory is named for its backend, so matching anywhere
    in the command line would count every helper as that backend's VMM.
    """
    base = program.rsplit("/", 1)[-1]
    for name in COMPONENTS:
        if base == name or base.startswith(name + "-"):
            return name
    return None


def cpu_ticks(stat_text: str) -> int:
    """utime + stime. The command name may hold spaces or parentheses."""
    fields = stat_text.rsplit(")", 1)[1].split()
    return int(fields[11]) + int(fields[12])


def voluntary_switches(status_text: str) -> int:
    for line in status_text.splitlines():
        if line.startswith("voluntary_ctxt_switches:"):
            return int(line.split(":", 1)[1])
    raise ValueError("status has no voluntary_ctxt_switches line")


def sample_process(directory: Path) -> ProcessSample | None:
    program = (directory / "cmdline").read_bytes().split(b"\0", 1)[0].decode(errors="replace")
    component = component_of(program)
    if component is None:
        return None
    tasks = [task for task in (directory / "task").iterdir() if task.name.isdigit()]
    return ProcessSample(
        component=component,
        threads=len(tasks),
        descriptors=sum(1 for _ in (directory / "fd").iterdir()),
        cpu_ticks=cpu_ticks((directory / "stat").read_text()),
        voluntary_switches=sum(
            voluntary_switches((task / "status").read_text()) for task in tasks
        ),
    )


def sample(proc_root: Path, skip: frozenset[int] = frozenset()) -> dict[int, ProcessSample]:
    """One pass over procfs. A process that exits mid-read is left out."""
    found = {}
    for directory in proc_root.iterdir():
        if not directory.name.isdigit() or int(directory.name) in skip:
            continue
        try:
            taken = sample_process(directory)
        except (OSError, ValueError, IndexError):
            continue
        if taken is not None:
            found[int(directory.name)] = taken
    return found


def summarize(
    before: dict[int, ProcessSample],
    after: dict[int, ProcessSample],
    seconds: float,
    ticks_per_second: int,
) -> list[tuple[str, int, int, int, float, float]]:
    """Per component: processes, threads, descriptors, CPU millicores, wakeups per second.

    Only processes present in both passes are counted, so a rate is never
    computed from a process that started or exited inside the window.
    """
    if seconds <= 0 or ticks_per_second <= 0:
        raise ValueError("window and tick rate must be positive")
    rows = []
    for name in COMPONENTS:
        pids = [
            pid
            for pid, taken in after.items()
            if taken.component == name and pid in before and before[pid].component == name
        ]
        if not pids:
            continue
        ticks = sum(after[pid].cpu_ticks - before[pid].cpu_ticks for pid in pids)
        wakes = sum(
            after[pid].voluntary_switches - before[pid].voluntary_switches for pid in pids
        )
        if ticks < 0 or wakes < 0:
            raise ValueError(f"{name}: a counter went backwards; a pid was reused")
        rows.append(
            (
                name,
                len(pids),
                sum(after[pid].threads for pid in pids),
                sum(after[pid].descriptors for pid in pids),
                ticks / ticks_per_second / seconds * 1000,
                wakes / seconds,
            )
        )
    return rows


def render(rows: list[tuple[str, int, int, int, float, float]], wave: int) -> tuple[str, str]:
    table = "component\tprocesses\tthreads\tdescriptors\tcpu_millicores\twakeups_per_second\n"
    summary = ""
    for name, processes, threads, descriptors, millicores, wakeups in rows:
        table += f"{name}\t{processes}\t{threads}\t{descriptors}\t{millicores:.1f}\t{wakeups:.1f}\n"
        key = f"wave_{wave}_idle_{name}"
        summary += (
            f"{key}_threads\t{threads}\n"
            f"{key}_descriptors\t{descriptors}\n"
            f"{key}_cpu_millicores\t{millicores:.1f}\n"
            f"{key}_wakeups_per_second\t{wakeups:.1f}\n"
        )
    return table, summary


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: density_idle.py WAVE_DIR WAVE_COUNT WINDOW_SECONDS", file=sys.stderr)
        return 64
    try:
        wave_dir, wave, seconds = Path(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
        if wave < 1:
            raise ValueError("wave count must be positive")
        proc_root = Path("/proc")
        if not (proc_root / "self" / "stat").is_file():
            print(f"wave_{wave}_idle_sampler\t{UNAVAILABLE}")
            return 0
        own = frozenset({os.getpid()})
        started = time.monotonic()
        before = sample(proc_root, own)
        time.sleep(seconds)
        after = sample(proc_root, own)
        elapsed = time.monotonic() - started
        rows = summarize(before, after, elapsed, os.sysconf("SC_CLK_TCK"))
        table, summary = render(rows, wave)
        (wave_dir / "idle-settled.tsv").write_text(table)
        print(f"wave_{wave}_idle_window_seconds\t{elapsed:.1f}\n{summary}", end="")
    except (OSError, ValueError) as error:
        print(f"density idle sample unavailable: {error}", file=sys.stderr)
        return 71
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
