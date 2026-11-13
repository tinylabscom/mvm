#!/usr/bin/env python3
"""Sample idle CPU, wakeups, threads and descriptors of a density wave's host processes.

Linux reads procfs; wakeups are voluntary context switches summed over a
process's threads, so a thread that blocks and is woken counts once per wake.

macOS reads libproc through ctypes (no subprocess, no third-party package) and
sees only processes the caller may inspect, which includes the caller's own.
CPU is user plus system time converted from mach ticks to nanoseconds. Wakeups
are the kernel's own per-process count (`ri_pkg_idle_wkups` plus
`ri_interrupt_wkups`), the nearest macOS analogue of a voluntary switch.
"""

import ctypes
import struct

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
UNAVAILABLE = "unavailable:unsupported_platform"
NANOSECONDS = 1_000_000_000

PROC_PIDLISTFDS = 1
PROC_PIDTASKINFO = 4
RUSAGE_INFO_V4 = 4
FD_INFO_BYTES = 8  # struct proc_fdinfo: int32 fd, uint32 type
PATH_MAX_BYTES = 4096



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


class TaskInfo(ctypes.Structure):
    """struct proc_taskinfo from <sys/proc_info.h>."""

    _fields_ = [
        (name, ctypes.c_uint64)
        for name in ("virtual", "resident", "user", "system", "threads_user", "threads_system")
    ] + [
        (name, ctypes.c_int32)
        for name in (
            "policy", "faults", "pageins", "cow_faults", "messages_sent",
            "messages_received", "syscalls_mach", "syscalls_unix", "switches",
            "threads", "running", "priority",
        )
    ]


class Libproc:
    """The libproc reads a macOS sample needs; each raises OSError when refused."""

    def __init__(self) -> None:
        self.lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.nanoseconds_per_tick = self._tick_nanoseconds()

    @staticmethod
    def _tick_nanoseconds() -> float:
        class Timebase(ctypes.Structure):
            _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]

        base = Timebase()
        ctypes.CDLL("/usr/lib/libSystem.dylib").mach_timebase_info(ctypes.byref(base))
        if base.denom == 0:
            raise OSError("mach_timebase_info returned a zero denominator")
        return base.numer / base.denom

    def pids(self) -> list[int]:
        needed = self.lib.proc_listallpids(None, 0)
        if needed <= 0:
            raise OSError(ctypes.get_errno(), "proc_listallpids")
        pids = (ctypes.c_int * (needed + 64))()
        count = self.lib.proc_listallpids(pids, ctypes.sizeof(pids))
        if count <= 0:
            raise OSError(ctypes.get_errno(), "proc_listallpids")
        return [pid for pid in pids[:count] if pid > 0]

    def program(self, pid: int) -> str:
        path = ctypes.create_string_buffer(PATH_MAX_BYTES)
        if self.lib.proc_pidpath(pid, path, len(path)) <= 0:
            raise OSError(ctypes.get_errno(), "proc_pidpath")
        return path.value.decode(errors="replace")

    def counters(self, pid: int) -> tuple[int, int, int, int]:
        """(threads, descriptors, cpu nanoseconds, wakeups)."""
        task = TaskInfo()
        if self.lib.proc_pidinfo(pid, PROC_PIDTASKINFO, 0, ctypes.byref(task), ctypes.sizeof(task)) != ctypes.sizeof(task):
            raise OSError(ctypes.get_errno(), "proc_pidinfo taskinfo")
        fd_bytes = self.lib.proc_pidinfo(pid, PROC_PIDLISTFDS, 0, None, 0)
        if fd_bytes < 0:
            raise OSError(ctypes.get_errno(), "proc_pidinfo listfds")
        usage = ctypes.create_string_buffer(1024)
        if self.lib.proc_pid_rusage(pid, RUSAGE_INFO_V4, usage) != 0:
            raise OSError(ctypes.get_errno(), "proc_pid_rusage")
        return (
            task.threads,
            fd_bytes // FD_INFO_BYTES,
            round((task.user + task.system) * self.nanoseconds_per_tick),
            wakeups_from_rusage(usage.raw),
        )


def wakeups_from_rusage(raw: bytes) -> int:
    """ri_pkg_idle_wkups + ri_interrupt_wkups: the two u64s after the uuid and two times."""
    idle, interrupt = struct.unpack_from("<QQ", raw, 32)
    return idle + interrupt


def sample_macos(reader: Libproc, skip: frozenset[int] = frozenset()) -> dict[int, ProcessSample]:
    """One pass over libproc, mirroring `sample`: a process that exits or refuses is left out."""
    found = {}
    for pid in reader.pids():
        if pid in skip:
            continue
        try:
            component = component_of(reader.program(pid))
            if component is None:
                continue
            threads, descriptors, nanoseconds, wakeups = reader.counters(pid)
        except OSError:
            continue
        found[pid] = ProcessSample(component, threads, descriptors, nanoseconds, wakeups)
    return found


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
        own = frozenset({os.getpid()})
        if (proc_root / "self" / "stat").is_file():
            take, ticks_per_second = (lambda: sample(proc_root, own)), os.sysconf("SC_CLK_TCK")
        elif sys.platform == "darwin":
            reader = Libproc()
            take, ticks_per_second = (lambda: sample_macos(reader, own)), NANOSECONDS
        else:
            print(f"wave_{wave}_idle_sampler\t{UNAVAILABLE}")
            return 0
        started = time.monotonic()
        before = take()
        time.sleep(seconds)
        after = take()
        elapsed = time.monotonic() - started
        rows = summarize(before, after, elapsed, ticks_per_second)
        table, summary = render(rows, wave)
        (wave_dir / "idle-settled.tsv").write_text(table)
        print(f"wave_{wave}_idle_window_seconds\t{elapsed:.1f}\n{summary}", end="")
    except (OSError, ValueError) as error:
        print(f"density idle sample unavailable: {error}", file=sys.stderr)
        return 71
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
