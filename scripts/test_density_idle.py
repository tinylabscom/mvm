"""Offline checks for the density wave's idle sampler, against a built procfs tree."""

import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.density_idle import (
    ProcessSample,
    component_of,
    cpu_ticks,
    render,
    render_per_standby,
    render_threads,
    sample,
    sample_macos,
    wakeups_from_rusage,
    summarize,
    summarize_threads,
)


def write_process(
    root: Path,
    pid: int,
    arguments: str,
    ticks: tuple[int, int],
    switches: list[int],
    descriptors: int,
    command: str = "name",
    thread_names: list[str] | None = None,
) -> None:
    directory = root / str(pid)
    (directory / "fd").mkdir(parents=True, exist_ok=True)
    for number in range(descriptors):
        (directory / "fd" / str(number)).write_text("")
    (directory / "cmdline").write_bytes(arguments.replace(" ", "\0").encode())
    head = f"{pid} ({command}) S"
    middle = " ".join(["0"] * 10)
    (directory / "stat").write_text(f"{head} {middle} {ticks[0]} {ticks[1]} 0 0\n")
    for index, count in enumerate(switches):
        task = directory / "task" / str(pid + index)
        task.mkdir(parents=True, exist_ok=True)
        (task / "status").write_text(
            f"Name:\tx\nvoluntary_ctxt_switches:\t{count}\nnonvoluntary_ctxt_switches:\t9\n"
        )
        name = thread_names[index] if thread_names else f"t{index}"
        (task / "comm").write_text(f"{name}\n")


class DensityIdleTests(unittest.TestCase):
    def test_a_component_is_named_by_its_program_file_alone(self) -> None:
        self.assertEqual(component_of("/x/mvm-mailbox"), "mvm-mailbox")
        self.assertEqual(component_of("firecracker-v1.17.0-x86_64"), "firecracker")
        self.assertEqual(component_of("/tmp/mvm-firecracker-density-1/bin/mvmctl"), "mvmctl")
        self.assertIsNone(component_of("/usr/bin/sleep"))
        self.assertIsNone(component_of("/x/not-mvmctl"))
        self.assertIsNone(component_of("/x/mvm-mailboxd"))

    def test_an_argument_naming_a_component_does_not_classify_the_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_process(root, 100, "/usr/bin/sleep /tmp/mvm-firecracker-density", (0, 0), [1], 0)
            self.assertEqual(sample(root), {})

    def test_cpu_ticks_survive_a_command_name_with_spaces_and_parentheses(self) -> None:
        middle = " ".join(["0"] * 10)
        self.assertEqual(cpu_ticks(f"7 (a b) c)) S {middle} 30 12 0 0"), 42)

    def test_switches_are_summed_over_every_thread(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_process(root, 100, "/x/mvm-mailbox", (1, 1), [5, 7, 11], 4)
            write_process(root, 200, "/usr/bin/sleep 9", (1, 1), [1], 1)
            (root / "self").mkdir()
            taken = sample(root)
        self.assertEqual(
            taken,
            {
                100: ProcessSample(
                    "mvm-mailbox", 3, 4, 2, 23,
                    ((100, "t0", 5), (101, "t1", 7), (102, "t2", 11)),
                )
            },
        )

    def test_a_skipped_pid_and_an_unreadable_process_are_left_out(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_process(root, 100, "/x/mvmctl run", (0, 0), [1], 0)
            write_process(root, 300, "/x/firecracker", (0, 0), [1], 0)
            (root / "300" / "stat").unlink()
            self.assertEqual(sample(root, frozenset({100})), {})

    def test_rates_use_only_processes_present_in_both_passes(self) -> None:
        mailbox = ProcessSample("mvm-mailbox", 2, 6, 100, 1000)
        before = {1: mailbox, 2: mailbox}
        after = {
            1: ProcessSample("mvm-mailbox", 2, 6, 110, 1500),
            3: ProcessSample("mvm-mailbox", 9, 9, 999, 9999),
        }
        rows = summarize(before, after, 10.0, 100)
        self.assertEqual(rows, [("mvm-mailbox", 1, 2, 6, 10.0, 50.0)])

    def test_a_reused_pid_is_refused_rather_than_reported_as_a_negative_rate(self) -> None:
        before = {1: ProcessSample("firecracker", 1, 1, 50, 50)}
        after = {1: ProcessSample("firecracker", 1, 1, 10, 60)}
        with self.assertRaises(ValueError):
            summarize(before, after, 1.0, 100)

    def test_a_pid_that_changed_component_is_not_counted(self) -> None:
        before = {1: ProcessSample("mvmctl", 1, 1, 0, 0)}
        after = {1: ProcessSample("firecracker", 1, 1, 5, 5)}
        self.assertEqual(summarize(before, after, 1.0, 100), [])

    def test_a_nonpositive_window_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            summarize({}, {}, 0.0, 100)

    def test_render_names_every_figure_by_wave_and_component(self) -> None:
        table, summary = render([("mvm-mailbox", 3, 6, 18, 6.25, 150.04)], 100)
        self.assertEqual(
            table.splitlines()[1], "mvm-mailbox\t3\t6\t18\t6.2\t150.0"
        )
        self.assertEqual(
            summary,
            "wave_100_idle_mvm-mailbox_threads\t6\n"
            "wave_100_idle_mvm-mailbox_descriptors\t18\n"
            "wave_100_idle_mvm-mailbox_cpu_millicores\t6.2\n"
            "wave_100_idle_mvm-mailbox_wakeups_per_second\t150.0\n",
        )


class DensityIdleThreadTests(unittest.TestCase):
    def test_wakeups_are_attributed_per_thread_name_across_processes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = ["firecracker", "fc_api", "fc_vcpu 0"]
            write_process(root, 100, "/x/firecracker", (0, 0), [1, 1, 1], 0, thread_names=names)
            write_process(root, 200, "/x/firecracker", (0, 0), [1, 1, 1], 0, thread_names=names)
            before = sample(root)
            write_process(root, 100, "/x/firecracker", (0, 0), [11, 1, 501], 0, thread_names=names)
            write_process(root, 200, "/x/firecracker", (0, 0), [21, 1, 301], 0, thread_names=names)
            rows = summarize_threads(before, sample(root), 10.0)
        self.assertEqual(
            rows,
            [
                ("firecracker", "fc_api", 2, 0.0),
                ("firecracker", "fc_vcpu 0", 2, 80.0),
                ("firecracker", "firecracker", 2, 3.0),
            ],
        )
        table, summary = render_threads(rows, 5)
        self.assertEqual(table.splitlines()[2], "firecracker\tfc_vcpu 0\t2\t80.0")
        self.assertIn("wave_5_thread_firecracker_fc_vcpu_0_threads\t2\n", summary)
        self.assertIn("wave_5_thread_firecracker_fc_vcpu_0_wakeups_per_second\t80.0\n", summary)

    def test_a_thread_that_started_or_was_renamed_inside_the_window_is_left_out(self) -> None:
        before = {1: ProcessSample("mvmctl", 2, 1, 0, 0, ((1, "main", 5), (2, "old", 5)))}
        after = {
            1: ProcessSample(
                "mvmctl", 3, 1, 0, 0, ((1, "main", 15), (2, "new", 50), (3, "late", 90))
            )
        }
        self.assertEqual(summarize_threads(before, after, 1.0), [("mvmctl", "main", 1, 10.0)])

    def test_a_host_without_per_thread_counters_emits_no_thread_rows(self) -> None:
        taken = {1: ProcessSample("mvm-hvf-supervisor", 4, 10, 0, 0)}
        self.assertEqual(summarize_threads(taken, taken, 1.0), [])


class FakeLibproc:
    """Stands in for libproc: pid -> (program, counters or None when refused)."""

    def __init__(self, table: dict) -> None:
        self.table = table

    def pids(self) -> list[int]:
        return list(self.table)

    def program(self, pid: int) -> str:
        program = self.table[pid][0]
        if program is None:
            raise OSError("proc_pidpath")
        return program

    def counters(self, pid: int) -> tuple[int, int, int, int]:
        counters = self.table[pid][1]
        if counters is None:
            raise OSError("proc_pidinfo")
        return counters


class DensityIdleMacosTests(unittest.TestCase):
    def test_wakeups_are_idle_exits_plus_interrupts_after_the_uuid_and_times(self) -> None:
        raw = bytes(16) + struct.pack("<QQQQQ", 11, 22, 3, 4, 99)
        self.assertEqual(wakeups_from_rusage(raw), 7)

    def test_a_component_is_classified_by_program_file_name_only(self) -> None:
        reader = FakeLibproc(
            {
                10: ("/Users/x/mvm-hvf-density-1/bin/mvm-hvf-supervisor", (4, 12, 5, 6)),
                11: ("/usr/bin/sleep", (1, 3, 0, 0)),
                12: ("/tmp/mvm-hvf-density-9/bin/python3", (1, 3, 0, 0)),
            }
        )
        self.assertEqual(
            sample_macos(reader),
            {10: ProcessSample("mvm-hvf-supervisor", 4, 12, 5, 6)},
        )

    def test_a_refused_process_and_the_samplers_own_pid_are_left_out(self) -> None:
        reader = FakeLibproc(
            {
                1: (None, None),
                2: ("/x/mvm-mailbox", None),
                3: ("/x/mvm-mailbox", (2, 5, 7, 9)),
                4: ("/x/mvm-mailbox", (2, 5, 7, 9)),
            }
        )
        self.assertEqual(
            sample_macos(reader, frozenset({4})),
            {3: ProcessSample("mvm-mailbox", 2, 5, 7, 9)},
        )

    def test_nanosecond_cpu_becomes_millicores_over_the_window(self) -> None:
        before = {1: ProcessSample("mvm-hvf-supervisor", 4, 10, 1_000_000_000, 100)}
        after = {1: ProcessSample("mvm-hvf-supervisor", 4, 10, 1_050_000_000, 600)}
        rows = summarize(before, after, 10.0, 1_000_000_000)
        self.assertEqual(rows, [("mvm-hvf-supervisor", 1, 4, 10, 5.0, 50.0)])


class DensityIdleBaselineTests(unittest.TestCase):
    def run_main(self, *arguments: str) -> subprocess.CompletedProcess:
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as raw:
            return subprocess.run(
                [sys.executable, "-m", "scripts.density_idle", raw, *arguments],
                cwd=root, capture_output=True, text=True, timeout=30,
            )

    def test_main_accepts_wave_zero_as_the_zero_unit_baseline(self) -> None:
        result = self.run_main("0", "0.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("wave_0_idle_window_seconds\t", result.stdout)

    def test_main_still_refuses_a_negative_wave(self) -> None:
        self.assertEqual(self.run_main("-1", "0.1").returncode, 71)

    def test_main_accepts_the_optional_standby_count(self) -> None:
        result = self.run_main("4", "0.1", "4")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("wave_4_idle_window_seconds\t", result.stdout)

    def test_main_refuses_a_sixth_argument(self) -> None:
        self.assertEqual(self.run_main("4", "0.1", "4", "x").returncode, 64)

    def test_a_component_absent_from_a_fake_procfs_emits_no_keys(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_process(root, 7, "/bin/sleep 1", (10, 0), [5], 2)
            before = sample(root)
            write_process(root, 7, "/bin/sleep 1", (20, 0), [15], 2)
            rows = summarize(before, sample(root), 10.0, 100)
        self.assertEqual(render(rows, 0)[1], "")

    def test_the_standby_summary_divides_cost_by_the_held_count(self) -> None:
        rows = [("mvm-hvf-supervisor", 4, 16, 40, 8.0, 20.0)]
        self.assertEqual(
            render_per_standby(rows, 4, 4),
            "wave_4_idle_mvm-hvf-supervisor_cpu_millicores_per_standby\t2.00\n"
            "wave_4_idle_mvm-hvf-supervisor_wakeups_per_second_per_standby\t5.00\n",
        )

    def test_a_standby_summary_for_no_standbys_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            render_per_standby([], 0, 0)


if __name__ == "__main__":
    unittest.main()
