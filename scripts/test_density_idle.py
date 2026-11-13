"""Offline checks for the density wave's idle sampler, against a built procfs tree."""

import tempfile
import unittest
from pathlib import Path

from scripts.density_idle import (
    ProcessSample,
    component_of,
    cpu_ticks,
    render,
    sample,
    summarize,
)


def write_process(
    root: Path,
    pid: int,
    arguments: str,
    ticks: tuple[int, int],
    switches: list[int],
    descriptors: int,
    command: str = "name",
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
            taken, {100: ProcessSample("mvm-mailbox", 3, 4, 2, 23)}
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


if __name__ == "__main__":
    unittest.main()
