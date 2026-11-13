"""Exercise the RSS classifier used by the density wave against process rows."""

import subprocess
import unittest
from pathlib import Path


class DensityRssTests(unittest.TestCase):
    def test_only_program_names_classify_and_rss_is_aggregated(self) -> None:
        processes = (
            "100 4096 firecracker /opt/firecracker-v1.17.0-x86_64 --api-sock /tmp/mvm-firecracker-density\n"
            "101 1024 firecracker /opt/firecracker --api-sock /tmp/mvm-firecracker-density\n"
            "102 2048 mvm-network-endpoint /opt/mvm-network-endpoint --state /tmp/mvm-firecracker-density\n"
            "103 512 mvmctl /opt/mvmctl machine run\n"
            "104 1024 tail /usr/bin/tail -f /tmp/mvm-firecracker-density/log\n"
            "105 256 mvm-mailboxd /opt/mvm-mailboxd --state /tmp/mvm-firecracker-density\n"
        )
        result = subprocess.run(
            ["awk", "-f", str(Path(__file__).with_name("density_rss.awk"))],
            input=processes,
            text=True,
            capture_output=True,
            check=True,
        )
        rows = {
            name: fields
            for name, *fields in (line.split("\t") for line in result.stdout.splitlines()[1:])
        }
        self.assertEqual(
            rows,
            {
                "firecracker": ["2", "5120", "5.0"],
                "mvm-network-endpoint": ["1", "2048", "2.0"],
                "mvmctl": ["1", "512", "0.5"],
            },
        )


if __name__ == "__main__":
    unittest.main()
