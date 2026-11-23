"""Run the published final-gate shell code against runner outcomes/outputs."""
import os
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
CASES = [("success", "0", 0), ("failure", "1", 1), ("failure", "0", 2),
         ("success", "1", 2), ("failure", "2", 2), ("success", "", 2),
         ("skipped", "0", 2), ("cancelled", "0", 2), ("failure", "", 2)]


class ExampleGates(unittest.TestCase):
    def check_gate(self, filename):
        text = (ROOT / filename).read_text()
        self.assertIn("SCAN_OUTCOME: ${{ steps.cassandra.outcome }}", text)
        gate = re.search(r'(?m)^\s*case .*? in\n.*?\besac', text, re.S)
        self.assertIsNotNone(gate, f"Missing final gate in {filename}")
        for outcome, output, expected in CASES:
            with self.subTest(outcome=outcome, output=output):
                result = subprocess.run(["bash", "-c", gate.group()],
                                        env=dict(os.environ, SCAN_OUTCOME=outcome, SCAN_EXIT_CODE=output),
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_english_quickstart_gate(self):
        self.check_gate("README.md")

    def test_korean_quickstart_gate(self):
        self.check_gate("README.ko.md")

    def test_sarif_workflow_gate(self):
        self.check_gate("docs/examples/code-scanning.yml")


if __name__ == "__main__":
    unittest.main()
