"""Execute the publication workflow's SARIF source-context preparation."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/published-consumer.yml"


class SarifSourceContext(unittest.TestCase):
    def setUp(self):
        match = re.search(r"python3 - <<'PY'\n(.*?)\n\s+PY\n", WORKFLOW.read_text(), re.S)
        self.assertIsNotNone(match, "Missing subdirectory SARIF source-context preparation")
        self.script = textwrap.dedent(match.group(1))
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.workspace = self.root / "checkout with spaces"
        self.source = self.workspace / "tests/fixtures/vulnerable"
        self.source.mkdir(parents=True)
        self.input = self.root / "original.sarif"
        self.output = self.root / "upload.sarif"
        self.document = {"version": "2.1.0", "runs": [{"results": [{"ruleId": "fixture", "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "requirements.txt", "uriBaseId": "%SRCROOT%"}}}]}]}]}
        self.input.write_text(json.dumps(self.document))

    def run_preparation(self, source=None):
        return subprocess.run([sys.executable, "-c", self.script], capture_output=True, text=True, timeout=5,
                              env=dict(os.environ, SCAN_ROOT=str(source or self.source),
                                       GITHUB_WORKSPACE=str(self.workspace), SARIF_FILE=str(self.input),
                                       UPLOAD_SARIF_FILE=str(self.output)))

    def test_subdirectory_root_is_bound_without_changing_findings(self):
        result = self.run_preparation()
        self.assertEqual(result.returncode, 0, result.stderr)
        uploaded = json.loads(self.output.read_text())
        self.assertEqual(uploaded["runs"][0]["originalUriBaseIds"]["%SRCROOT%"],
                         {"uri": self.source.as_uri() + "/"})
        self.assertEqual(uploaded["runs"][0]["results"], self.document["runs"][0]["results"])
        self.assertEqual(json.loads(self.input.read_text()), self.document)

    def test_scan_root_outside_checkout_is_rejected(self):
        result = self.run_preparation(self.root)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.output.exists())

    def test_existing_upload_file_is_not_overwritten(self):
        self.output.write_text("owned sentinel")
        result = self.run_preparation()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_text(), "owned sentinel")


if __name__ == "__main__":
    unittest.main()
