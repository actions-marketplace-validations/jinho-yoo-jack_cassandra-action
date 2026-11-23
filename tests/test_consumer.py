#!/usr/bin/env python3
"""Test the CI verifier with explicit, synthetic report fixtures (not scans)."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "scripts" / "verify_consumer.py"


class ConsumerVerification(unittest.TestCase):
    def setUp(self):
        self.assertTrue(VERIFY.is_file(), "Consumer verifier has not been implemented")
        self.tmp = tempfile.TemporaryDirectory(prefix="cassandra-consumer-test-", dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.output = self.root / "cassandra-results.fixture"
        self.output.mkdir()
        self.documents = {
            "REPORT_FILE": ("report.json", {"inventory": {"projects": [{"manifest": "package.json"}], "components": []},
                                          "match": {"findings": []}}),
            "SARIF_FILE": ("results.sarif", {"version": "2.1.0", "runs": [
                {"results": [], "invocations": [{"executionSuccessful": True}]}]}),
            "CYCLONEDX_FILE": ("sbom.cyclonedx.json", {"bomFormat": "CycloneDX", "specVersion": "1.6"}),
            "SPDX_FILE": ("sbom.spdx.json", {"spdxVersion": "SPDX-2.3"}),
        }
        self.env = dict(os.environ, EXPECTED_EXIT_CODE="0", SCAN_EXIT_CODE="0", SCAN_OUTCOME="success",
                        RUNNER_TEMP=str(self.root), SCAN_OUTPUT_DIR=str(self.output),
                        SUMMARY_FILE=str(self.output / "summary.md"))
        for key, (filename, document) in self.documents.items():
            path = self.output / filename
            path.write_text(json.dumps(document))
            self.env[key] = str(path)
        (self.output / "summary.md").write_text("Synthetic verifier-test summary\n")

    def run_verifier(self, **overrides):
        return subprocess.run(["python3", "-B", str(VERIFY)], env=dict(self.env, **overrides),
                              cwd=ROOT, text=True, capture_output=True, timeout=10)

    def test_complete_clean_result_passes(self):
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_complete_expected_vulnerability_result_passes(self):
        report = {"inventory": {"projects": [{"manifest": "requirements.txt"}],
                                "components": [{"id": "requests", "name": "requests", "version": "2.19.1"}]},
                  "match": {"findings": [{"componentID": "requests", "vulnerabilityID": "test-only"}]}}
        Path(self.env["REPORT_FILE"]).write_text(json.dumps(report))
        Path(self.env["SARIF_FILE"]).write_text(json.dumps({"version": "2.1.0", "runs": [
            {"results": [{"ruleId": "test-only"}], "invocations": [{"executionSuccessful": True}]}]}))
        result = self.run_verifier(EXPECTED_EXIT_CODE="1", SCAN_EXIT_CODE="1", SCAN_OUTCOME="failure")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_errors_missing_outputs_and_wrong_outcomes_fail(self):
        for overrides in ({"SCAN_EXIT_CODE": "2"}, {"SCAN_EXIT_CODE": ""},
                          {"SCAN_EXIT_CODE": "1"}, {"SCAN_OUTCOME": "failure"},
                          {"EXPECTED_EXIT_CODE": "2"}, {"REPORT_FILE": ""},
                          {"SCAN_OUTPUT_DIR": ""}):
            with self.subTest(overrides=overrides):
                result = self.run_verifier(**overrides)
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_missing_report_file_fails(self):
        Path(self.env["SPDX_FILE"]).unlink()
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_invalid_json_fails(self):
        Path(self.env["REPORT_FILE"]).write_text("not JSON")
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_report_output_outside_output_directory_fails(self):
        outside = self.root / "report.json"
        outside.write_text(Path(self.env["REPORT_FILE"]).read_text())
        result = self.run_verifier(REPORT_FILE=str(outside))
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_missing_findings_fail_vulnerable_expectation(self):
        result = self.run_verifier(EXPECTED_EXIT_CODE="1", SCAN_EXIT_CODE="1", SCAN_OUTCOME="failure")
        self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_partial_sarif_is_rejected(self):
        Path(self.env["SARIF_FILE"]).write_text(json.dumps({"version": "2.1.0", "runs": [
            {"results": [], "invocations": [{"executionSuccessful": False}]}]}))
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
