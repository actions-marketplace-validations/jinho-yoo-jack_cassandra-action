#!/usr/bin/env python3
"""Offline wrapper contracts, adapted from Cassandra for the standalone Action."""
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "scripts" / "action.sh"

# This is explicitly a test double, not a scan or fabricated vulnerability data.
CLI = b'''#!/bin/bash
set -eu
printf '%s\\n' "$@" > "$FIXTURE_ARGS"
out=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "--output-dir" ]]; then out="$2"; shift; fi
  shift
done
mkdir -p "$out"
printf 'fixture summary\\n' > "$out/summary.md"
printf '{}\\n' > "$out/report.json"
printf '{}\\n' > "$out/results.sarif"
printf '{}\\n' > "$out/sbom.cyclonedx.json"
printf '{}\\n' > "$out/sbom.spdx.json"
printf '::error::untrusted fixture text\\n'
exit "${FIXTURE_EXIT:-0}"
'''

CURL = '''#!/usr/bin/env python3
import os, pathlib, shutil, sys
if os.getenv("FIXTURE_DOWNLOAD_ERROR"):
    sys.exit(22)
args=sys.argv[1:]
dest=args[args.index("--output")+1]
url=args[-1]
with open(os.environ["FIXTURE_URLS"], "a") as log:
    log.write(url + "\\n")
shutil.copyfile(pathlib.Path(os.environ["FIXTURE_RELEASE"])/url.rsplit("/",1)[1],dest)
'''


class ActionContract(unittest.TestCase):
    def setUp(self):
        self.assertTrue(ACTION.is_file(), "Action script has not been implemented")
        self.tmp = tempfile.TemporaryDirectory(prefix="cassandra-action-", dir=os.environ.get("TMPDIR"))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ("bin", "release", "runner", "workspace with spaces"):
            (self.root / name).mkdir()
        self.asset = "cassandra_v1.2.3_linux_amd64.tar.gz"
        with tarfile.open(self.root / "release" / self.asset, "w:gz") as archive:
            info = tarfile.TarInfo("cassandra")
            info.size = len(CLI)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(CLI))
        self.checksum = self.root / "release" / "checksums.txt"
        digest = hashlib.sha256((self.root / "release" / self.asset).read_bytes()).hexdigest()
        self.checksum.write_text(f"{digest}  {self.asset}\n")
        curl = self.root / "bin" / "curl"
        curl.write_text(CURL)
        curl.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.root / "bin") + os.pathsep + os.environ["PATH"],
                        RUNNER_OS="Linux", RUNNER_ARCH="X64", RUNNER_TEMP=str(self.root / "runner"),
                        GITHUB_WORKSPACE=str(self.root / "workspace with spaces"),
                        GITHUB_OUTPUT=str(self.root / "outputs"), GITHUB_STEP_SUMMARY=str(self.root / "summary"),
                        INPUT_VERSION="v1.2.3", INPUT_PATH=".", INPUT_FAIL_ON="high", INPUT_TIMEOUT="5m",
                        FIXTURE_RELEASE=str(self.root / "release"), FIXTURE_ARGS=str(self.root / "args"),
                        FIXTURE_URLS=str(self.root / "urls"))
        self.env.pop("NVD_API_KEY", None)

    def run_action(self, **overrides):
        env = {key: value for key, value in dict(self.env, **overrides).items() if value is not None}
        return subprocess.run(["bash", str(ACTION)], cwd=self.env["GITHUB_WORKSPACE"], env=env,
                              text=True, capture_output=True, timeout=15)

    def test_missing_runner_paths_are_operational_errors(self):
        for variable in ("GITHUB_WORKSPACE", "RUNNER_TEMP"):
            for value in (None, str(self.root / "missing")):
                with self.subTest(variable=variable, value=value):
                    (self.root / "outputs").unlink(missing_ok=True)
                    result = self.run_action(**{variable: value})
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertEqual((self.root / "outputs").read_text(), "exit-code=2\n")
                    self.assertFalse((self.root / "args").exists())
                    self.assertFalse((self.root / "urls").exists())

    def assert_finalization_error(self, result):
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        outputs = dict(line.split("=", 1) for line in (self.root / "outputs").read_text().splitlines())
        self.assertEqual(outputs["exit-code"], "2")
        self.assertNotIn("exit-code=0", (self.root / "outputs").read_text())
        for key in ("report-file", "sarif-file", "cyclonedx-file", "spdx-file", "summary-file"):
            report = Path(outputs[key])
            self.assertTrue(report.is_file(), key)
            self.assertFalse(report.is_relative_to(Path(self.env["GITHUB_WORKSPACE"])))

    def test_summary_write_failure_overrides_cli_success_and_policy(self):
        for code in ("0", "1"):
            with self.subTest(cli_exit=code):
                (self.root / "outputs").unlink(missing_ok=True)
                result = self.run_action(FIXTURE_EXIT=code, GITHUB_STEP_SUMMARY=str(self.root / "runner"))
                self.assert_finalization_error(result)
                self.assertEqual(list((self.root / "runner").glob("cassandra-tool.*")), [])

    def test_cleanup_failure_is_operational_and_preserves_reports(self):
        rm = self.root / "bin" / "rm"
        rm.write_text("#!/bin/bash\nexit 1\n")
        rm.chmod(0o755)
        result = self.run_action()
        self.assert_finalization_error(result)
        self.assertIn("Exit code: 2", (self.root / "summary").read_text())

    def test_command_restoration_failure_does_not_abort_finalization(self):
        hook = self.root / "bash-env"
        hook.write_text('''printf() {
  if [[ "$1" == '::%s::\\n' ]]; then return 1; fi
  builtin printf "$@"
}
''')
        result = self.run_action(BASH_ENV=str(hook))
        self.assert_finalization_error(result)
        self.assertIn("Exit code: 2", (self.root / "summary").read_text())
        self.assertEqual(list((self.root / "runner").glob("cassandra-tool.*")), [])

    def test_summary_footer_write_failure_overrides_cli_success(self):
        hook = self.root / "bash-env"
        hook.write_text('''printf() {
  if [[ "$1" == *"Exit code:"* ]]; then return 1; fi
  builtin printf "$@"
}
''')
        result = self.run_action(BASH_ENV=str(hook))
        self.assert_finalization_error(result)
        self.assertIn("fixture summary", (self.root / "summary").read_text())

    def test_output_destination_failure_fails_closed_and_keeps_reports(self):
        for code in ("0", "1"):
            with self.subTest(cli_exit=code):
                (self.root / "summary").unlink(missing_ok=True)
                result = self.run_action(FIXTURE_EXIT=code, GITHUB_OUTPUT=str(self.root / "runner"))
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("Exit code: 2", (self.root / "summary").read_text())
                outputs = list((self.root / "runner").glob("cassandra-results.*"))
                self.assertTrue(outputs)
                for output in outputs:
                    self.assertEqual(len(list(output.iterdir())), 5)
                self.assertEqual(list((self.root / "runner").glob("cassandra-tool.*")), [])

    def test_output_path_write_failure_is_not_masked_by_later_writes(self):
        hook = self.root / "bash-env"
        hook.write_text('''printf() {
  if [[ "$*" == *"output-dir="* ]]; then return 1; fi
  builtin printf "$@"
}
''')
        result = self.run_action(BASH_ENV=str(hook))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual((self.root / "outputs").read_text(), "exit-code=2\n")
        self.assertIn("Exit code: 2", (self.root / "summary").read_text())
        self.assertTrue(list((self.root / "runner").glob("cassandra-results.*/report.json")))

    def test_partial_exit_output_write_failure_repairs_status(self):
        hook = self.root / "bash-env"
        hook.write_text('''printf() {
  if [[ "$1" == 'exit-code=%s\\n' && "$2" == 0 ]]; then
    builtin printf 'exit-code=0'
    return 1
  fi
  builtin printf "$@"
}
''')
        result = self.run_action(BASH_ENV=str(hook))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        outputs = dict(line.split("=", 1) for line in (self.root / "outputs").read_text().splitlines() if line)
        self.assertEqual(outputs["exit-code"], "2")
        self.assertTrue(Path(outputs["report-file"]).is_file())
        self.assertTrue((self.root / "summary").read_text().rstrip().endswith(
            "Exit code: 2 (0: passed, 1: vulnerability policy, 2: incomplete/error)."))

    def test_command_restoration_is_retried_on_abnormal_exit(self):
        hook = self.root / "bash-env"
        hook.write_text('''printf() {
  if [[ "$1" == '::%s::\\n' && "${restoration_attempted:-}" != yes ]]; then
    restoration_attempted=yes
    return 1
  fi
  builtin printf "$@"
}
''')
        result = self.run_action(BASH_ENV=str(hook))
        self.assert_finalization_error(result)
        stop = next(line for line in result.stdout.splitlines() if line.startswith("::stop-commands::"))
        token = stop.removeprefix("::stop-commands::")
        self.assertEqual(result.stdout.splitlines().count(f"::{token}::"), 1)

    def test_consumer_gate_rejects_permanently_broken_output_channel(self):
        import re
        hook = self.root / "bash-env"
        hook.write_text('''printf() {
  if [[ "$1" == 'exit-code=%s\\n' ]]; then
    builtin printf 'exit-code=0'
    return 1
  fi
  if [[ "$1" == '\\nexit-code=2\\n' ]]; then return 1; fi
  builtin printf "$@"
}
''')
        result = self.run_action(BASH_ENV=str(hook))
        self.assertEqual(result.returncode, 2, result.stderr)
        outputs = dict(line.split("=", 1) for line in (self.root / "outputs").read_text().splitlines())
        self.assertEqual(outputs["exit-code"], "0")  # The permanently broken channel cannot be repaired.
        self.assertTrue(Path(outputs["report-file"]).is_file())
        gate = re.search(r'(?m)^\s*case .*? in\n.*?\besac', (ROOT / "README.md").read_text(), re.S)
        self.assertIsNotNone(gate)
        checked = subprocess.run(["bash", "-c", gate.group()], capture_output=True, text=True,
                                 env=dict(os.environ, SCAN_OUTCOME="failure", SCAN_EXIT_CODE=outputs["exit-code"]),
                                 timeout=5)
        self.assertEqual(checked.returncode, 2, "A failed step must not pass through stale output")

    def test_reports_and_exit_code_survive_policy_failure(self):
        result = self.run_action(FIXTURE_EXIT="1")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        outputs = dict(line.split("=", 1) for line in (self.root / "outputs").read_text().splitlines())
        self.assertEqual(outputs["exit-code"], "1")
        self.assertTrue(Path(outputs["report-file"]).is_file())
        self.assertIn("fixture summary", (self.root / "summary").read_text())
        args = (self.root / "args").read_text().splitlines()
        self.assertEqual(args[args.index("--path") + 1], str((self.root / "workspace with spaces").resolve()))
        self.assertEqual(list((self.root / "runner").glob("cassandra-tool.*")), [])

    def test_checksum_mismatch_never_executes(self):
        self.checksum.write_text("0" * 64 + f"  {self.asset}\n")
        result = self.run_action()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse((self.root / "args").exists())

    def test_version_injection_is_rejected(self):
        result = self.run_action(INPUT_VERSION="v1.2.3;touch injected")
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / "args").exists())
        self.assertFalse((Path(self.env["GITHUB_WORKSPACE"]) / "injected").exists())

    def test_invalid_os_policy_and_download_fail_closed(self):
        for overrides in ({"RUNNER_OS": "Windows"}, {"INPUT_FAIL_ON": "typo"},
                          {"FIXTURE_DOWNLOAD_ERROR": "1"}, {"INPUT_TIMEOUT": "-1m"}):
            with self.subTest(overrides=overrides):
                result = self.run_action(**overrides)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse((self.root / "args").exists())

    def test_success(self):
        result = self.run_action()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_all_reports_are_preserved_outside_the_checkout(self):
        result = self.run_action(FIXTURE_EXIT="2")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        outputs = dict(line.split("=", 1) for line in (self.root / "outputs").read_text().splitlines())
        self.assertEqual(outputs["exit-code"], "2")
        output_dir = Path(outputs["output-dir"]).resolve()
        self.assertTrue(output_dir.is_relative_to((self.root / "runner").resolve()))
        self.assertFalse(output_dir.is_relative_to(Path(self.env["GITHUB_WORKSPACE"]).resolve()))
        for key in ("report-file", "sarif-file", "cyclonedx-file", "spdx-file", "summary-file"):
            self.assertTrue(Path(outputs[key]).is_file(), key)
            self.assertEqual(Path(outputs[key]).resolve().parent, output_dir)
        self.assertEqual(list((self.root / "runner").glob("cassandra-tool.*")), [])

    def test_workflow_commands_are_disabled_around_cli_output(self):
        result = self.run_action()
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        stop = next(line for line in lines if line.startswith("::stop-commands::"))
        token = stop.removeprefix("::stop-commands::")
        self.assertRegex(token, r"^cassandra-[a-f0-9]{32}$")
        self.assertLess(lines.index(stop), lines.index("::error::untrusted fixture text"))
        self.assertGreater(lines.index(f"::{token}::"), lines.index("::error::untrusted fixture text"))

    def test_downloads_use_the_exact_upstream_release(self):
        result = self.run_action()
        self.assertEqual(result.returncode, 0, result.stderr)
        base = "https://github.com/jinho-yoo-jack/Cassandra/releases/download/v1.2.3/"
        self.assertEqual((self.root / "urls").read_text().splitlines(),
                         [base + self.asset, base + "checksums.txt"])

    def test_floating_versions_are_rejected_before_download(self):
        for version in ("latest", "main", "v1", "v1.2", "", "v1.2.3\ninjected=value"):
            with self.subTest(version=version):
                result = self.run_action(INPUT_VERSION=version)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse((self.root / "urls").exists())
                self.assertFalse((self.root / "args").exists())

    def test_workspace_escape_and_symlink_escape_are_rejected(self):
        outside = self.root / "outside"
        outside.mkdir()
        link = Path(self.env["GITHUB_WORKSPACE"]) / "escape"
        link.symlink_to(outside, target_is_directory=True)
        for target in (str(outside), "../outside", "escape", "missing"):
            with self.subTest(target=target):
                result = self.run_action(INPUT_PATH=target)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse((self.root / "urls").exists())
                self.assertFalse((self.root / "args").exists())

    def test_nested_path_with_spaces_is_passed_as_one_argument(self):
        target = Path(self.env["GITHUB_WORKSPACE"]) / "nested project"
        target.mkdir()
        result = self.run_action(INPUT_PATH="nested project")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        args = (self.root / "args").read_text().splitlines()
        self.assertEqual(args[args.index("--path") + 1], str(target.resolve()))

    def test_duplicate_missing_and_invalid_checksums_never_execute(self):
        valid = self.checksum.read_text()
        for content in (valid + valid, "", "invalid  " + self.asset + "\n"):
            with self.subTest(content=content):
                self.checksum.write_text(content)
                result = self.run_action()
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse((self.root / "args").exists())

    def test_unexpected_cli_exit_is_normalized_to_operational_error(self):
        result = self.run_action(FIXTURE_EXIT="42")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("exit-code=2", (self.root / "outputs").read_text())

    def test_arm64_uses_the_arm64_release_asset(self):
        arm = "cassandra_v1.2.3_linux_arm64.tar.gz"
        data = (self.root / "release" / self.asset).read_bytes()
        (self.root / "release" / arm).write_bytes(data)
        self.checksum.write_text(f"{hashlib.sha256(data).hexdigest()}  {arm}\n")
        result = self.run_action(RUNNER_ARCH="ARM64")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(arm, (self.root / "urls").read_text())

    def test_unsupported_architecture_is_rejected(self):
        result = self.run_action(RUNNER_ARCH="X86")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse((self.root / "urls").exists())


if __name__ == "__main__":
    unittest.main()
