#!/usr/bin/env python3
"""Fail closed on real-consumer mismatches; never download or run a scanner."""
import json
import os
from pathlib import Path
import sys

FILES = {
    "REPORT_FILE": "report.json",
    "SARIF_FILE": "results.sarif",
    "CYCLONEDX_FILE": "sbom.cyclonedx.json",
    "SPDX_FILE": "sbom.spdx.json",
    "SUMMARY_FILE": "summary.md",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify():
    expected = os.environ["EXPECTED_EXIT_CODE"]
    actual = os.environ["SCAN_EXIT_CODE"]
    require(expected in ("0", "1"), "Expected exit must be 0 or 1; operational errors are never expected.")
    require(actual == expected, f"Expected scanner exit {expected}, got {actual!r}.")
    outcome = "success" if expected == "0" else "failure"
    require(os.environ["SCAN_OUTCOME"] == outcome, "Action step outcome disagrees with its exit-code output.")
    require(bool(os.environ["SCAN_OUTPUT_DIR"]), "Missing output-dir output.")
    output = Path(os.environ["SCAN_OUTPUT_DIR"]).resolve(strict=True)
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(output != temporary and output.is_relative_to(temporary), "Reports must be inside RUNNER_TEMP.")
    documents = {}
    for key, filename in FILES.items():
        require(bool(os.environ[key]), f"Missing {key} output.")
        path = Path(os.environ[key]).resolve(strict=True)
        require(path == output / filename, f"{key} does not identify the expected report file.")
        require(path.is_file() and path.stat().st_size > 0, f"Missing or empty {filename}.")
        text = path.read_text(encoding="utf-8")
        if filename.endswith(".md"):
            require(bool(text.strip()), "Empty Markdown summary.")
        else:
            document = json.loads(text)
            require(isinstance(document, dict), f"{filename} is not a JSON object.")
            documents[key] = document
    report = documents["REPORT_FILE"]
    require(bool(report["inventory"]["projects"]), "No supported project was analysed.")
    require(not report["match"].get("warnings"), "Scan contains incomplete-analysis warnings.")
    findings = report["match"]["findings"] or []
    components = report["inventory"]["components"] or []
    require(isinstance(findings, list) and isinstance(components, list), "Malformed inventory or findings.")
    sarif = documents["SARIF_FILE"]
    require(sarif["version"] == "2.1.0" and bool(sarif["runs"]), "Missing SARIF 2.1.0 analysis.")
    results = []
    for run in sarif["runs"]:
        invocations = run.get("invocations", [])
        require(bool(invocations) and all(i.get("executionSuccessful") is True for i in invocations),
                "SARIF analysis is incomplete.")
        results.extend(run.get("results") or [])
    cdx = documents["CYCLONEDX_FILE"]
    require(cdx.get("bomFormat") == "CycloneDX" and cdx.get("specVersion") == "1.6", "Invalid CycloneDX version.")
    require(documents["SPDX_FILE"].get("spdxVersion") == "SPDX-2.3", "Invalid SPDX version.")
    if expected == "0":
        require(not components and not findings and not results, "Clean dependency-free fixture unexpectedly has dependencies or findings.")
    else:
        require(bool(findings) and bool(results), "Expected real vulnerability findings in JSON and SARIF.")
        require(any(c.get("name") == "requests" and c.get("version") == "2.19.1" for c in components),
                "Vulnerable fixture's requests==2.19.1 was not inventoried.")
    print(f"Consumer verified: scanner exit={actual}, step outcome={outcome}, {len(FILES)} report files, {len(findings)} findings.")


if __name__ == "__main__":
    try:
        verify()
    except (KeyError, OSError, ValueError, TypeError) as error:
        print(f"Consumer verification failed: {error}", file=sys.stderr)
        sys.exit(1)
