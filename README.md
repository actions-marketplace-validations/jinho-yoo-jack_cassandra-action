# Cassandra Action

[한국어](README.ko.md) · [CLI and analysis engine](https://github.com/jinho-yoo-jack/Cassandra)

Scan a checked-out repository for vulnerable dependencies and produce a JSON report, Markdown summary, CycloneDX/SPDX SBOMs and SARIF. This repository contains only the GitHub Action adapter, documentation and tests. The CLI is downloaded from [Cassandra releases](https://github.com/jinho-yoo-jack/Cassandra/releases), not built here.

**Release target: `v0.1.0`.** The examples require both this Action's `v0.1.0` tag and the upstream CLI's `v0.1.0` assets to be published. A local checkout of this repository is not evidence of a published release or Marketplace listing.

## Quick start

Save as `.github/workflows/cassandra.yml` in the repository to scan:

```yaml
name: Cassandra scan
on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          persist-credentials: false
      - name: Scan without executing project code
        id: cassandra
        uses: jinho-yoo-jack/cassandra-action@v0.1.0
        continue-on-error: true # Only to preserve reports before the final gate.
        with:
          version: v0.1.0
          path: .
          fail-on: high
          timeout: 5m
      - name: Keep reports even after a failed scan
        if: always() && steps.cassandra.outputs.output-dir != ''
        uses: actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f # v6
        with:
          name: cassandra-reports
          path: ${{ steps.cassandra.outputs.output-dir }}
          if-no-files-found: warn
          retention-days: 7
      - name: Enforce the scanner result
        if: always()
        env:
          SCAN_EXIT_CODE: ${{ steps.cassandra.outputs.exit-code }}
          SCAN_OUTCOME: ${{ steps.cassandra.outcome }}
        shell: bash
        run: |
          case "$SCAN_OUTCOME:$SCAN_EXIT_CODE" in
            success:0) exit 0 ;;
            failure:1) exit 1 ;;
            *) exit 2 ;;
          esac
```

**Do not remove the final gate.** `continue-on-error` only allows saving artifacts; it is not permission to ignore a vulnerability or scanner failure. Empty/missing exit outputs fail closed. No secret or write permission is needed for the basic scan. Pin `uses` to a reviewed full commit SHA for stronger Action source pinning; keep the CLI `version` exact and review both upgrades separately.

## Inputs

| Input | Default | Meaning |
| --- | --- | --- |
| `version` | `v0.1.0` | Exact CLI release tag (`vMAJOR.MINOR.PATCH`, optionally a prerelease). `latest`, `main` and `v1` are refused. |
| `path` | `.` | Existing directory inside `GITHUB_WORKSPACE`. Paths escaping the checkout, including through a symlink, are refused. |
| `fail-on` | `high` | `none`, `low`, `medium`, `high`, `critical`. Unknown severity blocks an enabled gate. |
| `timeout` | `5m` | Total CLI preparation and scan budget, such as `30s` or `5m`; downloads have separate bounded timeouts. |
| `nvd-api-key` | unset | Optional NVD API key. Use a GitHub Actions secret, never a committed value. Not needed for basic use and usually unavailable to fork PRs. |

`fail-on: none` disables only the vulnerability threshold, **not** incomplete-scan or operational failures. Do not install the project dependencies before scanning just to use this Action.

## Outputs and failure semantics

| Output | Value |
| --- | --- |
| `exit-code` | `0`: complete scan passed; `1`: vulnerability policy failed; `2`: incomplete scan, unsupported input, timeout, download, I/O or other operational error. |
| `output-dir` | Unique reports directory under `$RUNNER_TEMP`, outside the checkout. |
| `report-file` | `report.json`: full inventory, code graph, findings and warnings. |
| `sarif-file` | `results.sarif`: SARIF 2.1.0. Upload only a complete result with exit `0` or `1`. |
| `cyclonedx-file` | `sbom.cyclonedx.json`: CycloneDX 1.6. |
| `spdx-file` | `sbom.spdx.json`: SPDX 2.3. |
| `summary-file` | `summary.md`: also appended to the GitHub job summary. |

Reports survive a policy failure. A partial/error scan may retain diagnostic artifacts, but early failures may produce no files even when path outputs are present. The Markdown summary can truncate findings; the JSON report retains the full result. No supported manifest is an incomplete scan, not a clean result. A dependency-free supported manifest can pass.

If the runner's output channel fails permanently, publishing or repairing outputs is best-effort; the process still fails. Always cross-check `steps.cassandra.outcome` as the example does, not only `exit-code` (or `conclusion`, which `continue-on-error` can change). A failed step with a stale `0` output must not pass the job.

## Optional GitHub Code scanning

Use the [complete Code scanning workflow](docs/examples/code-scanning.yml) instead of the quick-start workflow when the repository supports SARIF uploads. It adds `security-events: write` only to the scanning job, keeps artifacts, validates that the SARIF file is present and complete, uploads only for exit `0`/`1`, then enforces the original scanner result.

The example skips SARIF uploads for fork pull requests and Dependabot-triggered runs with restricted tokens. It still scans and retains artifacts. Do **not** switch to `pull_request_target` or expose secrets to untrusted PR code to bypass permission failures. Code scanning must be available/enabled for the repository; private/internal repositories may require GitHub Code Security. See [GitHub's SARIF upload documentation](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).

Never upload exit-`2` results as a successful complete analysis: doing so can wrongly clear existing alerts. SARIF upload is optional; JSON, SBOMs, artifacts and the job summary work without it.

## Runtime and trust boundaries

- Linux X64 and ARM64 runners only. Use a current GitHub-hosted Ubuntu runner or a compatible self-hosted runner with Bash, curl, tar, standard Unix utilities and SHA-256 verification (`sha256sum` or `shasum`). The scan does not require a local server, database, Go toolchain or project dependency installation.
- The scanner does **not execute the checked-out project's code**, install/build/test scripts, or automatic fixes. It does not open PRs or deploy. The Action does execute its reviewed wrapper and downloaded CLI binary.
- **Public API network access is required.** The CLI uses vulnerability services such as OSV, NVD, CISA KEV and FIRST EPSS; Go graph expansion uses the Go module proxy. Package names/versions are sent to these services. Full source code is not uploaded. It is not an offline scanner.
- Downloads stay at `https://github.com/jinho-yoo-jack/Cassandra/releases/download/<version>/`. The wrapper verifies `checksums.txt`, extracts only the executable's bytes and disables GitHub workflow-command parsing around repository/advisory output. Checksums detect corruption, not a compromised upstream release account. Exact release tags must not be moved or replaced by maintainers.
- Reports can contain private dependency names and repository paths. Review artifact access and retention before using this on sensitive code. A scan with no findings is not a guarantee that the project has no security defects. Analysis capabilities and limitations belong to the [upstream CLI documentation](https://github.com/jinho-yoo-jack/Cassandra/blob/main/docs/usage/cli-and-actions.md).

## Tests and maintenance

```sh
bash -n scripts/action.sh
python3 -B -m unittest discover -s tests -v
```

Local tests use Python's standard library and explicit fixture CLI/downloads; they do not contact public services or prove a published release works. [Wrapper CI](.github/workflows/ci.yml) runs these checks on PRs and `main`. [Real-consumer CI](.github/workflows/consumer.yml) runs on pushes to `main` and manual dispatch, calls `uses: ./` with the actual released CLI `v0.1.0`, scans clean and vulnerable fixtures, saves reports and verifies exit codes and every report output. No project dependencies are installed. Live service errors must fail this workflow, never be accepted as vulnerability results.

See [maintenance and release prerequisites](docs/MAINTAINING.md). Licensed under [Apache-2.0](LICENSE), with wrapper code adapted from [Cassandra](https://github.com/jinho-yoo-jack/Cassandra).
