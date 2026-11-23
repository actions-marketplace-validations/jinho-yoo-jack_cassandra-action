# Maintaining the standalone Action

## Scope and provenance

This repository distributes an adapter, not a second scanner implementation. It imports `scripts/action.sh` and the Apache-2.0 `LICENSE` from [jinho-yoo-jack/Cassandra](https://github.com/jinho-yoo-jack/Cassandra). `action.yml` is adapted to default to the exact CLI version `v0.1.0`; `tests/test_action.py` derives from upstream `scripts/test_action.py` with extra boundary coverage. Do not copy the server, UI or CLI source into this repository.

The source checkout's observed HEAD at extraction was `0340e3b2046873698ac39722885193a2dde6675a`; the CLI/Action files were in its working tree, so this HEAD is context, not a claim that the commit contains those files. The duplicate wrapper files were removed from the service checkout during the split. This repository is now the canonical source for the adapter; update it against the published CLI's inputs, reports and exit-code contracts rather than maintaining another wrapper copy in the service repository. Preserve provenance and license notices when adapting files.

## Local verification (no dependency installation or network)

```sh
bash -n scripts/action.sh
python3 -B -m unittest discover -s tests -v
```

The wrapper tests substitute only download and CLI boundaries. They exercise checksum rejection, exact upstream URLs, version validation, Linux architectures, scoped paths, workflow-command suppression, outputs, cleanup and nonzero scanner exits. The consumer-verifier tests use explicitly synthetic report documents to ensure missing files, partial analysis and wrong exits cannot pass. Neither suite proves live vulnerability data, release availability, GitHub output propagation or Marketplace publication.

Use an available workflow linter (for example `actionlint`) on `.github/workflows/*.yml` and `docs/examples/code-scanning.yml` before publishing; it is not installed by this repository. CI uses only the runner's Bash and Python standard library.

## Real-consumer integration

`.github/workflows/consumer.yml` runs on `push` to `main` and `workflow_dispatch`. It calls `uses: ./` so the actual composite Action metadata, environment mapping, failure outputs and wrapper are exercised together. The CLI version is explicitly `v0.1.0`; no locally built binary, mock API or `latest` release is substituted.

| Fixture | Input | Required scanner exit |
| --- | --- | --- |
| `tests/fixtures/clean` | Supported, dependency-free `package.json` | `0` |
| `tests/fixtures/vulnerable` | `requests==2.19.1` | `1` |

The vulnerable manifest is intentionally unsafe as an installation input. **Never install it.** This is scan-only test data. The workflow uses `fail-on: low` to test vulnerability detection without tying the case to a changing severity rating. It requires real findings, not a fixed advisory count or ID, because public data changes.

Both matrix jobs retain artifacts, then `scripts/verify_consumer.py` checks the Action outcome, exact exit, output path scope, all five nonempty report files, JSON formats, complete SARIF, and clean/vulnerable content expectations. Only the explicitly expected policy violation is accepted; exit `2`, missing outputs, failed downloads, provider outages, timeouts and malformed reports fail the job. `continue-on-error` belongs only on the scan step. Do not suppress errors on the verifier or artifact uploader. A failed artifact upload remains a failed job even if the verifier passes.

This workflow intentionally uses public APIs and cannot be validated by the offline wrapper tests. Publish the upstream CLI assets before pushing this repository to `main`, then inspect both jobs and retained reports. A local YAML file is not an observed CI run. SARIF upload permissions and the Marketplace listing require separate remote verification.

## First release prerequisites and order

1. Verify the upstream CLI `v0.1.0` release under `jinho-yoo-jack/Cassandra` contains `cassandra_v0.1.0_linux_amd64.tar.gz`, `cassandra_v0.1.0_linux_arm64.tar.gz` and `checksums.txt`. Archives must contain the `cassandra` executable; checksums must use the exact archive names. The download base remains `https://github.com/jinho-yoo-jack/Cassandra/releases/download`.
2. Review this Action's root metadata, branding, Apache license, English/Korean usage, immutable CLI default and pinned third-party Actions. Do not move published version tags or replace release assets. A future version must use a new tag; do not introduce a `latest` default.
3. With explicit maintainer authorization, create/push `jinho-yoo-jack/cassandra-action`, then observe wrapper CI and both real-consumer jobs against the already-published CLI. Review reports and confirm nonzero composite outputs reach the caller.
4. After those checks, publish the Action's first version `v0.1.0` and separately complete GitHub Marketplace listing requirements/terms through the maintainer account. Repository creation, commits, tags, pushes, release publication and Marketplace acceptance are not performed by the local preparation or either workflow.
5. Verify the actual release/tag, listing and a version-pinned consumer before announcing availability. Keep Action and CLI version pins explicit; a release/checksum alone does not establish protection against account compromise.

The source Action and scanner evolve separately. Never silently redirect downloads to this wrapper repository or ship a fallback binary when an upstream release or API is unavailable.
