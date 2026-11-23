# Cassandra Action

[English](README.md) · [CLI 및 분석 엔진](https://github.com/jinho-yoo-jack/Cassandra)

checkout된 저장소의 의존성 취약점을 검사하고 JSON 보고서, Markdown 요약, CycloneDX/SPDX SBOM, SARIF를 생성합니다. 이 저장소에는 GitHub Action 어댑터·문서·테스트만 있습니다. CLI는 여기서 빌드하지 않고 [Cassandra 릴리스](https://github.com/jinho-yoo-jack/Cassandra/releases)에서 내려받습니다.

**첫 릴리스 대상은 `v0.1.0`입니다.** 아래 예제는 이 Action의 `v0.1.0` 태그와 원본 CLI의 `v0.1.0` 릴리스 파일이 게시되어 있어야 실행됩니다. 로컬 소스가 있다는 사실만으로 릴리스나 Marketplace 게시가 확인된 것은 아닙니다.

## 빠른 시작

검사할 저장소의 `.github/workflows/cassandra.yml`에 저장합니다.

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
        continue-on-error: true # 최종 판정 전에 보고서를 저장하기 위한 용도만 허용합니다.
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

**마지막 판정 단계를 제거하지 마세요.** `continue-on-error`는 산출물 저장을 위한 것이지 취약점이나 검사 오류를 무시하는 옵션이 아닙니다. 종료 코드 출력이 없거나 비어 있어도 실패합니다. 기본 검사에는 비밀값이나 쓰기 권한이 필요하지 않습니다. Action 소스를 더 강하게 고정하려면 `uses`에 검토한 전체 커밋 SHA를 사용하고, CLI `version`도 정확한 버전으로 유지하세요. Action과 CLI 업그레이드는 각각 검토해야 합니다.

## 입력

| 입력 | 기본값 | 의미 |
| --- | --- | --- |
| `version` | `v0.1.0` | 정확한 CLI 릴리스 태그(`vMAJOR.MINOR.PATCH`, prerelease 허용). `latest`, `main`, `v1`은 거부합니다. |
| `path` | `.` | `GITHUB_WORKSPACE` 안의 기존 디렉터리. 심볼릭 링크를 포함해 checkout 밖으로 벗어나는 경로는 거부합니다. |
| `fail-on` | `high` | `none`, `low`, `medium`, `high`, `critical`. 활성화된 임계값에서는 `UNKNOWN` 심각도도 차단합니다. |
| `timeout` | `5m` | `30s`, `5m` 같은 CLI 준비·분석 전체 시간 제한. 다운로드에는 별도 시간 제한이 있습니다. |
| `nvd-api-key` | 없음 | 선택적 NVD API 키. 저장소 파일에 넣지 말고 GitHub Actions secret으로 전달하세요. 기본 검사에는 필요하지 않으며 포크 PR에는 보통 전달되지 않습니다. |

`fail-on: none`은 **취약점 임계값만** 끕니다. 불완전 검사와 운영 오류를 성공으로 바꾸지 않습니다. 이 Action을 쓰기 위해 검사 대상의 의존성을 설치할 필요가 없습니다.

## 출력과 실패 처리

| 출력 | 값 |
| --- | --- |
| `exit-code` | `0`: 완전한 검사 및 정책 통과, `1`: 취약점 정책 위반, `2`: 불완전 검사·지원하지 않는 입력·시간 초과·다운로드·입출력 등 운영 오류. |
| `output-dir` | checkout 밖 `$RUNNER_TEMP` 아래의 실행별 고유 결과 디렉터리. |
| `report-file` | `report.json`: 전체 인벤토리·코드 그래프·finding·경고. |
| `sarif-file` | `results.sarif`: SARIF 2.1.0. 종료 코드 `0` 또는 `1`의 완전한 결과만 업로드합니다. |
| `cyclonedx-file` | `sbom.cyclonedx.json`: CycloneDX 1.6. |
| `spdx-file` | `sbom.spdx.json`: SPDX 2.3. |
| `summary-file` | `summary.md`: GitHub Job Summary에도 추가합니다. |

취약점 정책 위반 시에도 보고서를 보존합니다. 오류·불완전 검사에서는 진단 산출물이 남을 수 있지만, 초기 실패 시에는 경로 출력이 있더라도 파일이 없을 수 있습니다. Markdown 요약은 finding을 일부만 표시할 수 있으며 전체 결과는 JSON에 보존합니다. 지원 매니페스트가 없으면 정상 결과가 아니라 불완전 검사입니다. 의존성이 없는 정상 지원 매니페스트는 통과할 수 있습니다.

runner의 출력 채널이 영구적으로 고장 나면 출력 기록·복구를 보장할 수 없지만 프로세스는 실패합니다. 예제처럼 `steps.cassandra.outcome`도 반드시 대조하세요. `exit-code`만 보거나 `continue-on-error`로 바뀔 수 있는 `conclusion`을 사용하면 안 됩니다. 실패한 단계에 이전 값 `0`이 남아 있어도 job은 실패해야 합니다.

## 선택 사항: GitHub Code scanning

SARIF 업로드를 지원하는 저장소에서는 빠른 시작 예제 대신 [완전한 Code scanning 워크플로](docs/examples/code-scanning.yml)를 사용할 수 있습니다. 검사 job에만 `security-events: write`를 추가하고, 산출물을 저장한 다음 SARIF 파일의 존재와 완전성을 확인합니다. 종료 코드가 `0` 또는 `1`일 때만 업로드하며 마지막에는 원래 검사 결과를 강제합니다.

예제는 포크 PR과 권한이 제한되는 Dependabot 실행의 SARIF 업로드를 생략하되 검사와 artifact 저장은 유지합니다. 권한 문제를 우회하려고 `pull_request_target`으로 바꾸거나 신뢰할 수 없는 PR 코드에 비밀값을 전달하지 마세요. 저장소에서 Code scanning을 사용할 수 있어야 하며, 비공개/내부 저장소에는 GitHub Code Security가 필요할 수 있습니다. [GitHub SARIF 업로드 문서](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)를 참고하세요.

종료 코드 `2`를 정상적인 완전 분석처럼 업로드하면 기존 경고가 잘못 해제될 수 있습니다. SARIF 업로드 없이도 JSON·SBOM·artifact·Job Summary를 사용할 수 있습니다.

SARIF 위치는 검사 `path`를 기준으로 한 상대 경로입니다. 하위 디렉터리를 검사했다면 업로드 사본의 artifact URI를 저장소 상대 경로로 변환하고 검사 루트 `uriBaseId`를 제거하세요. 업로더의 `checkout_path`는 저장소 checkout 루트로 유지합니다. `%SRCROOT%` 메타데이터만 추가했을 때는 GitHub에 저장된 경고 경로에 하위 디렉터리가 반영되지 않았습니다. [게시 버전 검증 workflow](.github/workflows/published-consumer.yml)는 경로 이탈을 거부하면서 원본 보고서와 finding 식별자를 보존하는 예제입니다.

## 실행 환경과 보안 경계

- Linux X64/ARM64 runner만 지원합니다. 최신 GitHub-hosted Ubuntu runner 또는 Bash·curl·tar·표준 Unix 도구·SHA-256 검사 도구(`sha256sum` 또는 `shasum`)가 있는 호환 self-hosted runner를 사용하세요. 로컬 서버·데이터베이스·Go 툴체인·프로젝트 의존성 설치는 필요하지 않습니다.
- **검사 대상 프로젝트의 코드나 install/build/test 스크립트를 실행하지 않습니다.** 자동 수정·PR 생성·배포도 하지 않습니다. Action 자체는 검토한 셸 래퍼와 내려받은 CLI 바이너리를 실행합니다.
- **공개 API 네트워크 접근이 필요합니다.** CLI는 OSV·NVD·CISA KEV·FIRST EPSS 등의 취약점 서비스를 사용하며 Go 그래프 확장에는 Go module proxy를 사용합니다. 패키지 이름·버전이 외부 서비스로 전송되며 전체 소스 코드는 업로드하지 않습니다. 오프라인 스캐너가 아닙니다.
- 다운로드 주소는 `https://github.com/jinho-yoo-jack/Cassandra/releases/download/<version>/`입니다. 래퍼는 `checksums.txt`를 검증하고 실행 파일의 바이트만 추출하며, 저장소·보안 권고 텍스트가 출력되는 동안 GitHub workflow 명령 해석을 중단합니다. 체크섬은 손상 검증이지 릴리스 계정 침해에 대한 증명이 아닙니다. 유지관리자는 정확한 릴리스 태그를 이동하거나 파일을 교체하면 안 됩니다.
- 보고서에는 비공개 의존성 이름과 저장소 경로가 포함될 수 있습니다. 민감한 코드에 적용하기 전에 artifact 접근 권한과 보존 기간을 검토하세요. 취약점 미발견이 모든 보안 문제의 부재를 보증하지는 않습니다. 분석 범위와 한계는 [원본 CLI 문서](https://github.com/jinho-yoo-jack/Cassandra/blob/main/docs/usage/cli-and-actions.md)를 참고하세요.

## 테스트와 유지관리

```sh
bash -n scripts/action.sh
python3 -B -m unittest discover -s tests -v
```

로컬 테스트는 Python 표준 라이브러리와 명시적인 CLI/다운로드 fixture만 사용합니다. 공개 서비스에 접근하지 않으며 게시된 릴리스의 동작을 증명하지는 않습니다. [래퍼 CI](.github/workflows/ci.yml)는 PR과 `main`에서 이 검사를 수행합니다. [실제 소비자 CI](.github/workflows/consumer.yml)는 `main` push와 수동 실행 시 `uses: ./`로 로컬 Action을 호출하고 실제 게시된 CLI `v0.1.0`으로 정상·취약 fixture를 검사합니다. 보고서를 저장하고 종료 코드와 모든 산출물 출력을 확인하며 의존성은 설치하지 않습니다. 공개 API 오류를 취약점 탐지 성공으로 취급하지 않고 워크플로를 실패시킵니다.

[유지관리·릴리스 전제조건](docs/MAINTAINING.md)을 확인하세요. [Apache-2.0](LICENSE) 라이선스이며 래퍼 코드는 [Cassandra](https://github.com/jinho-yoo-jack/Cassandra)에서 가져왔습니다.
