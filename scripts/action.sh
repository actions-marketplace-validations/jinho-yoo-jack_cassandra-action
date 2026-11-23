#!/usr/bin/env bash
# Composite Action adapter: download a pinned CLI, verify it, scan, retain reports.
set -euo pipefail
umask 077

tool_dir=""
output_dir=""
command_token=""
normal_completion=false
cli_code=2
finish() {
  local status=$? code=2
  trap - EXIT
  # EXIT inherits errexit: account for each failure rather than aborting the trap.
  set +e
  # Only a captured CLI result on the normal path can mean success or policy.
  if [[ "$normal_completion" == true && "$status" == 0 ]]; then
    case "$cli_code" in 0|1) code=$cli_code ;; esac
  fi
  if [[ -n "$command_token" ]]; then printf '::%s::\n' "$command_token" || code=2; fi
  # Only downloaded tools are disposable; reports always remain available.
  if [[ -n "$tool_dir" ]]; then rm -rf -- "$tool_dir" || code=2; fi
  if [[ -n "${GITHUB_OUTPUT:-}" && -n "$output_dir" ]]; then
    printf '%s\n' "output-dir=$output_dir" \
      "report-file=$output_dir/report.json" \
      "sarif-file=$output_dir/results.sarif" \
      "cyclonedx-file=$output_dir/sbom.cyclonedx.json" \
      "spdx-file=$output_dir/sbom.spdx.json" \
      "summary-file=$output_dir/summary.md" >> "$GITHUB_OUTPUT" || code=2
  fi
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    if [[ -n "$output_dir" && -f "$output_dir/summary.md" ]]; then
      cat "$output_dir/summary.md" >> "$GITHUB_STEP_SUMMARY" || code=2
    else
      printf '## Cassandra scan\n\nThe scan did not complete. See the step log.\n' >> "$GITHUB_STEP_SUMMARY" || code=2
    fi
    printf '\nExit code: %s (0: passed, 1: vulnerability policy, 2: incomplete/error).\n' "$code" >> "$GITHUB_STEP_SUMMARY" || code=2
  fi
  # Publish the final status only after all summary and cleanup operations.
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    if ! printf 'exit-code=%s\n' "$code" >> "$GITHUB_OUTPUT"; then
      code=2
      # A short/failed write may have left a partial status line. Repair it if
      # possible; a broken output channel must never make the process succeed.
      printf '\nexit-code=2\n' >> "$GITHUB_OUTPUT" || :
      if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        printf '\nExit code: 2 (0: passed, 1: vulnerability policy, 2: incomplete/error).\n' >> "$GITHUB_STEP_SUMMARY" || :
      fi
    fi
  fi
  exit "$code"
}
trap finish EXIT
fail() { printf 'Cassandra: %s\n' "$1" >&2; exit 2; }

[[ "${RUNNER_OS:-}" == Linux ]] || fail 'Only Linux runners are supported.'
version="${INPUT_VERSION:-}"
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || fail 'version must be an exact vMAJOR.MINOR.PATCH release tag.'
case "${RUNNER_ARCH:-}" in
  X64) arch=amd64 ;;
  ARM64) arch=arm64 ;;
  *) fail 'Unsupported runner architecture.' ;;
esac
fail_on="${INPUT_FAIL_ON:-high}"
case "$fail_on" in none|low|medium|high|critical) ;; *) fail 'Invalid fail-on policy.' ;; esac
timeout="${INPUT_TIMEOUT:-5m}"
[[ "$timeout" =~ ^[0-9]+(ms|s|m|h)$ ]] || fail 'timeout must be a positive duration such as 30s or 5m.'
workspace=$(cd "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}" && pwd -P)
target="${INPUT_PATH:-.}"
[[ "$target" == /* ]] || target="$workspace/$target"
[[ -d "$target" ]] || fail 'The scan path must be an existing directory.'
target=$(cd "$target" && pwd -P)
[[ "$target" == "$workspace" || "$target" == "$workspace/"* ]] || fail 'The scan path must remain inside GITHUB_WORKSPACE.'

output_dir=$(mktemp -d "${RUNNER_TEMP:?RUNNER_TEMP is required}/cassandra-results.XXXXXX")
tool_dir=$(mktemp -d "$RUNNER_TEMP/cassandra-tool.XXXXXX")
asset="cassandra_${version}_linux_${arch}.tar.gz"
base="https://github.com/jinho-yoo-jack/Cassandra/releases/download/$version"
for file in "$asset" checksums.txt; do
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --tlsv1.2 --connect-timeout 15 --max-time 120 --retry 2 \
    --output "$tool_dir/$file" "$base/$file"
done
expected=""
while read -r digest name; do
  if [[ "$name" == "$asset" ]]; then
    [[ -z "$expected" ]] || fail 'Duplicate checksum entries.'
    expected="$digest"
  fi
done < "$tool_dir/checksums.txt"
[[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || fail 'Missing or invalid release checksum.'
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$tool_dir" && printf '%s  %s\n' "$expected" "$asset" | sha256sum --check --status) || fail 'Release checksum mismatch.'
else
  (cd "$tool_dir" && printf '%s  %s\n' "$expected" "$asset" | shasum -a 256 --check --status) || fail 'Release checksum mismatch.'
fi
# Extract only the executable's bytes: archive paths/links cannot write elsewhere.
tar -xOzf "$tool_dir/$asset" cassandra > "$tool_dir/cassandra"
[[ -s "$tool_dir/cassandra" ]] || fail 'Release archive contains no CLI.'
chmod 700 "$tool_dir/cassandra"

# Disable workflow command parsing around untrusted repository/advisory text.
command_token="cassandra-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
printf '::stop-commands::%s\n' "$command_token"
cli_code=0
"$tool_dir/cassandra" scan --path "$target" --output-dir "$output_dir" \
  --fail-on "$fail_on" --timeout "$timeout" || cli_code=$?
printf '::%s::\n' "$command_token"
command_token="" # Workflow commands are restored; no EXIT retry is needed.
normal_completion=true
exit 0
