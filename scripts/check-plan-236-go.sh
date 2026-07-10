#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MAIN_REPO="${REPO_ROOT}"
DEFAULT_MAIN_REF="main"
if git -C "${MAIN_REPO}" rev-parse --verify origin/main >/dev/null 2>&1; then
  DEFAULT_MAIN_REF="origin/main"
fi
MAIN_REF="${PLAN236_MAIN_REF:-${DEFAULT_MAIN_REF}}"
WATCH_INTERVAL="${PLAN236_WATCH_INTERVAL:-10}"

usage() {
  cat <<'EOF'
Usage: scripts/check-plan-236-go.sh [--watch] [--json]

Checks whether the prerequisite inputs for Plan 236 are in a conservative
"ready to integrate" state.

Current GO criteria:
  - merged prerequisite slices stay reachable from the chosen main ref
  - active prerequisite worktrees exist
  - active worktree branches match the expected branch
  - active worktrees are not detached
  - active worktrees have no local tracked or untracked changes
  - active worktree branches are not behind the chosen main ref
  - active worktree branches are either ahead of the chosen main ref or exactly
    aligned with it after refresh

Environment overrides:
  PLAN236_MAIN_REF=origin/main   Compare against a different main ref
  PLAN236_WATCH_INTERVAL=5       Seconds between --watch refreshes
EOF
}

WATCH=0
JSON=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --watch)
      WATCH=1
      shift
      ;;
    --json)
      JSON=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

INPUT_LABELS=(
  "agent-verb-grant-delivery"
  "vsock-port-handler-registry"
  "host-services-cleanup"
  "vsock-only-egress-cutover"
  "mvm-client-facade"
)
INPUT_KINDS=(
  "merged"
  "merged"
  "worktree"
  "worktree"
  "worktree"
)
INPUT_PATHS=(
  "-"
  "-"
  "/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-plan-202-refresh"
  "/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-vsock-egress-refresh"
  "/Users/auser/work/tinylabs/mvmco/.worktrees/mvm-plan-216-refresh"
)
EXPECTED_BRANCHES=(
  "merged-on-main"
  "merged-on-main"
  "codex/plan-236-plan202-refresh"
  "codex/plan-236-vsock-egress-refresh"
  "codex/plan-236-plan216-refresh"
)
MERGED_REFS=(
  "7ba5df7c3dcba134249da2fc779b91f5558304f3"
  "6a9b94397048cc2b9d452c30cd34fdf9ff30c025"
  ""
  ""
  ""
)

git_cmd() {
  git -C "${1}" "${@:2}"
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  printf '%s' "${s}"
}

collect_status() {
  local label="$1"
  local kind="$2"
  local path="$3"
  local expected_branch="$4"
  local merged_ref="$5"

  local exists="false"
  local detached="false"
  local branch=""
  local dirty_count=0
  local ahead=0
  local behind=0
  local status="GO"
  local reasons=()

  if [[ "${kind}" == "merged" ]]; then
    exists="true"
    branch="merged@${MAIN_REF}"
    if ! git -C "${MAIN_REPO}" rev-parse --verify "${MAIN_REF}" >/dev/null 2>&1; then
      status="NO-GO"
      reasons+=("missing comparison ref ${MAIN_REF}")
    elif [[ -z "${merged_ref}" ]] || ! git -C "${MAIN_REPO}" rev-parse --verify "${merged_ref}" >/dev/null 2>&1; then
      status="NO-GO"
      reasons+=("missing merged prerequisite ref ${merged_ref:-<unset>}")
    elif ! git -C "${MAIN_REPO}" merge-base --is-ancestor "${merged_ref}" "${MAIN_REF}" >/dev/null 2>&1; then
      status="NO-GO"
      reasons+=("merged prerequisite ${merged_ref:0:12} not reachable from ${MAIN_REF}")
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "${label}" "${path}" "${expected_branch}" "${exists}" "${status}" "${branch}" "${dirty_count}" "${ahead}|${behind}"
    if [[ ${#reasons[@]} -eq 0 ]]; then
      printf '\n'
    else
      printf '%s\n' "$(IFS='; '; printf '%s' "${reasons[*]}")"
    fi
    return
  fi

  if [[ ! -d "${path}" ]]; then
    exists="false"
    status="NO-GO"
    reasons+=("missing worktree")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "${label}" "${path}" "${expected_branch}" "${exists}" "${status}" "" "0" "0|0"
    printf '%s\n' "$(IFS='; '; printf '%s' "${reasons[*]}")"
    return
  fi

  exists="true"
  branch="$(git_cmd "${path}" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  if [[ "${branch}" == "HEAD" || -z "${branch}" ]]; then
    detached="true"
    status="NO-GO"
    reasons+=("detached HEAD")
  fi

  if [[ "${branch}" != "${expected_branch}" ]]; then
    status="NO-GO"
    reasons+=("branch mismatch (expected ${expected_branch}, got ${branch:-detached})")
  fi

  dirty_count="$(git_cmd "${path}" status --porcelain | wc -l | tr -d ' ')"
  if [[ "${dirty_count}" != "0" ]]; then
    status="NO-GO"
    reasons+=("local changes (${dirty_count})")
  fi

  if git -C "${MAIN_REPO}" rev-parse --verify "${MAIN_REF}" >/dev/null 2>&1; then
    local counts
    counts="$(git -C "${MAIN_REPO}" rev-list --left-right --count "${MAIN_REF}...${branch:-HEAD}" 2>/dev/null || printf '0\t0')"
    behind="$(printf '%s' "${counts}" | awk '{print $1}')"
    ahead="$(printf '%s' "${counts}" | awk '{print $2}')"
    if [[ "${behind}" != "0" ]]; then
      status="NO-GO"
      reasons+=("behind ${MAIN_REF} by ${behind}")
    fi
    if [[ "${ahead}" == "0" && "${behind}" == "0" ]]; then
      branch="${branch}@aligned"
    fi
  else
    status="NO-GO"
    reasons+=("missing comparison ref ${MAIN_REF}")
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${label}" "${path}" "${expected_branch}" "${exists}" "${status}" "${branch}" "${dirty_count}" "${ahead}|${behind}"
  if [[ ${#reasons[@]} -eq 0 ]]; then
    printf '\n'
  else
    printf '%s\n' "$(IFS='; '; printf '%s' "${reasons[*]}")"
  fi
}

render_once() {
  local overall="GO"
  local rows=()
  local reasons=()
  local idx

  for idx in "${!INPUT_LABELS[@]}"; do
    local output
    output="$(
      collect_status \
        "${INPUT_LABELS[$idx]}" \
        "${INPUT_KINDS[$idx]}" \
        "${INPUT_PATHS[$idx]}" \
        "${EXPECTED_BRANCHES[$idx]}" \
        "${MERGED_REFS[$idx]}"
    )"
    local header
    header="$(printf '%s' "${output}" | sed -n '1p')"
    local reason_line
    reason_line="$(printf '%s' "${output}" | sed -n '2p')"
    rows+=("${header}")
    reasons+=("${reason_line}")
    local row_status
    row_status="$(printf '%s' "${header}" | cut -f5)"
    if [[ "${row_status}" != "GO" ]]; then
      overall="NO-GO"
    fi
  done

  if [[ "${JSON}" == "1" ]]; then
    printf '{\n'
    printf '  "plan": "236",\n'
    printf '  "main_ref": "%s",\n' "$(json_escape "${MAIN_REF}")"
    printf '  "overall": "%s",\n' "${overall}"
    printf '  "worktrees": [\n'
    for idx in "${!rows[@]}"; do
      IFS=$'\t' read -r label path expected exists status branch dirty counts <<<"${rows[$idx]}"
      ahead="${counts%%|*}"
      behind="${counts##*|}"
      printf '    {\n'
      printf '      "label": "%s",\n' "$(json_escape "${label}")"
      printf '      "path": "%s",\n' "$(json_escape "${path}")"
      printf '      "expected_branch": "%s",\n' "$(json_escape "${expected}")"
      printf '      "branch": "%s",\n' "$(json_escape "${branch}")"
      printf '      "exists": %s,\n' "${exists}"
      printf '      "status": "%s",\n' "${status}"
      printf '      "dirty_count": %s,\n' "${dirty}"
      printf '      "ahead": %s,\n' "${ahead}"
      printf '      "behind": %s,\n' "${behind}"
      printf '      "reasons": ['
      if [[ -n "${reasons[$idx]}" ]]; then
        local first=1
        local reason
        IFS=';' read -r -a split_reasons <<<"${reasons[$idx]}"
        for reason in "${split_reasons[@]}"; do
          reason="${reason# }"
          if [[ "${first}" -eq 0 ]]; then
            printf ', '
          fi
          printf '"%s"' "$(json_escape "${reason}")"
          first=0
        done
      fi
      printf ']\n'
      if [[ "${idx}" -lt $((${#rows[@]} - 1)) ]]; then
        printf '    },\n'
      else
        printf '    }\n'
      fi
    done
    printf '  ]\n'
    printf '}\n'
    return
  fi

  printf 'Plan 236 readiness against %s: %s\n' "${MAIN_REF}" "${overall}"
  printf '\n'
  printf '%-30s %-5s %-8s %-8s %-9s %s\n' "input" "go" "ahead" "behind" "dirty" "branch"
  printf '%-30s %-5s %-8s %-8s %-9s %s\n' "--------" "--" "-----" "------" "-----" "------"
  for idx in "${!rows[@]}"; do
    IFS=$'\t' read -r label path expected exists status branch dirty counts <<<"${rows[$idx]}"
    ahead="${counts%%|*}"
    behind="${counts##*|}"
    printf '%-30s %-5s %-8s %-8s %-9s %s\n' \
      "${label}" "${status}" "${ahead}" "${behind}" "${dirty}" "${branch:-detached}"
    if [[ -n "${reasons[$idx]}" ]]; then
      printf '  reasons: %s\n' "${reasons[$idx]}"
      printf '  path: %s\n' "${path}"
    fi
  done
  printf '\n'
  if [[ "${overall}" == "GO" ]]; then
    printf 'GO: the tracked prerequisite inputs look integration-ready for Plan 236.\n'
  else
    printf 'NO-GO: at least one tracked prerequisite input is stale, dirty, detached, mismatched, or not yet reachable from %s.\n' "${MAIN_REF}"
  fi
}

if [[ "${WATCH}" == "1" ]]; then
  while true; do
    clear
    printf '[%s] ' "$(date '+%Y-%m-%d %H:%M:%S')"
    render_once
    sleep "${WATCH_INTERVAL}"
  done
else
  render_once
fi
