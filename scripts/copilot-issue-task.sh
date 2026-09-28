#!/usr/bin/env bash
# Build a focused GitHub Copilot cloud-agent prompt from an mvm issue.
# Usage: ./scripts/copilot-issue-task.sh <issue-number> [--copy]
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: ./scripts/copilot-issue-task.sh <issue-number> [--copy]

Fetches the issue and repository guidance with gh, then prints a bounded,
repo-aware task prompt for GitHub Copilot. It does not assign the issue,
create a branch, or open a PR.

Options:
  --copy   Copy the generated prompt to the clipboard (macOS/Linux with pbcopy/xclip)
USAGE
}

die() { printf 'error: %s\n' "$*" >&2; exit 2; }

issue_number=""
copy_prompt=0
for arg in "$@"; do
  case "$arg" in
    --copy) copy_prompt=1 ;;
    -h|--help) usage; exit 0 ;;
    -* ) die "unknown option: $arg" ;;
    * )
      [[ -z "$issue_number" ]] || die "provide only one issue number"
      issue_number="$arg"
      ;;
  esac
done

[[ "$issue_number" =~ ^[0-9]+$ ]] || { usage >&2; exit 2; }
command -v gh >/dev/null 2>&1 || die "GitHub CLI (gh) is required"
command -v jq >/dev/null 2>&1 || die "jq is required"

repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || die "run this from a git checkout"
repo="$(gh repo view --json nameWithOwner --jq .nameWithOwner)" || die "could not determine GitHub repository; run gh auth login"
[[ "$repo" == "tinylabscom/mvm" ]] || die "expected tinylabscom/mvm checkout, found $repo"

issue_json="$(gh issue view "$issue_number" --repo "$repo" --json number,title,body,url,state,labels,assignees)" || die "could not fetch issue #$issue_number"
issue_title="$(jq -r '.title' <<<"$issue_json")"
issue_url="$(jq -r '.url' <<<"$issue_json")"
issue_state="$(jq -r '.state' <<<"$issue_json")"
issue_body="$(jq -r '.body // "(No issue body.)"' <<<"$issue_json")"
[[ "$issue_state" == OPEN ]] || die "issue #$issue_number is $issue_state, not open"

instructions_file="$repo_root/.github/copilot-instructions.md"
[[ -f "$instructions_file" ]] || die "missing $instructions_file"
instructions="$(cat "$instructions_file")"
if [[ -f "$repo_root/AGENTS.md" ]]; then
  repo_rules="$(sed -n '1,220p' "$repo_root/AGENTS.md")"
else
  repo_rules="(AGENTS.md not found; use repository guidance available to the agent.)"
fi

prompt_file="$(mktemp "${TMPDIR:-/tmp}/mvm-copilot-issue.XXXXXX")"
trap 'rm -f "$prompt_file"' EXIT
cat >"$prompt_file" <<PROMPT
Work on GitHub issue #${issue_number} in `${repo}`.

Issue: ${issue_title}
URL: ${issue_url}

## Issue description

${issue_body}

## Instructions

1. Read and follow the repository guidance below. Start by using the repo's Graft context graph as instructed in `.github/copilot-instructions.md`; inspect exact source spans before editing.
2. Before changing files, summarize the likely root cause and a short implementation/test plan. If the issue lacks enough detail or conflicts with repository contracts, ask a clarifying question in the issue/PR context instead of guessing.
3. Implement only the smallest change that satisfies the issue's explicit expected behavior and acceptance criteria. Preserve existing security boundaries and fail-closed behavior. Do not weaken checks, widen permissions, or increase timeouts to hide a race.
4. Add or update meaningful tests for the behavior and failure cases. Run the narrow relevant tests first, then the applicable repository gates. Follow the repo's host-versus-builder VM rules; do not run VM/Nix/Linux-only operations on the wrong host.
5. Update the active plan and `specs/SPRINT.md` when the repository's Definition of Done requires it. Refresh the Graft graph after substantial code changes.
6. Open a focused PR that links this issue and reports root cause, changes, tests run, and any checks that could not be run. Do not merge it.
7. Keep PR title/body and commits free of assistant, model, or tool attribution. Do not make unrelated edits.

## Repository Copilot instructions

${instructions}

## Repository working agreement (beginning)

${repo_rules}
PROMPT

cat "$prompt_file"

if (( copy_prompt )); then
  if command -v pbcopy >/dev/null 2>&1; then
    pbcopy <"$prompt_file"
    printf '\nPrompt copied to clipboard.\n'
  elif command -v xclip >/dev/null 2>&1; then
    xclip -selection clipboard <"$prompt_file"
    printf '\nPrompt copied to clipboard.\n'
  else
    die "--copy requested, but neither pbcopy nor xclip is installed"
  fi
fi
