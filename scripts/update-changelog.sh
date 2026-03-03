#!/usr/bin/env bash
#
# update-changelog.sh - Automatically add or update a changelog entry for a release
#
# Usage: scripts/update-changelog.sh --version X.Y.Z [--changelog PATH]
#
# If the version section doesn't exist, it will be inserted at the top after
# the "# Changelog" header with recent commits as bullet points.

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/update-changelog.sh --version X.Y.Z [--changelog PATH]

Automatically adds a changelog section for the given version if it doesn't exist.
Uses recent git commits since the last tag to populate initial entries.

Options:
  --version X.Y.Z   Target release version (required)
  --changelog PATH  Changelog file (default: CHANGELOG.md)
  --help            Show this help text
USAGE
}

version=""
changelog="CHANGELOG.md"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --changelog)
      changelog="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$version" ]]; then
  echo "--version is required" >&2
  exit 1
fi

if [[ ! -f "$changelog" ]]; then
  echo "Changelog not found: $changelog" >&2
  exit 1
fi

# Check if entry already exists (support both hyphen and em dash)
if grep -Eq "^## \[$version\]" "$changelog"; then
  echo "Changelog entry for $version already exists"
  exit 0
fi

# Get current date in YYYY-MM-DD format
current_date=$(date +%Y-%m-%d)

# Get commits since last tag for automatic changelog generation
last_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [[ -n "$last_tag" ]]; then
  # Get commit messages since last tag, format as bullet points
  commits=$(git log "$last_tag..HEAD" --pretty=format:"- %s" --no-merges | head -10)
else
  # No previous tags, get last 10 commits
  commits=$(git log --pretty=format:"- %s" --no-merges -10)
fi

# Create temp file with new entry
temp_entry=$(mktemp)
cat > "$temp_entry" <<NEW_ENTRY
## [$version] — $current_date

### Added
$commits

### Changed

### Fixed

NEW_ENTRY

# Find the line number where we should insert (after "# Changelog" header)
insert_line=$(grep -n "^# Changelog" "$changelog" | head -1 | cut -d: -f1)
if [[ -z "$insert_line" ]]; then
  # If no "# Changelog" header, insert before first "## " heading
  insert_line=$(grep -n "^## " "$changelog" | head -1 | cut -d: -f1)
  if [[ -z "$insert_line" ]]; then
    echo "Could not find insertion point in $changelog" >&2
    rm "$temp_entry"
    exit 1
  fi
  insert_line=$((insert_line - 1))
else
  insert_line=$((insert_line + 1))
fi

# Insert the new entry
{
  head -n "$insert_line" "$changelog"
  echo ""
  cat "$temp_entry"
  tail -n +$((insert_line + 1)) "$changelog"
} > "${changelog}.tmp"

mv "${changelog}.tmp" "$changelog"
rm "$temp_entry"

echo "Added changelog entry for version $version ($current_date)"
echo "Please review and edit $changelog to categorize changes properly."
