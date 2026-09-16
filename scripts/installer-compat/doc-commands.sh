#!/bin/sh
# Print the first fenced shell block under a heading of a markdown page.
#
#   doc-commands.sh <page.md> "<heading line, exactly as written>"
#
# Fails when the heading is missing, or when another heading comes before any
# fenced block — a restructured page must break the smoke loudly rather than
# have it run nothing.
set -eu

[ "$#" -eq 2 ] || { echo "usage: $0 <page.md> \"<heading line>\"" >&2; exit 2; }

awk -v heading="$2" '
  BEGIN { state = "seek" }
  state == "seek" { if ($0 == heading) state = "under"; next }
  state == "under" {
    if ($0 ~ /^#/) { print "heading \"" heading "\" has no fenced block before the next heading" > "/dev/stderr"; failed = 1; exit }
    if ($0 ~ /^```(bash|sh|shell)?[[:space:]]*$/) state = "block"
    next
  }
  state == "block" {
    if ($0 ~ /^```[[:space:]]*$/) { state = "done"; exit }
    print
    printed = 1
  }
  END {
    if (failed) exit 1
    if (state == "seek") { print "heading \"" heading "\" not found" > "/dev/stderr"; exit 1 }
    if (state != "done") { print "heading \"" heading "\" has no closed fenced block" > "/dev/stderr"; exit 1 }
    if (!printed) { print "heading \"" heading "\" has an empty fenced block" > "/dev/stderr"; exit 1 }
  }
' "$1"
