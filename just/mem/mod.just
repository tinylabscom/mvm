# ── Agent memory (.agent-memory/notes) ───────────────────────────────────

# Recall local findings. Lexical, because at a few hundred terse,
# keyword-dense notes a substring match beats anything with a model in it.
# Terms are OR-ed: `just mem::recall teardown ram` finds notes mentioning either.
#
# `.agent-memory/` is gitignored, so a fresh clone has none of this and the
# recipes say so rather than erroring.
recall +TERMS:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -d .agent-memory/notes ]; then
    echo "no .agent-memory/notes yet — notes are local and gitignored; \`just mem::remember <slug>\` starts one"
    exit 0
    fi
    pattern=$(printf '%s' "{{ TERMS }}" | tr ' ' '|')
    rg -il --sort path -e "$pattern" .agent-memory/notes | while read -r path; do
    printf '%s\n    %s\n' \
    "$(basename "$path" .md)" \
    "$(sed -n 's/^title: //p' "$path")"
    done

# List every note, newest first.
notes:
    #!/usr/bin/env bash
    set -euo pipefail
    shopt -s nullglob
    set -- .agent-memory/notes/*.md
    if [ "$#" -eq 0 ]; then
    echo "no .agent-memory/notes yet — notes are local and gitignored; \`just mem::remember <slug>\` starts one"
    exit 0
    fi
    for path in "$@"; do
    printf '%s  %s — %s\n' \
    "$(sed -n 's/^date: //p' "$path")" \
    "$(basename "$path" .md)" \
    "$(sed -n 's/^title: //p' "$path")"
    done | sort -r

# Scaffold a note. Fill in the body; it stays in your checkout, gitignored.
remember SLUG:
    #!/usr/bin/env bash
    set -euo pipefail
    path=".agent-memory/notes/{{ SLUG }}.md"
    if [ -e "$path" ]; then echo "note {{ SLUG }} already exists" >&2; exit 1; fi
    printf -- '---\ntitle: \ndate: %s\ntags: []\n---\n\n' "$(date +%F)" > "$path"
    echo "created $path"

# Local findings parse, are dated, and link to notes that exist. Not in
# `check-all`: CI has no .agent-memory/ to check.
check:
    cargo run -p xtask -- check-agent-notes
