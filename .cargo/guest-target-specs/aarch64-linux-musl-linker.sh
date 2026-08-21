#!/bin/sh
set -e
add_args() {
    for tok in "$@"; do
        case "$tok" in
            --fix-cortex-a53-843419) ;;
            -nodefaultlibs) ;;
            -nostartfiles) ;;
            *) filtered="$filtered $tok" ;;
        esac
    done
}
filtered=""
for arg in "$@"; do
    case "$arg" in
        --fix-cortex-a53-843419) ;;
        -Wl,--fix-cortex-a53-843419) ;;
        -nodefaultlibs) ;;
        -nostartfiles) ;;
        -Wl,*)
            rest="${arg#-Wl,}"
            # Split comma-separated linker options so -z,noexecstack becomes -z noexecstack.
            IFS=',' read -ra toks <<EOF_REST
$rest
EOF_REST
            add_args "${toks[@]}"
            ;;
        *) filtered="$filtered $arg" ;;
    esac
done
exec zig ld.lld $filtered
