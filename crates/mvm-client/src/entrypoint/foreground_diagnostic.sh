set -euo pipefail
umask 077
# Bound guest-private diagnostics even if the client is unexpectedly noisy.
ulimit -f 2048
B=/nix/store/d6qdvwi82xli2wxbfkzadzcaigm2krw8-busybox-static-aarch64-unknown-linux-musl-1.36.1/bin/busybox
S=/nix/store/7ls7m3jyp74xb0ahnybm2pk4s2pvnk3n-bash-5.3p3/bin/bash
C=/nix/store/ndjllrzn0dy5z18dns77n2wfzjl9flkq-claude-code-native-2.1.273/bin/claude
export B S
work=$("$B" mktemp -d /tmp/foreground-diagnostic.XXXXXXXX)
export work
server=
finish() {
    if [[ -n "$server" ]]; then
        kill "$server" 2>/dev/null || :
        wait "$server" 2>/dev/null || :
    fi
    "$B" rm -rf "$work"
}
trap finish EXIT
read -r actual _ < <("$B" sha256sum "$C")
[[ "$actual" == 7544d5d74f38f78b7d5457728dea4bf3f467befda7c1a892021dcfbfda1ab4e1 ]]
"$B" timeout 5 "$C" --version < /dev/null > "$work/version" 2> "$work/version-error"
IFS= read -r version < "$work/version"
[[ "$version" == '2.1.273 (Claude Code)' ]]
"$B" cat > "$work/handler" <<'HANDLER'
set -euo pipefail
# tcpsvd -c 1 serializes handlers; every accepted connection is counted.
n=0
[[ ! -f "$work/count" ]] || read -r n < "$work/count"
n=$((n + 1))
printf '%s\n' "$n" > "$work/count"
if (( n >= 4 )); then
    # The foreground script recorded its actual live server child.
    read -r server_child < "$work/server-child"
    trap 'kill -TERM "$server_child" 2>/dev/null || :' EXIT
fi
(( n <= 4 )) || exit 1
export LC_ALL=C
IFS= read -r -t 5 -n 4097 line
[[ ${#line} -le 4096 ]] || exit 1
[[ "$line" =~ ^([A-Z]+)\ ([^[:space:]]+)\ HTTP/1.1$'\r'$ ]] || exit 1
request=${line%$'\r'}
length=
headers=
auth=false
bytes=0
api_version=
encoding=
betas=
for (( i=0; i<64; i++ )); do
    IFS= read -r -t 5 -n 4097 line
    (( bytes += ${#line} + 1 ))
    (( bytes <= 16384 )) || exit 1
    [[ "$line" == *$'\r' ]] || exit 1
    line=${line%$'\r'}
    [[ -n "$line" ]] || break
    [[ "$line" == *:* ]] || exit 1
    name=${line%%:*}
    name=$(printf '%s' "$name" | "$B" tr 'A-Z' 'a-z')
    [[ "$name" =~ ^[a-z0-9-]{1,64}$ ]] || exit 1
    value=${line#*:}
    value=${value#"${value%%[!$' \t']*}"}
    case "$name" in
        transfer-encoding|expect) exit 1 ;;
        content-length)
            [[ -z "$length" && "$value" =~ ^[0-9]{1,5}$ ]] || exit 1
            length=$((10#$value))
            (( length > 0 && length <= 65536 )) || exit 1
            ;;
        x-api-key)
            [[ "$value" == 'synthetic-foreground-diagnostic-not-a-credential' ]] || exit 1
            auth=true
            ;;
        authorization) exit 1 ;;
        anthropic-version|content-encoding|anthropic-beta)
            [[ ${#value} -le 1024 && "$value" =~ ^[a-zA-Z0-9,._:/+\;\ =-]*$ ]] || exit 1
            case "$name" in
                anthropic-version) api_version+="$value," ;;
                content-encoding) encoding+="$value," ;;
                anthropic-beta) betas+="$value," ;;
            esac
            ;;
    esac
    headers+="$name,"
done
(( i < 64 )) && [[ -n "$length" && "$auth" == true ]] || exit 1
"$B" dd bs=1 count="$length" of="$work/body-$n" 2>/dev/null
[[ $("$B" wc -c < "$work/body-$n") -eq "$length" ]] || exit 1
printf '%s\n' "$headers" > "$work/headers-$n"
printf 'request=%s\napi_version=%s\nencoding=%s\nbetas=%s\n' "$request" "$api_version" "$encoding" "$betas" > "$work/protocol-$n"
response='{"type":"error","error":{"type":"invalid_request_error","message":"synthetic foreground diagnostic refusal"}}'
printf 'HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' "${#response}" "$response"
printf 'complete\n' > "$work/complete-$n"
HANDLER
"$B" tcpsvd -c 1 127.0.0.1 18983 "$B" timeout 5 "$S" "$work/handler" < /dev/null > "$work/server-out" 2> "$work/server-error" &
server=$!
printf '%s\n' "$server" > "$work/server-child"
"$B" mkdir "$work/home"
set +e
"$B" timeout 35 "$B" env -i \
    HOME="$work/home" PATH="${B%/*}" TERM=dumb \
    ANTHROPIC_BASE_URL=http://127.0.0.1:18983 \
    ANTHROPIC_API_KEY=synthetic-foreground-diagnostic-not-a-credential \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    CLAUDE_CODE_MAX_OUTPUT_TOKENS=20000 \
    CLAUDE_CODE_MAX_RETRIES=0 \
    CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1 \
    ENABLE_TOOL_SEARCH=false \
    DISABLE_AUTOUPDATER=1 \
    "$C" --print --model claude-haiku-4-5-20251001 --max-turns 1 \
    -- 'Reply with the single word diagnostic. Do not use tools.' \
    < /dev/null > "$work/client-out" 2> "$work/client-error"
code=$?
set -e
kill "$server" 2>/dev/null || :
wait "$server" 2>/dev/null || :
server=
[[ -f "$work/count" ]]
read -r count < "$work/count"
(( count >= 1 && count <= 4 ))
printf 'client_sha256=%s\nclient_version=%s\nclient_exit=%s\nattempts=%s\n' "$actual" "$version" "$code" "$count"
for (( n=1; n<=count; n++ )); do
    [[ -f "$work/complete-$n" ]]
    "$B" cat "$work/protocol-$n"
    IFS= read -r headers < "$work/headers-$n"
    printf 'headers=%s\nbody=' "$headers"
    "$B" base64 < "$work/body-$n" | "$B" tr -d '\n'
    printf '\n'
done
