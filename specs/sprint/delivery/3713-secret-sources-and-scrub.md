# #3713 — response scrub, secret sources, provider routes, `[secrets]`

The second PS-03 change (`specs/plans/2026-09-25-agent-sandbox-product-surface.md`),
after `--secret` and per-binding scope. It closes the gap the first change's
live run found, and adds the three authoring surfaces PS-03 listed. OAuth2 is
split into a follow-up issue.

## Response-path scrub

The first change's live run showed the one remaining way a raw value reached
the guest: an echo endpoint returned the substituted `authorization` header in
its body. The endpoint now remembers every value it substitutes in the VM and
replaces each occurrence in a response with that binding's placeholder before
a byte reaches the guest.

- **Where:** `SubstitutionService`, on the buffered and streamed response
  paths, which every terminated flow and every typed flow go through. Headers
  are scrubbed before any other transform; the body is scrubbed first in the
  chunk pipeline, ahead of reinjection and redaction.
- **Learning:** the injector reports each value as it substitutes it
  (`SubstitutionObserver`). No second decrypt happens, and a value rotated in
  the store while the VM runs is learned the first time it is sent. So is a
  refreshed OAuth token.
- **Split values:** the scrubber holds back the longest value's length minus
  one byte, so a value split across chunks is caught. Chunked transfer framing
  was already removed before this stage, and the terminator frames its own
  chunks afterwards. HTTP/2 does not arise: nothing on either leg negotiates
  it.
- **Encoded bodies:** a VM holding an injected credential sends
  `Accept-Encoding: identity` upstream in place of the client's value. A
  response that arrives content-encoded anyway is refused with a 502 and
  recorded as `response_encoded_unscannable`. Stripping the header is the
  primary answer because it costs only bandwidth; refusing is the backstop,
  because the endpoint does not decompress and must not relay bytes it cannot
  read.
- **Audit:** `secret.reflection_scrubbed { name, destination, count }`, never
  the value. It is recorded on every exit, including a canceled or failed
  body.
- **Stated limits:** values under 8 bytes are not scrubbed. A value returned in
  a transformed form (base64, split by markup) is not caught.

## Secret sources

`mvmctl secret set|put NAME --from REF` accepts `env://VAR`,
`file:///abs/path`, `keychain://service/account`, `op://vault/item[/section]/field`
and `bw://item/field`. The reference is resolved once, on the host, when the
value is accepted (`mvm_client::secret::SourceResolver`).

The password-manager CLIs are handled as follows:

- **Arguments:** each part is checked against a narrow character set, with no
  leading `-`, no `?` parameters and no quoting. The binary receives an
  argument vector, never a shell line.
- **Binary lookup:** only in `PATH` directories that are absolute, owned by
  root or the user, not world-writable, and outside the current directory, its
  repository and `MVM_HOME`. The binary itself must not be group- or
  world-writable.
- **Environment:** scrubbed with the shared env-hygiene filter. Only that CLI's
  own session variables are re-admitted, by exact name.
- **Limits:** a 60-second timeout and 64 KiB of output.
- **Errors:** the exit status and the first stderr line, never stdout.

The keychain reader is `mvm_core::crypto::secret_store::read_os_keychain_item`,
on the existing `keyring` dependency. No dependency was added.

## Provider routes

Two catalog entries are new: `gitlab` (`gitlab.com`, `PRIVATE-TOKEN`,
`GITLAB_TOKEN`) and `gemini` (`generativelanguage.googleapis.com`,
`x-goog-api-key`, `GEMINI_API_KEY`). Each entry that puts a value on the wire
now declares its credential header, and catalog validation requires it.
`secret providers` prints it as `header=…`. Substitution itself still finds
the placeholder in whichever header it is in.

## `[secrets]` in `mvm.toml`

The table holds names and hosts only. The schema has no field for a value,
and a manifest that tries to add one is refused by a shape check over the
untyped document, whose error quotes none of it. Otherwise the typed parse's
own error would echo the offending string. A run reads the manifest behind
`--manifest`, or the one in a local `--flake` directory. It merges that
manifest's `[secrets]` with `--secret` under the narrowing rule: stored
allow-list ⊇ manifest ⊇ flag. This applies on transient runs, `--entrypoint`
runs and persistent machines.

## Live verification (macOS 26, HVF)

`secret set mvm-live-echo --host postman-echo.com --type bearer --from env://…`,
then
`run --image curlimages/curl:latest --secret mvm-live-echo --allow-host postman-echo.com`
with `curl https://postman-echo.com/headers -H "Authorization: Bearer $MVM_LIVE_ECHO"`:

- the echoed body read `"authorization":"Bearer mvm-secret-dd50…"`;
- the dummy value appeared nowhere in the guest's output or in the audit chain;
- the chain carried `secret.reflection_scrubbed name=mvm-live-echo count=1`
  followed by `forward_outcome completed`;
- `secret providers` listed gitlab and gemini with their headers.

## OAuth2 (follow-up: #3743)

The uncommitted work in the `feat/3266-oauth-broker` worktree would plug in as
follows:

- It adds `SecretBindingMeta.oauth` (non-secret endpoint/client metadata).
- The token set lives encrypted in the secret store.
- `LocalResolver::with_bindings` returns the current access token, or
  `OAuthRefreshRequired`.

The access token then reaches the wire through the same injector, so the
response scrub learns each refreshed token as it is sent. `--from` does not
apply: a token set is written by the host browser flow, not imported.
