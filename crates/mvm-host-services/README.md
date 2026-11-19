# mvm-host-services

`mvm-host-services` is the language-neutral C ABI used by code running inside a
guest to call mvm host services. It builds both a Rust library and a `cdylib`
that language SDKs can load without linking their own Rust transport stack.

## Who uses it

`mvm-sdk` packages and describes the veneer for generated Python, TypeScript,
and other guest SDK adapters. Inside the shared object, `mvm-agentd` supplies
the broker client and `mvm-core` supplies the typed service vocabulary. The
host-side peer is the broker in `mvm-hostd`.

## How it works

1. A language binding passes a UTF-8 method name, a JSON request buffer, and a
   timeout to `mvm_hsvc_call`.
2. The veneer validates pointers, lengths, UTF-8, method shape, and limits.
3. It maps the method to the typed guest broker client and sends the request
   over the established vsock service channel.
4. It returns owned JSON bytes and a stable integer status code.
5. The caller releases that allocation with `mvm_hsvc_free`.

The ABI intentionally has only one call and one free operation. Service verbs
such as `host.audit.emit`, `host.time.now`, and `host.cost.workload` evolve in
the typed broker protocol instead of multiplying exported symbols.

`host.actor.call` accepts the canonical versioned `ActorRequest` and returns
`ActorResponse`. Unlike ordinary broker calls, it requires the admitted per-boot
actor identity, pins the actor holder's public key, and encrypts the request and
reply with the shared authenticated session protocol. The broker forwards only
bounded opaque bytes. Missing provisioning or a mismatched boot, purpose, key,
or protocol fails closed; there is no bare `ServiceCall` fallback. Deadlines
must be between one and 300 seconds. A transport failure after dispatch can
mean an unknown outcome: retry only with the original operation's idempotency key.

The actor holder uses a private inherited socket to the separate lifecycle
authority; the guest library and broker cannot mint launch permits. Mailbox
application payloads do not use this channel.

`host.mailbox.call`, `host.mailbox.receive`, `host.mailbox.reply`,
`host.mailbox.receive_result`, `host.mailbox.ack_result`, and
`host.mailbox.ack_request` use the existing guest-local mailbox reader socket,
not the broker. The guest agent holds the mailbox ACK identity and establishes
an encrypted mailbox-purpose session with its VM-scoped holder over the dedicated
mailbox port. The complete admitted boot/plan/address/policy binding and fresh
session nonce are checked before application payload disclosure. Current signed
reader enrollment and operation capabilities remain independent authorization
gates; session authentication alone grants no operation.

Messages use canonical mailbox addresses and IDs. Payload bytes are base64 in
the JSON field `payload_b64`. Call and Reply IDs are caller-supplied and stable;
the FFI does not retry. `queued` means the immutable source intent is durable,
not that the child replied. `receive_result` does not settle a call: only explicit
`ack_result` does. The call wait deadline is separate from the reply's finite
authority and retention window. A delivery includes its canonical signed lease;
both ACK methods require that exact lease. The agent signs the canonical
`MailboxDeliveryAck` only for an observed lease and retains exact signed bytes
for bounded retries. Fresh enrolled reader possession is proven inside the
encrypted exchange before each operation; session authentication is not a
substitute for the signed lease/ACK journal.
Missing provisioning fails closed, with no
plaintext host-hop fallback or new guest listener. This is a trusted-host
transport boundary, not confidentiality from an actively compromised host.

```c
typedef struct { uint8_t *data; size_t len; } MvmHsvcBuf;

int32_t mvm_hsvc_call(const uint8_t *method, size_t method_len,
                      const uint8_t *request, size_t request_len,
                      uint64_t timeout_secs, MvmHsvcBuf *out);
void mvm_hsvc_free(MvmHsvcBuf buf);
```

## Security boundary

This guest library holds no host key and grants no authority. The host broker
enforces the execution plan, service allowlist, rate and size limits, forced
audit categories, and correlation identities. The FFI layer's responsibility
is memory safety, bounded input, stable ownership, and non-sensitive errors.

## Developing

Run `cargo test -p mvm-host-services`. Every ABI change needs layout tests,
null/invalid pointer cases, allocation/free tests, status-code stability, and
end-to-end broker round trips. Exported symbol changes also require updating
all language shims together.
