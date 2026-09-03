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
