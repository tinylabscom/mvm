#ifndef MVM_HOSTLIB_H
#define MVM_HOSTLIB_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t *data;
    size_t len;
} MvmHostlibBuf;

typedef struct MvmHostlibContext MvmHostlibContext;

uint32_t mvm_hostlib_abi_version(void);
int32_t mvm_hostlib_abi_is_compatible(uint16_t major, uint16_t minor);
int32_t mvm_hostlib_call(const uint8_t *method, size_t method_len,
                        const uint8_t *request, size_t request_len,
                        MvmHostlibBuf *out);
void mvm_hostlib_free(MvmHostlibBuf buf);

/*
 * Contexts require independent create negotiation for ABI 1.9 or later
 * supported within major 1. The legacy global latch does not authorize them.
 * Initialize *slot to NULL; keep the shared library strongly held until
 * checked_free succeeds. Never serialize a context address.
 *
 * Calls on a context are serial; concurrent/reentrant operations refuse busy.
 * The caller MUST exclude ALL access (including calls about to begin) while
 * checked_free runs. A lock check cannot make racing pointer destruction safe.
 * Every returned buffer must be freed exactly once with mvm_hostlib_free.
 * An ordinary session gets one start attempt per context. Unknown/malformed
 * starts retain their private original response and forbid close/free.
 * Stop must name the original validated binding; it cannot clear another
 * session. This compatibility lifetime is not native generation/exit proof.
 */
int32_t mvm_hostlib_context_create(uint16_t major, uint16_t minor,
                                 MvmHostlibContext **slot, MvmHostlibBuf *out);
int32_t mvm_hostlib_context_call(MvmHostlibContext *context,
                               const uint8_t *method, size_t method_len,
                               const uint8_t *request, size_t request_len,
                               MvmHostlibBuf *out);

enum MvmHostlibContextPart {
    MVM_CONTEXT_RESULT = 0,
    MVM_CONTEXT_PRIMARY = 1,
    MVM_CONTEXT_FLUSH = 2,
    MVM_CONTEXT_STOP = 3,
    MVM_CONTEXT_CLEANUP = 4
};
/*
 * Inspection only copies data; it never dispatches, reconnects or cleans up.
 * Invalid selectors refuse without effect. For error parts, OK with len=0
 * means absence, NOT successful work or native completion. RESULT can be a
 * failure/nonzero terminal even when the transport call succeeded.
 * Native raw output requires original exit plus required flush/kernel cleanup.
 */
int32_t mvm_hostlib_context_inspect(MvmHostlibContext *context, uint32_t part,
                                  MvmHostlibBuf *out);
int32_t mvm_hostlib_context_retry_stop(MvmHostlibContext *context,
                                     MvmHostlibBuf *out);
/*
 * Explicit close retains the pointer and the full original group on failure.
 * Retry uses only the held original owner and remaining cleanup, never work.
 * Neither process exit nor closing descriptors proves the native VM stopped.
 */
int32_t mvm_hostlib_context_close(MvmHostlibContext *context, MvmHostlibBuf *out);
/*
 * Nonblocking, no implicit stop: only Empty/Closed can be freed. On failure
 * *slot is unchanged; on success it becomes NULL. No unconditional destructor.
 * Abandoning a retained pointer loses recovery; it is not cleanup success.
 */
int32_t mvm_hostlib_context_checked_free(MvmHostlibContext **slot);

#ifdef __cplusplus
}
#endif
#endif
