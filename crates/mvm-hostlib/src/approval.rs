//! Runtime approvals for applications embedding the host library.
//!
//! The language binding registers one process-wide callback. Every machine
//! this process boots gets a host-local approval broker after admitted boot
//! and before an optional guest command starts. The broker stays alive after
//! the ABI call returns, including for persistent machines, and is removed on
//! `machine.stop` or `machine.rm`.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use mvm_client::approval_broker::{
    ApprovalAnswer, ApprovalPrompt, ApprovalScope, ApprovalServer, CallbackBackend,
};
use mvm_client::launch::detached::{BootCommand, CommandStarter, GuestAgentStarter};

use crate::status::MVM_HOSTLIB_OK;

/// Deny the request. Every unknown callback result is treated this way.
const CALLBACK_DENY: i32 = 0;
/// Approve only this request.
const CALLBACK_APPROVE_ONCE: i32 = 1;
/// Approve this question for the endpoint's bounded session TTL.
const CALLBACK_APPROVE_SESSION: i32 = 2;

/// The callback shape exposed through the C ABI.
pub type ApprovalCallback = unsafe extern "C" fn(*const u8, usize) -> i32;

#[derive(Default)]
struct CallbackState {
    callback: Option<ApprovalCallback>,
    active_calls: usize,
}

fn callback_state() -> &'static (Mutex<CallbackState>, Condvar) {
    static CALLBACK: OnceLock<(Mutex<CallbackState>, Condvar)> = OnceLock::new();
    CALLBACK.get_or_init(|| (Mutex::new(CallbackState::default()), Condvar::new()))
}

fn servers() -> &'static Mutex<HashMap<String, ApprovalServer>> {
    static SERVERS: OnceLock<Mutex<HashMap<String, ApprovalServer>>> = OnceLock::new();
    SERVERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register or clear the SDK callback used by machines this process launches.
///
/// A binding must keep a non-null pointer alive until a later setter call
/// returns. The setter waits for in-flight calls before replacing it. Existing
/// brokers read the current pointer for each question, so clearing the callback
/// makes them deny immediately. A callback must not call this setter itself.
#[unsafe(no_mangle)]
pub extern "C" fn mvm_hostlib_set_approval_callback(callback: Option<ApprovalCallback>) -> i32 {
    let (state, idle) = callback_state();
    let mut state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while state.active_calls != 0 {
        state = idle
            .wait(state)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    state.callback = callback;
    MVM_HOSTLIB_OK
}

fn answer(prompt: &ApprovalPrompt) -> ApprovalAnswer {
    let Ok(encoded) = serde_json::to_vec(prompt) else {
        return ApprovalAnswer::denied(prompt.request_id.clone(), "sdk_callback_encode");
    };
    let (state, idle) = callback_state();
    let callback = {
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(callback) = state.callback else {
            return ApprovalAnswer::denied(prompt.request_id.clone(), "sdk_callback_unset");
        };
        state.active_calls += 1;
        callback
    };
    struct ActiveCall<'a> {
        state: &'a Mutex<CallbackState>,
        idle: &'a Condvar,
    }
    impl Drop for ActiveCall<'_> {
        fn drop(&mut self) {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.active_calls -= 1;
            self.idle.notify_all();
        }
    }
    let _active = ActiveCall { state, idle };
    // SAFETY: the binding supplied this C function pointer and its contract
    // requires it to stay alive until a later setter call returns. The active
    // call guard prevents that setter from returning while this invocation is
    // running, and `encoded` remains readable for the duration of the call.
    let decision = unsafe { callback(encoded.as_ptr(), encoded.len()) };
    match decision {
        CALLBACK_APPROVE_ONCE => ApprovalAnswer::approved(
            prompt.request_id.clone(),
            ApprovalScope::Once,
            "sdk_callback",
        ),
        CALLBACK_APPROVE_SESSION => ApprovalAnswer::approved(
            prompt.request_id.clone(),
            ApprovalScope::Session,
            "sdk_callback",
        ),
        CALLBACK_DENY => ApprovalAnswer::denied(prompt.request_id.clone(), "sdk_callback_denied"),
        _ => ApprovalAnswer::denied(prompt.request_id.clone(), "sdk_callback_invalid"),
    }
}

/// Bind and retain `name`'s broker when an SDK callback is registered.
///
/// Failure leaves no broker, which is the endpoint's fail-closed denial path.
pub(crate) fn ensure_server(name: &str) {
    if callback_state()
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .callback
        .is_none()
    {
        return;
    }
    let mut live = servers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if live.contains_key(name) {
        return;
    }
    let path = mvm_core::config::vm_approval_socket(name);
    let backend = Arc::new(CallbackBackend::new(answer));
    match ApprovalServer::bind(&path, backend) {
        Ok(server) => {
            live.insert(name.to_string(), server);
        }
        Err(error) => {
            tracing::warn!(
                machine = name,
                error = %format!("{error:#}"),
                "SDK approval broker not started; ask decisions will be denied"
            );
        }
    }
}

/// Stop retaining `name`'s broker. Dropping it removes the private socket.
pub(crate) fn remove_server(name: &str) {
    servers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(name);
}

/// Starts a launch command only after its machine has an approval broker.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ApprovalCommandStarter;

impl CommandStarter for ApprovalCommandStarter {
    fn start(&self, name: &str, command: BootCommand) -> anyhow::Result<String> {
        ensure_server(name);
        GuestAgentStarter.start(name, command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    use mvm_contract::policy::approval::{ApprovalOutcome, ApprovalRequestId};
    use mvm_contract::policy::approval_prompt::ApprovalSubject;
    use mvm_core::util::test_env::TestEnv;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn prompt() -> ApprovalPrompt {
        ApprovalPrompt {
            request_id: ApprovalRequestId::parse("sdk-approval-1").expect("request id"),
            subject: ApprovalSubject::ToolCall {
                tool: "shell".into(),
            },
            expires_in_ms: 1_000,
        }
    }

    unsafe extern "C" fn once(bytes: *const u8, len: usize) -> i32 {
        // SAFETY: the host library supplies a readable prompt buffer for this call.
        let encoded = unsafe { std::slice::from_raw_parts(bytes, len) };
        let decoded: ApprovalPrompt = serde_json::from_slice(encoded).expect("prompt JSON");
        assert_eq!(decoded, prompt());
        CALLBACK_APPROVE_ONCE
    }

    unsafe extern "C" fn invalid(_: *const u8, _: usize) -> i32 {
        99
    }

    unsafe extern "C" fn session(_: *const u8, _: usize) -> i32 {
        CALLBACK_APPROVE_SESSION
    }

    #[test]
    fn callback_results_are_bounded_and_fail_closed() {
        let _guard = TEST_LOCK.lock().expect("approval test lock");
        mvm_hostlib_set_approval_callback(Some(once));
        let allowed = answer(&prompt());
        assert_eq!(allowed.outcome, ApprovalOutcome::Approved);
        assert_eq!(allowed.scope, ApprovalScope::Once);
        assert_eq!(allowed.reason_label(), "sdk_callback");

        mvm_hostlib_set_approval_callback(Some(invalid));
        let refused = answer(&prompt());
        assert_eq!(refused.outcome, ApprovalOutcome::Denied);
        assert_eq!(refused.reason_label(), "sdk_callback_invalid");

        mvm_hostlib_set_approval_callback(None);
        let absent = answer(&prompt());
        assert_eq!(absent.outcome, ApprovalOutcome::Denied);
        assert_eq!(absent.reason_label(), "sdk_callback_unset");
    }

    #[test]
    fn retained_server_answers_until_the_machine_is_removed() {
        let _guard = TEST_LOCK.lock().expect("approval test lock");
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let name = "sdk-approval-machine";
        let path = mvm_core::config::vm_approval_socket(name);
        std::fs::create_dir_all(path.parent().expect("socket parent")).expect("state dir");
        mvm_hostlib_set_approval_callback(Some(session));

        ensure_server(name);
        assert!(path.exists(), "the hostlib retains a per-machine broker");
        let mut stream = UnixStream::connect(&path).expect("connect broker");
        let mut encoded = serde_json::to_vec(&prompt()).expect("prompt encodes");
        encoded.push(b'\n');
        stream.write_all(&encoded).expect("write prompt");
        let mut line = String::new();
        BufReader::new(stream)
            .read_line(&mut line)
            .expect("read answer");
        let response: ApprovalAnswer = serde_json::from_str(&line).expect("answer JSON");
        assert_eq!(response.outcome, ApprovalOutcome::Approved);
        assert_eq!(response.scope, ApprovalScope::Session);

        remove_server(name);
        assert!(!path.exists(), "stop/remove drops the retained broker");
        mvm_hostlib_set_approval_callback(None);
    }
}
