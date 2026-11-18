//! Mailbox listener glue: bind the reserved mailbox vsock port and forward the
//! workload's outbox message to each host connection.
//!
//! Opt-in and launch-asserted, like telemetry: the listener binds only when
//! the kernel cmdline carries `mvm.mailbox=1`, which the host sets only for a
//! signed plan that carries a mailbox grant. Otherwise no thread starts and no
//! port is held. Vsock-only; the container tier has none.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use std::sync::{OnceLock, atomic::Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_agentd::flowmux_drive::{MAILBOX_ACK_SIGNING_KEY_FILE, RUN_MVM_DIR};
use mvm_agentd::mailbox_outbox::{
    LOCAL_OUTBOX_PATH, MAILBOX_CMDLINE_TOKEN, MAILBOX_HOLD, MAILBOX_IO_TIMEOUT, OUTBOX_PATH,
    forward_local_outbox, forward_outbox, peer_gone, wait_for_outbox,
};
use mvm_agentd::telemetry_capture::session::TimedStream;
use mvm_contract::protocol::mailbox::MAILBOX_PORT;
use mvm_core::mailbox::conversation_wire::{
    CONVERSATION_BINDING_FILE, ConversationBinding, MAX_BINDING_BYTES,
};
use mvm_core::mailbox::frame::Refusal;
use mvm_core::mailbox::reader::MailboxReaderBootBinding;
use zeroize::Zeroizing;

use crate::globals::SHUTDOWN_REQUESTED;
use crate::telemetry::cmdline_asserts;
use crate::transport::{accept_vsock, bind_vsock_listener, unix_transport_selected};

static ACK_SEED: OnceLock<Zeroizing<[u8; 32]>> = OnceLock::new();
static READER_BOOT: OnceLock<MailboxReaderBootBinding> = OnceLock::new();
static CONVERSATION_BINDING: OnceLock<ConversationBinding> = OnceLock::new();

/// Retain the root-only ACK key before PID 1 drops to the workload UID.
/// A missing or malformed key disables Receive; the existing Send path
/// remains available, and warm children never inherit reader authority.
pub(crate) fn capture_ack_key_before_privilege_drop() {
    let dir = Path::new(RUN_MVM_DIR);
    let binding = match MailboxReaderBootBinding::load(dir) {
        Ok(binding) => binding,
        Err(error) => {
            if dir
                .join(mvm_core::mailbox::reader::MAILBOX_READER_BOOT_FILE)
                .exists()
            {
                eprintln!("mvm-guest-agent: mailbox reader boot unavailable: {error}");
            }
            return;
        }
    };
    match load_ack_seed(&dir.join(MAILBOX_ACK_SIGNING_KEY_FILE), 0) {
        Ok(seed)
            if SigningKey::from_bytes(&seed).verifying_key().to_bytes()
                == binding.ack_public_key =>
        {
            if let Ok(Some(conversation)) = load_conversation_binding(dir, &binding, 0) {
                let _ = CONVERSATION_BINDING.set(conversation);
            }
            if ACK_SEED.set(seed).is_err() || READER_BOOT.set(binding).is_err() {
                eprintln!("mvm-guest-agent: mailbox ACK identity already initialized");
            }
        }
        Ok(_) | Err(_) => eprintln!("mvm-guest-agent: mailbox ACK key does not match this boot"),
    }
}

/// The workload runs under the same UID as the agent. A captured ACK key must
/// not become readable through ptrace or `/proc/<pid>/mem` after the UID drop.
pub(crate) fn protect_ack_key_after_privilege_drop()
-> Result<(), mvm_agentd::guest_mount::MountError> {
    #[cfg(target_os = "linux")]
    if ACK_SEED.get().is_some() {
        // SAFETY: prctl receives only integer arguments and affects this process.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(mvm_agentd::guest_mount::MountError::InvalidConfig(format!(
                "protect mailbox ACK key after privilege drop: {}",
                io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

fn load_conversation_binding(
    dir: &Path,
    boot: &MailboxReaderBootBinding,
    owner_uid: u32,
) -> io::Result<Option<ConversationBinding>> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(dir.join(CONVERSATION_BINDING_FILE))
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != owner_uid
        || meta.mode() & 0o022 != 0
        || meta.len() > MAX_BINDING_BYTES as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid mailbox binding",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BINDING_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BINDING_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized mailbox binding",
        ));
    }
    let binding: ConversationBinding = serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid mailbox binding"))?;
    if binding.check_reader(boot).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "foreign mailbox binding",
        ));
    }
    Ok(Some(binding))
}

fn load_ack_seed(path: &Path, owner_uid: u32) -> io::Result<Zeroizing<[u8; 32]>> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.len() != 32
        || meta.nlink() != 1
        || meta.uid() != owner_uid
        || meta.permissions().mode() & 0o777 != 0o400
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "mailbox ACK key is not root-only",
        ));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    file.read_exact(seed.as_mut())?;
    Ok(seed)
}

pub(crate) struct MailboxDeadline<'a, S> {
    stream: &'a mut S,
    until: Option<Instant>,
    cancellation: Option<RawFd>,
}

impl<'a, S> MailboxDeadline<'a, S> {
    pub(crate) fn new(stream: &'a mut S) -> Self {
        Self {
            stream,
            until: None,
            cancellation: None,
        }
    }

    pub(crate) fn with_deadline(stream: &'a mut S, until: Instant) -> Self {
        Self {
            stream,
            until: Some(until),
            cancellation: None,
        }
    }

    pub(crate) fn for_conversation(
        stream: &'a mut S,
        caller: Instant,
        cancellation: RawFd,
    ) -> Self {
        Self {
            stream,
            until: Some(caller.min(Instant::now() + MAILBOX_IO_TIMEOUT)),
            cancellation: Some(cancellation),
        }
    }

    /// Called only after the destination's signed reader enrollment is verified.
    pub(crate) fn authorize_wait(&mut self, until: Instant) {
        self.until = Some(until);
    }

    fn remaining(&mut self) -> io::Result<Duration> {
        let until = *self
            .until
            .get_or_insert_with(|| Instant::now() + MAILBOX_IO_TIMEOUT);
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "mailbox I/O deadline",
            ))
        } else {
            Ok(remaining)
        }
    }
}

impl<S: AsRawFd> AsRawFd for MailboxDeadline<'_, S> {
    fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }
}

impl<S: AsRawFd> Read for MailboxDeadline<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let millis = self.remaining()?.as_millis().max(1);
            let millis = libc::c_int::try_from(millis).unwrap_or(libc::c_int::MAX);
            let fd = self.stream.as_raw_fd();
            let mut ready = [
                libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.cancellation.unwrap_or(-1),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // SAFETY: both descriptors are borrowed from live sockets; -1 is ignored.
            let polled = unsafe { libc::poll(ready.as_mut_ptr(), 2, millis) };
            if polled == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "mailbox read timeout",
                ));
            }
            if polled < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready[1].revents != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "mailbox caller disconnected",
                ));
            }
            // SAFETY: `fd` is live and `buf` is writable for its exact length.
            let received =
                unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
            if received >= 0 {
                return Ok(received as usize);
            }
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error);
        }
    }
}

impl<S: TimedStream> Write for MailboxDeadline<'_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let write_deadline = Instant::now() + MAILBOX_IO_TIMEOUT;
        loop {
            let remaining = self
                .remaining()?
                .min(write_deadline.saturating_duration_since(Instant::now()));
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "mailbox write timeout",
                ));
            }
            match self.stream.write_now(buf) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.stream.wait_writable(remaining)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}

/// Spawn the mailbox listener on a boot that asserts one. Called after PID-1
/// activation; a bind failure is logged and abandoned, never boot-fatal.
pub(crate) fn init_mailbox() {
    let asserted = std::fs::read_to_string("/proc/cmdline")
        .map(|cmdline| cmdline_asserts(&cmdline, MAILBOX_CMDLINE_TOKEN))
        .unwrap_or(false);
    if !asserted || unix_transport_selected() {
        return;
    }
    let reader_boot = READER_BOOT.get().cloned();
    let ack_seed = ACK_SEED.get();
    let _ =
        mvm_agentd::detached::spawn_named("mailbox-listener", move || {
            match bind_vsock_listener(MAILBOX_PORT) {
                Ok(fd) => {
                    let reader = match (reader_boot.clone(), ack_seed) {
                        (Some(binding), Some(seed)) => crate::mailbox_reader::start(
                            binding,
                            seed,
                            CONVERSATION_BINDING.get().cloned(),
                        ),
                        _ => None,
                    };
                    accept_loop(fd, reader, reader_boot);
                }
                Err(e) => eprintln!(
                    "mvm-guest-agent: mailbox listener bind failed (port {MAILBOX_PORT}): {e}"
                ),
            }
        });
}

/// The host re-dials an idle guest forever, so only the first few refusals
/// and then one in a hundred are logged.
fn logs_refusal(refused: u32) -> bool {
    refused < 3 || refused.is_multiple_of(100)
}

/// One host connection at a time, each answered from the outbox.
fn accept_loop(
    listener_fd: RawFd,
    reader: Option<std::sync::mpsc::Receiver<crate::mailbox_reader::PendingReader>>,
    reader_boot: Option<MailboxReaderBootBinding>,
) {
    let mut refused = 0u32;
    while !SHUTDOWN_REQUESTED.load(Ordering::Acquire) {
        let Some(cfd) = accept_vsock(listener_fd, "mailbox") else {
            continue;
        };
        // SAFETY: `cfd` is the just-accepted connection fd, owned here and
        // closed on drop.
        let mut stream = unsafe { std::fs::File::from_raw_fd(cfd) };
        if let Err(error) = stream.set_timeouts(MAILBOX_IO_TIMEOUT, MAILBOX_IO_TIMEOUT) {
            eprintln!("mvm-guest-agent: mailbox connection has no bounded I/O: {error}");
            continue;
        }
        let result = wait_for_operation(
            &mut stream,
            reader.as_ref(),
            reader_boot.as_ref(),
            CONVERSATION_BINDING.get(),
            Path::new(LOCAL_OUTBOX_PATH),
            Path::new(OUTBOX_PATH),
        );
        match result {
            Ok(()) | Err(Refusal::Unavailable) => {}
            Err(refusal) => {
                if logs_refusal(refused) {
                    eprintln!("mvm-guest-agent: mailbox frame not delivered: {refusal}");
                }
                refused = refused.saturating_add(1);
            }
        }
    }
}

fn wait_for_operation(
    stream: &mut (impl Read + Write + AsRawFd),
    reader: Option<&std::sync::mpsc::Receiver<crate::mailbox_reader::PendingReader>>,
    reader_boot: Option<&MailboxReaderBootBinding>,
    conversation: Option<&ConversationBinding>,
    local_outbox: &Path,
    outbox: &Path,
) -> Result<(), Refusal> {
    let until = Instant::now() + MAILBOX_HOLD;
    loop {
        // A local-durable request cannot be downgraded to the older unit
        // verdict even when both requests share the guest mailbox port.
        if conversation.is_none()
            && local_outbox.exists()
            && let Some(binding) = reader_boot
        {
            let authority =
                VerifyingKey::from_bytes(&binding.authority_key).map_err(|_| Refusal::Malformed)?;
            return forward_local_outbox(
                &mut MailboxDeadline::new(stream),
                local_outbox,
                &authority,
                binding.mailbox,
                binding.execution_epoch,
            )
            .map(|_| ());
        }
        // A pending Send gets the existing port before reader traffic.
        if conversation.is_none()
            && (outbox.is_file()
                || wait_for_outbox(outbox, Duration::ZERO, Duration::ZERO, || false))
        {
            return forward_outbox(&mut MailboxDeadline::new(stream), outbox);
        }
        if conversation.is_none() && local_outbox.exists() {
            return Err(Refusal::Unavailable);
        }
        if let Some(Ok(pending)) = reader.map(std::sync::mpsc::Receiver::try_recv) {
            return crate::mailbox_reader::exchange(stream, pending);
        }
        if peer_gone(stream.as_raw_fd())
            || SHUTDOWN_REQUESTED.load(Ordering::Acquire)
            || Instant::now() >= until
        {
            return Err(Refusal::Unavailable);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::mailbox::frame::OutboxMessage;

    fn stage_pending_outbox(path: &Path, message: &OutboxMessage) {
        // These tests exercise the guest port, not a concurrent workload
        // writer. Stage immutable bytes without competing for the writer's
        // directory lock during the forwarding assertion.
        mvm_core::util::atomic_io::atomic_write_new(path, &message.encode())
            .expect("stage pending mailbox request");
        mvm_core::util::atomic_io::sync_dir(path.parent().expect("outbox parent"))
            .expect("sync pending mailbox request");
    }

    #[test]
    fn projected_conversation_loads_with_the_exact_boot_and_enforces_owner_and_mode() {
        use mvm_contract::protocol::mailbox::{
            AuthorizationDomainId, ExecutionEpoch, MailboxAddress, MailboxGrant, MailboxId,
            PrincipalId, TenantId,
        };
        use mvm_core::mailbox::conversation_wire::ConversationTarget;
        use std::os::unix::fs::PermissionsExt as _;
        let drive = tempfile::tempdir().unwrap();
        let run = tempfile::tempdir().unwrap();
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.mailbox = Some(MailboxGrant {
            mailbox: MailboxId::from_bytes([11; 32]),
            authority_key: SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes(),
            epoch: ExecutionEpoch::new(plan.execution_epoch).unwrap(),
            report: None,
            retention: None,
            service_blind: None,
        });
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        let boot = MailboxReaderBootBinding::mint(
            &plan,
            SigningKey::from_bytes(&[13; 32]).verifying_key(),
            SigningKey::from_bytes(&[14; 32]).verifying_key().to_bytes(),
        )
        .unwrap();
        boot.persist(run.path()).unwrap();
        let projection = ConversationTarget {
            address: MailboxAddress {
                tenant: TenantId::from_bytes([15; 32]),
                authorization_domain: AuthorizationDomainId::from_bytes([16; 32]),
                mailbox: boot.mailbox,
                recipient: PrincipalId::from_bytes([17; 32]),
            },
            policy_epoch: 1,
        }
        .bind(&boot)
        .unwrap();
        std::fs::write(
            drive.path().join(CONVERSATION_BINDING_FILE),
            serde_json::to_vec(&projection).unwrap(),
        )
        .unwrap();
        mvm_agentd::conversation_identity::install_from_drive(drive.path(), run.path()).unwrap();
        // SAFETY: geteuid has no arguments and cannot fail.
        let fixture_owner = unsafe { libc::geteuid() };
        assert_eq!(
            load_conversation_binding(run.path(), &boot, fixture_owner).unwrap(),
            Some(projection)
        );
        assert!(
            load_conversation_binding(run.path(), &boot, fixture_owner.wrapping_add(1)).is_err()
        );
        let mut other_boot = boot.clone();
        other_boot.boot = mvm_contract::protocol::mailbox::BootId::from_bytes([18; 32]);
        assert!(load_conversation_binding(run.path(), &other_boot, fixture_owner).is_err());
        std::fs::set_permissions(
            run.path().join(CONVERSATION_BINDING_FILE),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(load_conversation_binding(run.path(), &boot, fixture_owner).is_err());
    }

    #[test]
    fn an_idle_guest_logs_a_bounded_number_of_refusals() {
        assert_eq!((0..1000).filter(|&n| logs_refusal(n)).count(), 3 + 10 - 1);
    }

    #[test]
    fn only_the_exact_token_asserts_a_mailbox() {
        assert!(cmdline_asserts(
            "console=ttyS0 mvm.mailbox=1",
            MAILBOX_CMDLINE_TOKEN
        ));
        assert!(!cmdline_asserts("mvm.mailbox=0", MAILBOX_CMDLINE_TOKEN));
        assert!(!cmdline_asserts("xmvm.mailbox=1", MAILBOX_CMDLINE_TOKEN));
        assert!(!cmdline_asserts("console=ttyS0", MAILBOX_CMDLINE_TOKEN));
    }

    #[test]
    fn a_mailbox_deadline_refuses_more_io_after_it_expires() {
        let (mut stream, _peer) = std::os::unix::net::UnixStream::pair().expect("socket");
        let mut expired = MailboxDeadline {
            stream: &mut stream,
            until: Some(Instant::now() - Duration::from_millis(1)),
            cancellation: None,
        };
        assert_eq!(
            expired.read(&mut [0u8; 1]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            expired.write(b"pending").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn a_silent_host_cannot_keep_the_guest_reader_blocked() {
        let (mut stream, _silent_peer) = std::os::unix::net::UnixStream::pair().expect("socket");
        let mut bounded = MailboxDeadline {
            stream: &mut stream,
            until: Some(Instant::now() + Duration::from_millis(25)),
            cancellation: None,
        };
        assert_eq!(
            bounded.read(&mut [0u8; 1]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn authorized_wait_replaces_only_the_handshake_read_deadline_and_cancels_on_disconnect() {
        let (mut stream, mut host) = std::os::unix::net::UnixStream::pair().unwrap();
        let (caller, client) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut bounded = MailboxDeadline::for_conversation(
            &mut stream,
            Instant::now() + Duration::from_secs(60),
            caller.as_raw_fd(),
        );
        bounded.until = Some(Instant::now() - Duration::from_millis(1));
        bounded.authorize_wait(Instant::now() + Duration::from_secs(60));
        host.write_all(b"x").unwrap();
        assert_eq!(bounded.read(&mut [0]).unwrap(), 1);
        drop(client);
        assert_eq!(
            bounded.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    #[test]
    fn a_pending_send_still_uses_the_existing_port_when_receive_is_enabled() {
        use mvm_contract::protocol::mailbox::PrincipalId;
        let dir = tempfile::tempdir().unwrap();
        let outbox = dir.path().join("outbox");
        let local_outbox = dir.path().join("outbox-local");
        stage_pending_outbox(
            &outbox,
            &OutboxMessage::new(PrincipalId::from_bytes([0; 32]), b"hello".to_vec()),
        );
        stage_pending_outbox(
            &local_outbox,
            &OutboxMessage::new(PrincipalId::from_bytes([0; 32]), b"local".to_vec()),
        );
        let (mut guest, mut host) = std::os::unix::net::UnixStream::pair().unwrap();
        let (_sender, reader) = std::sync::mpsc::sync_channel(1);
        let peer = std::thread::spawn(move || {
            let mut len = [0; 4];
            host.read_exact(&mut len).unwrap();
            let mut body = vec![0; u32::from_be_bytes(len) as usize];
            host.read_exact(&mut body).unwrap();
            assert!(!mvm_core::mailbox::reader_wire::is_reader_frame(&body));
            assert_eq!(OutboxMessage::decode(&body).unwrap().body, b"hello");
            host.write_all(&serde_json::to_vec(&Ok::<(), Refusal>(())).unwrap())
                .unwrap();
        });
        wait_for_operation(
            &mut guest,
            Some(&reader),
            None,
            None,
            &local_outbox,
            &outbox,
        )
        .unwrap();
        peer.join().unwrap();
        assert!(!outbox.exists(), "accepted Send is removed as before");
        assert!(
            local_outbox.exists(),
            "missing boot authority cannot downgrade a local request"
        );
    }

    #[test]
    fn local_send_requires_boot_authority_and_signed_acceptance() {
        use ed25519_dalek::SigningKey;
        use mvm_contract::protocol::mailbox::{
            AuthorizationDomainId, BootId, DeliveryId, DeliveryOutcome, DestinationReceipt,
            ExecutionEpoch, MailboxAddress, MailboxId, PrincipalId, ProtocolVersion,
            SignatureAlgorithm, TenantId,
        };
        use mvm_core::mailbox::sign_receipt;

        let dir = tempfile::tempdir().expect("outbox root");
        let local = dir.path().join("outbox-local");
        let legacy = dir.path().join("outbox");
        let operation = OutboxMessage::new(PrincipalId::from_bytes([0; 32]), b"report".to_vec());
        stage_pending_outbox(&local, &operation);
        let (mut guest, _host) = std::os::unix::net::UnixStream::pair().expect("socket");
        assert_eq!(
            wait_for_operation(&mut guest, None, None, None, &local, &legacy),
            Err(Refusal::Unavailable)
        );
        assert!(local.exists(), "no boot authority means no acceptance");
        drop(guest);

        let signer = SigningKey::from_bytes(&[51; 32]);
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();
        let boot = MailboxReaderBootBinding {
            plan_id: plan.plan_id,
            plan_nonce: plan.nonce,
            mailbox: MailboxId::from_bytes([52; 32]),
            authority_key: signer.verifying_key().to_bytes(),
            execution_epoch: ExecutionEpoch::new(1).expect("epoch"),
            boot: BootId::from_bytes([53; 32]),
            guest_identity_key: [54; 32],
            ack_public_key: [55; 32],
        };
        let (mut guest, mut host) = std::os::unix::net::UnixStream::pair().expect("socket");
        let responder = std::thread::spawn(move || {
            let mut length = [0; 4];
            host.read_exact(&mut length).expect("frame length");
            let mut frame = vec![0; u32::from_be_bytes(length) as usize];
            host.read_exact(&mut frame).expect("outbox frame");
            let sent = OutboxMessage::decode(&frame).expect("operation");
            let signed = sign_receipt(
                DestinationReceipt {
                    protocol_version: ProtocolVersion::V2,
                    signature_algorithm: SignatureAlgorithm::ED25519,
                    delivery_id: DeliveryId::from_bytes([56; 32]),
                    message_id: sent.message_id,
                    address: MailboxAddress {
                        tenant: TenantId::from_bytes([57; 32]),
                        authorization_domain: AuthorizationDomainId::from_bytes([58; 32]),
                        mailbox: MailboxId::from_bytes([52; 32]),
                        recipient: PrincipalId::from_bytes([59; 32]),
                    },
                    execution_epoch: ExecutionEpoch::new(1).expect("epoch"),
                    outcome: DeliveryOutcome::AcceptedLocalDurable,
                    observed_at_unix_ms: 1_500,
                    ciphertext_commitment: [60; 32],
                },
                &signer,
            )
            .expect("destination signs");
            host.write_all(&serde_json::to_vec(&Ok::<_, Refusal>(signed)).expect("receipt wire"))
                .expect("reply");
        });
        wait_for_operation(&mut guest, None, Some(&boot), None, &local, &legacy)
            .expect("boot-pinned signed acceptance");
        responder.join().expect("host reply");
        assert!(!local.exists(), "verified V2 receipt closes pending send");
    }

    #[test]
    fn ack_seed_loader_requires_exact_private_regular_file() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let dir = tempfile::tempdir().unwrap();
        let uid = dir.path().metadata().unwrap().uid();
        let path = dir.path().join(MAILBOX_ACK_SIGNING_KEY_FILE);
        std::fs::write(&path, [8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(*load_ack_seed(&path, uid).unwrap(), [8; 32]);
        assert!(load_ack_seed(&path, uid.wrapping_add(1)).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_ack_seed(&path, uid).is_err());
        std::fs::write(&path, [8; 31]).unwrap();
        assert!(load_ack_seed(&path, uid).is_err());
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(dir.path().join("missing"), &path).unwrap();
        assert!(load_ack_seed(&path, uid).is_err());
    }
}
