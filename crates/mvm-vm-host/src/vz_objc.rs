//! Rust-native Vz supervisor objc2 bridge.
//!
//! Drives Apple's `Virtualization.framework` directly from Rust via the
//! `objc2` stack — the replacement for the (removed) Swift supervisor.
//! One guest per process; nothing depends on this as a library beyond the
//! sibling `mvm-vz-supervisor` `[[bin]]`.
//!
//! **Threading.** Every `VZVirtualMachine` call runs
//! on a private serial dispatch queue — the model the Swift supervisor already
//! shipped (`Supervisor.swift`), ported rather than swapped for a main-thread
//! `CFRunLoop`. The non-`Send` objc2 handles live behind that queue; a small
//! [`SerialQueue::dispatch`] bridges each queue hop to an `async` await so the
//! process main thread stays free for the control socket + vsock proxy. All
//! `unsafe` is contained in this module.
//!
//! **Scope.** This is the production VZ path — the Swift supervisor is deleted.
//! Cold boot + clean lifecycle/exit propagation; config translation
//! (cpu/memory/kernel/disks/virtio-fs/vsock-device/console/entropy/balloon/
//! platform) with a host resource-cap check; the vsock host-side proxy (per-port
//! UNIX listeners spliced to the guest); the gvproxy virtio-net attachment and
//! the in-process flow-audit `payload_tap` (claim 10); the control socket
//! (STATUS/PAUSE/RESUME/BALLOON/SAVE) and `Restore` startup mode with the
//! machine-id sidecar; and the workload-exit channel. Deferred (separate plans):
//! nested-virt `/dev/kvm`; rootfs-provider/SLIRP notes.

use std::cell::Cell;
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use anyhow::{Result, anyhow, bail};
use block2::RcBlock;
use dispatch2::{DispatchQueue, DispatchQueueAttr, DispatchRetained};
use objc2::rc::Retained;
use objc2::runtime::{Bool, NSObjectProtocol, ProtocolObject};
use objc2::{AnyThread, DefinedClass, define_class, msg_send};
use objc2_foundation::{NSArray, NSData, NSError, NSFileHandle, NSObject, NSString, NSURL};
use objc2_virtualization::{
    VZDiskImageStorageDeviceAttachment, VZFileHandleNetworkDeviceAttachment,
    VZFileHandleSerialPortAttachment, VZGenericMachineIdentifier, VZGenericPlatformConfiguration,
    VZLinuxBootLoader, VZMACAddress, VZSharedDirectory, VZSingleDirectoryShare,
    VZVirtioBlockDeviceConfiguration, VZVirtioConsoleDeviceSerialPortConfiguration,
    VZVirtioEntropyDeviceConfiguration, VZVirtioFileSystemDeviceConfiguration,
    VZVirtioNetworkDeviceConfiguration, VZVirtioSocketConnection, VZVirtioSocketDevice,
    VZVirtioSocketDeviceConfiguration, VZVirtioSocketListener, VZVirtioSocketListenerDelegate,
    VZVirtioTraditionalMemoryBalloonDevice, VZVirtioTraditionalMemoryBalloonDeviceConfiguration,
    VZVirtualMachine, VZVirtualMachineConfiguration, VZVirtualMachineDelegate,
    VZVirtualMachineState,
};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use mvm_build::vz::{NetworkConfig, StartupMode, SupervisorConfig};
use mvm_core::exit_capture::exit_file_path;
use mvm_guest::vsock::WORKLOAD_EXIT_PORT;

/// Unique per-process counter so each VM's dispatch queue gets a distinct
/// label (libdispatch keys its worker bookkeeping off the label).
static VM_COUNTER: AtomicU64 = AtomicU64::new(0);

fn mib_to_bytes(mib: u64) -> u64 {
    mib * 1024 * 1024
}

// ---------------------------------------------------------------------------
// Terminal-state channel
// ---------------------------------------------------------------------------

/// Coarse lifecycle state the supervisor blocks on. We only need to tell a
/// non-terminal transition apart from the two terminal outcomes; the full
/// `VZVirtualMachineState` is collapsed onto this.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RunState {
    /// Created but `start()` not yet observed to complete.
    Pending,
    /// Running (or any other non-terminal framework state).
    Running,
    /// Guest powered itself off cleanly (`guestDidStopVirtualMachine:`).
    Stopped,
    /// Guest stopped with an error (`virtualMachine:didStopWithError:` or a
    /// framework `Error` state). Carries the localized description.
    Errored(String),
}

/// Collapse Apple's `VZVirtualMachineState` onto [`RunState`]. Any state that
/// is not `Stopped`/`Error` is non-terminal here (`Running`), so reading the
/// authoritative property right after `start()` never races the delegate's
/// terminal push into a false positive.
fn collapse_state(s: VZVirtualMachineState) -> RunState {
    match s {
        VZVirtualMachineState::Stopped => RunState::Stopped,
        VZVirtualMachineState::Error => RunState::Errored(String::new()),
        _ => RunState::Running,
    }
}

// ---------------------------------------------------------------------------
// Serial dispatch queue (GCD ↔ tokio bridge)
// ---------------------------------------------------------------------------

/// A private serial dispatch queue. `Virtualization.framework` requires every
/// `VZVirtualMachine` operation to run on the queue the VM was created with;
/// this wraps it with an `async` dispatch that bridges the GCD callback back
/// to tokio without blocking a thread. Cloneable (the inner queue is
/// reference-counted) so each vsock-proxy task can hop onto the VM's queue.
#[derive(Clone)]
struct SerialQueue {
    inner: DispatchRetained<DispatchQueue>,
}

impl SerialQueue {
    fn new(label: &str) -> Self {
        Self {
            inner: DispatchQueue::new(label, DispatchQueueAttr::SERIAL),
        }
    }

    fn clone_inner(&self) -> DispatchRetained<DispatchQueue> {
        self.inner.clone()
    }

    /// Run `f` on the serial queue and await its result. The tokio task yields
    /// while the queue executes, so no thread is parked.
    async fn dispatch<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        self.inner.exec_async(move || {
            let _ = tx.send(f());
        });
        rx.await
            .map_err(|_| anyhow!("dispatch queue dropped before the operation completed"))
    }
}

// ---------------------------------------------------------------------------
// VM delegate (objc2 class)
// ---------------------------------------------------------------------------

/// Ivars for [`VmDelegate`]. The delegate runs exclusively on the VM's serial
/// queue, so a `Cell` (not a lock) is enough to mutate from the `&self`
/// objc callbacks.
struct VmDelegateIvars {
    state_tx: Cell<Option<watch::Sender<RunState>>>,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements; VmDelegate adds no Drop.
    #[unsafe(super(NSObject))]
    #[ivars = VmDelegateIvars]
    #[name = "MvmVzSupervisorDelegate"]
    struct VmDelegate;

    unsafe impl NSObjectProtocol for VmDelegate {}

    unsafe impl VZVirtualMachineDelegate for VmDelegate {
        /// Guest initiated a clean power-off.
        #[unsafe(method(guestDidStopVirtualMachine:))]
        fn guest_did_stop(&self, _vm: &VZVirtualMachine) {
            self.push(RunState::Stopped);
        }

        /// VM stopped due to an error; surface the localized description.
        #[unsafe(method(virtualMachine:didStopWithError:))]
        fn vm_did_stop_with_error(&self, _vm: &VZVirtualMachine, error: &NSError) {
            self.push(RunState::Errored(error.localizedDescription().to_string()));
        }
    }
);

impl VmDelegate {
    fn new(tx: watch::Sender<RunState>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(VmDelegateIvars {
            state_tx: Cell::new(Some(tx)),
        });
        unsafe { msg_send![super(this), init] }
    }

    /// Send a terminal state, keeping the sender alive for the (impossible but
    /// cheap to guard) case of a second callback.
    fn push(&self, state: RunState) {
        if let Some(tx) = self.ivars().state_tx.take() {
            let _ = tx.send(state);
            self.ivars().state_tx.set(Some(tx));
        }
    }

    fn as_protocol(&self) -> &ProtocolObject<dyn VZVirtualMachineDelegate> {
        ProtocolObject::from_ref(self)
    }
}

// ---------------------------------------------------------------------------
// Completion-handler bridge
// ---------------------------------------------------------------------------

/// Build an `RcBlock` for the framework's `(NSError*) -> void` completion
/// handlers, forwarding success/failure to a oneshot. `RcBlock` needs `Fn`, so
/// the single-use sender lives behind a `Cell`.
fn completion_block(tx: oneshot::Sender<Result<()>>) -> RcBlock<dyn Fn(*mut NSError)> {
    let tx = Cell::new(Some(tx));
    RcBlock::new(move |error: *mut NSError| {
        let result = if error.is_null() {
            Ok(())
        } else {
            // SAFETY: non-null per the check; the framework keeps the NSError
            // valid for the duration of the callback.
            Err(anyhow!("{}", ns_error_to_string(unsafe { &*error })))
        };
        if let Some(tx) = tx.take() {
            let _ = tx.send(result);
        }
    })
}

fn ns_error_to_string(error: &NSError) -> String {
    format!(
        "{} ({}:{})",
        error.localizedDescription(),
        error.domain(),
        error.code()
    )
}

fn nsurl_from_path(path: &str) -> Retained<NSURL> {
    let s = NSString::from_str(path);
    NSURL::initFileURLWithPath(NSURL::alloc(), &s)
}

// ---------------------------------------------------------------------------
// vsock byte stream (guest connection fd → AsyncFd)
// ---------------------------------------------------------------------------

/// Carries a `VZVirtioSocketConnection` across the dispatch-queue → tokio hop.
/// Non-`Send` on its own; sound because we only ever touch its fd (via `dup`),
/// which is thread-safe — the retained object just keeps the fd alive.
struct SendableConnection(Retained<VZVirtioSocketConnection>);

// SAFETY: only the fd is used after the hop; fds are thread-safe.
unsafe impl Send for SendableConnection {}

/// Keeps the objc connection alive for as long as the stream's dup'd fd is in
/// use. No objc methods are called after construction.
struct ConnectionHandle {
    _connection: Retained<VZVirtioSocketConnection>,
}

// SAFETY: held only to keep the connection retained; no objc method is called on
// it after construction. The sole cross-thread access is the `objc_release` on
// drop, which is atomic-refcount and thread-safe.
unsafe impl Send for ConnectionHandle {}
unsafe impl Sync for ConnectionHandle {}

/// A bidirectional async byte stream over a guest vsock connection. Wraps the
/// connection's (dup'd, non-blocking) fd in `AsyncFd`, so it composes with
/// `tokio::io::copy_bidirectional`. Ported idiom — the framework hands us a
/// POSIX fd on connect, which we own independently via `dup`.
struct VsockStream {
    fd: AsyncFd<OwnedFd>,
    _connection: Arc<ConnectionHandle>,
}

impl VsockStream {
    fn from_connection(connection: Retained<VZVirtioSocketConnection>) -> Result<Self> {
        // SAFETY: fileDescriptor() returns the framework-owned POSIX fd.
        let raw = unsafe { connection.fileDescriptor() };
        if raw < 0 {
            bail!("vsock connection has a closed file descriptor");
        }
        // dup so our lifetime is independent of the objc connection; VZ keeps
        // the original.
        // SAFETY: `raw` is a valid open fd from the framework.
        let dup = unsafe { libc::dup(raw) };
        if dup < 0 {
            bail!("dup vsock fd: {}", io::Error::last_os_error());
        }
        // SAFETY: `dup` is a valid fd we own; set non-blocking for AsyncFd.
        let flags = unsafe { libc::fcntl(dup, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(dup, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            // SAFETY: closing the fd we just opened.
            unsafe { libc::close(dup) };
            bail!("set O_NONBLOCK on vsock fd: {}", io::Error::last_os_error());
        }
        // SAFETY: transfer ownership of the dup'd fd to OwnedFd.
        let owned = unsafe { OwnedFd::from_raw_fd(dup) };
        Ok(Self {
            fd: AsyncFd::new(owned).map_err(|e| anyhow!("register vsock fd with tokio: {e}"))?,
            _connection: Arc::new(ConnectionHandle {
                _connection: connection,
            }),
        })
    }
}

impl AsyncRead for VsockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = match self.fd.poll_read_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let unfilled = buf.initialize_unfilled();
            let fd = self.fd.as_fd().as_raw_fd();
            // SAFETY: reading a valid fd into a sized buffer.
            let n = unsafe { libc::read(fd, unfilled.as_mut_ptr().cast(), unfilled.len()) };
            if n >= 0 {
                buf.advance(n as usize);
                return Poll::Ready(Ok(()));
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Poll::Ready(Err(err));
        }
    }
}

impl AsyncWrite for VsockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.fd.poll_write_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let fd = self.fd.as_fd().as_raw_fd();
            // SAFETY: writing a valid buffer to a valid fd.
            let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
            if n >= 0 {
                return Poll::Ready(Ok(n as usize));
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Poll::Ready(Err(err));
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let fd = self.fd.as_fd().as_raw_fd();
        // SAFETY: SHUT_WR on a valid fd; ENOTCONN is benign (already closed).
        if unsafe { libc::shutdown(fd, libc::SHUT_WR) } < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::NotConnected {
                return Poll::Ready(Err(err));
            }
        }
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// Guest→host vsock listener (workload-exit capture)
// ---------------------------------------------------------------------------

/// Ivars for [`VsockListenerDelegate`]: the channel each accepted guest
/// connection is forwarded on. Runs on the VM's queue, so a `Cell` suffices.
struct VsockListenerDelegateIvars {
    tx: Cell<Option<mpsc::UnboundedSender<SendableConnection>>>,
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements; adds no Drop.
    #[unsafe(super(NSObject))]
    #[ivars = VsockListenerDelegateIvars]
    #[name = "MvmVzExitListenerDelegate"]
    struct VsockListenerDelegate;

    unsafe impl NSObjectProtocol for VsockListenerDelegate {}

    unsafe impl VZVirtioSocketListenerDelegate for VsockListenerDelegate {
        /// Accept a guest-initiated connection and forward it for capture.
        #[unsafe(method(listener:shouldAcceptNewConnection:fromSocketDevice:))]
        fn should_accept(
            &self,
            _listener: &VZVirtioSocketListener,
            connection: &VZVirtioSocketConnection,
            _device: &VZVirtioSocketDevice,
        ) -> Bool {
            if let Some(tx) = self.ivars().tx.take() {
                // SAFETY: valid framework connection; retain it past the callback.
                let retained = unsafe {
                    Retained::retain(connection as *const _ as *mut VZVirtioSocketConnection)
                };
                if let Some(conn) = retained {
                    let _ = tx.send(SendableConnection(conn));
                    self.ivars().tx.set(Some(tx));
                    return Bool::YES;
                }
                self.ivars().tx.set(Some(tx));
            }
            Bool::NO
        }
    }
);

impl VsockListenerDelegate {
    fn new(tx: mpsc::UnboundedSender<SendableConnection>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(VsockListenerDelegateIvars {
            tx: Cell::new(Some(tx)),
        });
        unsafe { msg_send![super(this), init] }
    }

    fn as_protocol(&self) -> &ProtocolObject<dyn VZVirtioSocketListenerDelegate> {
        ProtocolObject::from_ref(self)
    }
}

/// Keeps the exit-port listener + delegate alive for the VM's lifetime. Both
/// are `!Send`; only ever touched on the VM's queue (creation) and dropped on
/// shutdown, which is what makes the `unsafe impl` sound.
struct ExitListenerHandle {
    _listener: Retained<VZVirtioSocketListener>,
    _delegate: Retained<VsockListenerDelegate>,
}

// SAFETY: held only to keep the listener + delegate retained; no objc method is
// called on them after creation (on the queue). The sole cross-thread access is
// the `objc_release` on drop, which is atomic-refcount and thread-safe.
unsafe impl Send for ExitListenerHandle {}
unsafe impl Sync for ExitListenerHandle {}

/// Capture one finished workload's exit code: read the guest's 4-byte LE i32,
/// persist it to `<vm_state_dir>/workload.exit`, store it in `slot`, then ack
/// (the guest waits for the ack before powering off — so the file + slot are
/// durably set before the VM stops). Mirrors `exit_capture::capture_once`.
async fn capture_exit<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    vm_state_dir: PathBuf,
    slot: Arc<Mutex<Option<i32>>>,
) {
    let mut buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut buf).await {
        tracing::warn!(error = %e, "exit-capture: read failed");
        return;
    }
    let code = i32::from_le_bytes(buf);
    if let Err(e) = std::fs::write(exit_file_path(&vm_state_dir), code.to_string()) {
        tracing::warn!(error = %e, "exit-capture: write workload.exit failed");
    }
    *slot.lock().expect("exit slot mutex") = Some(code);
    let _ = stream.write_all(&[1u8]).await;
    let _ = stream.flush().await;
}

/// Await the first guest connection on the exit port and capture its code. A
/// one-shot workload reports exactly once; long-running workloads never connect.
async fn run_exit_listener(
    mut rx: mpsc::UnboundedReceiver<SendableConnection>,
    vm_state_dir: PathBuf,
    slot: Arc<Mutex<Option<i32>>>,
) {
    if let Some(conn) = rx.recv().await {
        match VsockStream::from_connection(conn.0) {
            Ok(stream) => capture_exit(stream, vm_state_dir, slot).await,
            Err(e) => tracing::warn!(error = %e, "exit-capture: build stream failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// VM handle + supervisor
// ---------------------------------------------------------------------------

/// Holds the VM and its delegate together. Both are non-`Send`; the `Arc` is
/// moved/cloned across the tokio runtime, but the objects are only ever
/// *operated on* from inside [`SerialQueue::dispatch`] closures — which is what
/// makes the `unsafe impl Send`/`Sync` sound.
struct VmHandle {
    vm: Retained<VZVirtualMachine>,
    _delegate: Retained<VmDelegate>,
}

// SAFETY: VZ method calls on these objects only ever run inside
// `SerialQueue::dispatch` closures, i.e. on the queue VZ binds the VM to. The
// only access off that queue is the implicit `objc_release` when the last `Arc`
// drops on a tokio thread — atomic-refcount and queue-agnostic (`VZVirtualMachine`
// dealloc has no documented queue affinity). No VZ method is dispatched off-queue.
unsafe impl Send for VmHandle {}
unsafe impl Sync for VmHandle {}

/// What the create closure produces on the VM's queue: the VM handle, the
/// machine-identifier bytes (SAVE sidecar), and the pending flow-audit bridge
/// half (when the network is flow-audited).
type CreatedVm = (Arc<VmHandle>, Option<Vec<u8>>, Option<PendingBridge>);

/// Cheaply-clonable connector to a running VM. Each vsock-proxy / control-socket
/// task holds one so it can drive the VM (`connectToPort`, pause/resume/save, …)
/// on the VM's serial queue without sharing the whole supervisor.
#[derive(Clone)]
struct VmConn {
    queue: SerialQueue,
    handle: Arc<VmHandle>,
    /// Configured guest memory in bytes — the balloon target is derived from it
    /// (`target = total − inflate`).
    mem_total_bytes: u64,
    /// `VZGenericMachineIdentifier.dataRepresentation` — SAVE writes it to the
    /// `<snapshot>.machine-id` sidecar so RESTORE preserves guest identity.
    machine_id: Option<Arc<Vec<u8>>>,
}

impl VmConn {
    /// Dial the guest's vsock `port`, returning a byte stream. The
    /// `connectToPort` call runs on the VM's queue; the `AsyncFd` stream is
    /// built back on the tokio thread (it needs the reactor).
    async fn connect(&self, port: u32) -> Result<VsockStream> {
        let (tx, rx) = oneshot::channel::<Result<SendableConnection>>();
        let tx = Cell::new(Some(tx));
        let handle = Arc::clone(&self.handle);
        self.queue
            .dispatch(move || {
                // SAFETY: socketDevices() is a queue-bound property accessor.
                let devices = unsafe { handle.vm.socketDevices() };
                let device = devices
                    .to_vec()
                    .into_iter()
                    .next()
                    .and_then(|d| Retained::downcast::<VZVirtioSocketDevice>(d).ok());
                let Some(device) = device else {
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(Err(anyhow!("VM has no virtio-socket device")));
                    }
                    return;
                };
                let block = RcBlock::new(
                    move |conn: *mut VZVirtioSocketConnection, err: *mut NSError| {
                        let result = if !err.is_null() {
                            // SAFETY: non-null per the check; valid in-callback.
                            Err(anyhow!("{}", ns_error_to_string(unsafe { &*err })))
                        } else if conn.is_null() {
                            Err(anyhow!("vsock connect returned a null connection"))
                        } else {
                            // SAFETY: non-null framework connection; retain it.
                            unsafe { Retained::retain(conn) }
                                .map(SendableConnection)
                                .ok_or_else(|| anyhow!("failed to retain vsock connection"))
                        };
                        if let Some(tx) = tx.take() {
                            let _ = tx.send(result);
                        }
                    },
                );
                // SAFETY: connectToPort_completionHandler must run on the queue.
                unsafe { device.connectToPort_completionHandler(port, &block) };
            })
            .await?;
        let conn = rx
            .await
            .map_err(|_| anyhow!("vsock connect completion handler was never called"))??;
        VsockStream::from_connection(conn.0)
    }

    /// Control verb: pause the running guest (`pauseWithCompletionHandler`).
    async fn pause(&self) -> Result<()> {
        let handle = Arc::clone(&self.handle);
        let (tx, rx) = oneshot::channel();
        self.queue
            .dispatch(move || {
                let block = completion_block(tx);
                // SAFETY: pauseWithCompletionHandler must run on the VM's queue.
                unsafe { handle.vm.pauseWithCompletionHandler(&block) };
            })
            .await?;
        rx.await
            .map_err(|_| anyhow!("pause completion handler was never called"))?
    }

    /// Control verb: resume a paused guest (`resumeWithCompletionHandler`).
    async fn resume(&self) -> Result<()> {
        let handle = Arc::clone(&self.handle);
        let (tx, rx) = oneshot::channel();
        self.queue
            .dispatch(move || {
                let block = completion_block(tx);
                // SAFETY: resumeWithCompletionHandler must run on the VM's queue.
                unsafe { handle.vm.resumeWithCompletionHandler(&block) };
            })
            .await?;
        rx.await
            .map_err(|_| anyhow!("resume completion handler was never called"))?
    }

    /// Control verb: the guest's current lifecycle state as the word the
    /// control protocol reports (`OK <word>`).
    async fn status_word(&self) -> Result<&'static str> {
        let handle = Arc::clone(&self.handle);
        self.queue
            // SAFETY: `state` is a queue-bound property accessor.
            .dispatch(move || status_word(unsafe { handle.vm.state() }))
            .await
    }

    /// Control verb `BALLOON <mib>`: inflate the balloon by `inflate_mib` MiB,
    /// i.e. set the guest's available memory to `total − inflate`. Matches the
    /// host client contract (`balloon_set_target(target_inflate_mib)`) and the
    /// Swift supervisor. Apple rounds + clamps; the in-guest change is async.
    async fn set_balloon_inflate(&self, inflate_mib: u64) -> Result<()> {
        let total = self.mem_total_bytes;
        let inflate = inflate_mib.saturating_mul(1024 * 1024);
        if inflate > total {
            bail!(
                "BALLOON {inflate_mib} MiB exceeds VM memory {} MiB",
                total / (1024 * 1024)
            );
        }
        let target = total - inflate;
        let handle = Arc::clone(&self.handle);
        self.queue
            .dispatch(move || -> Result<()> {
                // SAFETY: memoryBalloonDevices is a queue-bound property accessor.
                let devices = unsafe { handle.vm.memoryBalloonDevices() };
                let device = devices
                    .to_vec()
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow!("no traditional memory balloon device attached"))?;
                let traditional =
                    Retained::downcast::<VZVirtioTraditionalMemoryBalloonDevice>(device)
                        .map_err(|_| anyhow!("balloon device is not a traditional balloon"))?;
                // SAFETY: setTargetVirtualMachineMemorySize is a plain property setter.
                unsafe { traditional.setTargetVirtualMachineMemorySize(target) };
                Ok(())
            })
            .await?
    }

    /// Control verb `SAVE <path>` (macOS 14+): checkpoint the guest to `path`,
    /// then best-effort write the `<path>.machine-id` sidecar (mode 0600) so
    /// RESTORE preserves guest identity.
    ///
    /// `saveMachineStateToURL` requires a paused VM (an unpaused one errors with
    /// `VZErrorDomain:3`), but the host sends `SAVE` on a running guest — so we
    /// pause here, save, then resume: a consistent live checkpoint in
    /// `pause → save` order. If the guest is already
    /// paused (a caller pre-paused), we save in place and leave it paused.
    async fn save(&self, path: &str) -> Result<()> {
        // VZ refuses to overwrite an existing save file.
        let _ = std::fs::remove_file(path);

        let resume_after = self.status_word().await? == "running";
        if resume_after {
            self.pause()
                .await
                .map_err(|e| anyhow!("pause before save: {e}"))?;
        }
        let saved = self.save_machine_state(path).await;
        // Resume even if the save failed, so a failure never strands the guest
        // suspended. A resume failure is logged, not fatal — the snapshot (if it
        // succeeded) is still the deliverable.
        if resume_after && let Err(e) = self.resume().await {
            tracing::warn!(error = %e, "resume after save failed; guest left paused");
        }
        saved?;

        if let Some(bytes) = &self.machine_id {
            let sidecar = format!("{path}.machine-id");
            if let Err(e) = write_machine_id_sidecar(&sidecar, bytes) {
                tracing::warn!(error = %e, "SAVE machine-id sidecar write failed (RESTORE will use a fresh identifier)");
            }
        }
        Ok(())
    }

    /// The raw `saveMachineStateToURL` call — the VM must already be paused (see
    /// [`save`](Self::save), which handles the pause/resume).
    async fn save_machine_state(&self, path: &str) -> Result<()> {
        let owned_path = path.to_string();
        let handle = Arc::clone(&self.handle);
        let (tx, rx) = oneshot::channel();
        self.queue
            .dispatch(move || {
                // NSURL is !Send — build it on the queue.
                let url = nsurl_from_path(&owned_path);
                let block = completion_block(tx);
                // SAFETY: saveMachineStateToURL_completionHandler runs on the queue.
                unsafe {
                    handle
                        .vm
                        .saveMachineStateToURL_completionHandler(&url, &block)
                };
            })
            .await?;
        rx.await
            .map_err(|_| anyhow!("save completion handler was never called"))?
    }
}

/// Write the machine-id sidecar atomically at mode 0600 (identity bytes bind to
/// the guest, so keep them owner-only).
fn write_machine_id_sidecar(path: &str, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, bytes).map_err(|e| anyhow!("write {path}: {e}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| anyhow!("chmod 0600 {path}: {e}"))
}

/// Map Apple's `VZVirtualMachineState` onto the control protocol's `STATUS`
/// word (matches the Swift `ControlSocket` responses).
fn status_word(s: VZVirtualMachineState) -> &'static str {
    match s {
        VZVirtualMachineState::Stopped => "stopped",
        VZVirtualMachineState::Starting => "starting",
        VZVirtualMachineState::Running => "running",
        VZVirtualMachineState::Pausing => "pausing",
        VZVirtualMachineState::Paused => "paused",
        VZVirtualMachineState::Resuming => "resuming",
        VZVirtualMachineState::Stopping => "stopping",
        VZVirtualMachineState::Saving => "saving",
        VZVirtualMachineState::Restoring => "restoring",
        VZVirtualMachineState::Error => "error",
        _ => "unknown",
    }
}

/// One Vz guest, driven from Rust. Created with [`VzSupervisor::boot`], which
/// builds the config, instantiates the VM on its queue, installs the delegate,
/// binds the vsock host proxy, and cold-boots it.
pub struct VzSupervisor {
    handle: Arc<VmHandle>,
    queue: SerialQueue,
    state_tx: watch::Sender<RunState>,
    state_rx: watch::Receiver<RunState>,
    /// Per-port vsock proxy accept loops; aborted on [`shutdown`](Self::shutdown).
    vsock_tasks: Vec<JoinHandle<()>>,
    /// Bound `vsock-<port>.sock` paths, unlinked on shutdown.
    vsock_paths: Vec<PathBuf>,
    /// Control-socket accept loop (PAUSE/RESUME/STATUS/BALLOON/SAVE), if bound.
    control_task: Option<JoinHandle<()>>,
    /// Bound `control.sock` path, unlinked on shutdown.
    control_path: Option<PathBuf>,
    /// Configured guest memory in bytes (balloon target derivation).
    mem_total_bytes: u64,
    /// Machine-identifier bytes for the SAVE sidecar (`None` if unavailable).
    machine_id: Option<Arc<Vec<u8>>>,
    /// Captured one-shot workload exit code, if the guest reported one over the
    /// exit port. `wait()` returns it in preference to the VZ clean/error code.
    captured_exit: Arc<Mutex<Option<i32>>>,
    /// Workload-exit listener accept loop, aborted on shutdown.
    exit_task: Option<JoinHandle<()>>,
    /// Retains the exit-port `VZVirtioSocketListener` for the VM's lifetime.
    _exit_listener: Option<ExitListenerHandle>,
    /// Host-listen (guest→host) proxy accept loops for the egress-substitution
    /// channel; aborted on [`shutdown`](Self::shutdown).
    host_listen_tasks: Vec<JoinHandle<()>>,
    /// Retains each host-listen port's `VZVirtioSocketListener` for the VM's
    /// lifetime (the framework drops accepts once the listener is released).
    _host_listen_listeners: Vec<ExitListenerHandle>,
    /// In-process flow-audited gvproxy bridge thread.
    /// Held for its lifetime; process exit reaps it. `None` when no audit
    /// substrate (direct gvproxy attach) or no network.
    _bridge: Option<std::thread::JoinHandle<()>>,
}

impl VzSupervisor {
    /// Build the configuration, create the VM on a fresh serial queue, install
    /// the delegate, and cold-boot. Returns once `start()` has completed (the
    /// guest is running) — call [`wait`](Self::wait) to block until it stops.
    pub async fn boot(config: &SupervisorConfig) -> Result<Self> {
        let label = format!(
            "com.mvm.vz-supervisor.{}",
            VM_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let queue = SerialQueue::new(&label);
        let (state_tx, state_rx) = watch::channel(RunState::Pending);
        let delegate_tx = state_tx.clone();

        // Captured before `config` is moved into the create closure.
        let vsock_dir = config.vsock.socket_dir.clone();
        // The exit port is guest→host (a VZVirtioSocketListener), so it is NOT a
        // host→guest proxy port — keep it out of the proxy set.
        let proxy_ports: Vec<u32> = config
            .vsock
            .ports
            .iter()
            .copied()
            .filter(|&p| p != WORKLOAD_EXIT_PORT)
            .collect();
        let capture_exit = config.vsock.ports.contains(&WORKLOAD_EXIT_PORT);
        // Guest→host host-listen ports (egress substitution): the supervisor
        // installs a VZVirtioSocketListener per port and splices each accepted
        // guest connection to the per-VM UDS the endpoint binds.
        let host_listen_ports = config.vsock.host_listen_ports.clone();
        let vm_state_dir = config.vm_state_dir.clone();
        let control_path = config.control_socket_path.clone();
        let mem_total_bytes = mib_to_bytes(config.resources.memory_mib);
        let startup_mode = config.startup_mode.clone();

        // Retained for the flow-audited bridge spawn after the VM is created.
        let bridge_config = config.clone();
        let config = config.clone();
        let queue_inner = queue.clone_inner();
        // The create closure returns the VM handle, the machine-identifier bytes
        // (for the SAVE sidecar), and the pending bridge socketpair half (when
        // flow-audited) — all produced on the queue.
        let (handle, machine_id, pending_bridge) = queue
            .dispatch(move || -> Result<CreatedVm> {
                let (vz_config, machine_id, pending_bridge) = build_vz_config(&config)?;
                // SAFETY: initWithConfiguration_queue binds the VM to this
                // queue; we are executing on it.
                let vm = unsafe {
                    VZVirtualMachine::initWithConfiguration_queue(
                        VZVirtualMachine::alloc(),
                        &vz_config,
                        &queue_inner,
                    )
                };
                let delegate = VmDelegate::new(delegate_tx);
                // SAFETY: setDelegate must run on the VM's queue (we are on it).
                unsafe { vm.setDelegate(Some(delegate.as_protocol())) };
                Ok((
                    Arc::new(VmHandle {
                        vm,
                        _delegate: delegate,
                    }),
                    machine_id,
                    pending_bridge,
                ))
            })
            .await??;

        let mut this = Self {
            handle,
            queue,
            state_tx,
            state_rx,
            vsock_tasks: Vec::new(),
            vsock_paths: Vec::new(),
            control_task: None,
            control_path: None,
            mem_total_bytes,
            machine_id: machine_id.map(Arc::new),
            captured_exit: Arc::new(Mutex::new(None)),
            exit_task: None,
            _exit_listener: None,
            host_listen_tasks: Vec::new(),
            _host_listen_listeners: Vec::new(),
            _bridge: None,
        };
        // Bind the host-side vsock proxy + control socket + workload-exit
        // listener before start, so a client (mvmctl / mvmd) can reach the guest
        // agent and drive lifecycle verbs — and a finished one-shot workload can
        // report its exit code — the moment it boots. The Swift supervisor's
        // ordering.
        this.start_vsock_proxy(&vsock_dir, &proxy_ports)?;
        if let Some(path) = control_path {
            this.start_control_socket(&path)?;
        }
        if capture_exit {
            this.start_exit_listener(&vm_state_dir).await?;
        }
        // Host-listen (guest→host) proxy for the egress-substitution channel.
        // The listener must be installed before the guest can dial it, so this
        // runs before start()/restore_and_resume().
        if !host_listen_ports.is_empty() {
            this.start_host_listen_proxy(&vsock_dir, &host_listen_ports)
                .await?;
        }
        // Flow-audited networking: spawn the in-process gvproxy bridge before
        // start so it is splicing before the guest brings its NIC up. Fail-closed
        // — a malformed audit substrate refuses the boot (the bridge guards
        // claim-10 egress; we never run a substrate-tagged guest unaudited).
        if let Some(pending) = pending_bridge {
            this._bridge = Some(spawn_payload_tap(&bridge_config, pending)?);
        }
        // Boot a fresh guest, or restore from a saved state + resume.
        match startup_mode {
            StartupMode::Boot => this.start().await?,
            StartupMode::Restore { snapshot_path, .. } => {
                this.restore_and_resume(&snapshot_path).await?
            }
        }
        Ok(this)
    }

    fn connector(&self) -> VmConn {
        VmConn {
            queue: self.queue.clone(),
            handle: Arc::clone(&self.handle),
            mem_total_bytes: self.mem_total_bytes,
            machine_id: self.machine_id.clone(),
        }
    }

    /// Restore a saved guest state (macOS 14+) and resume it. The two calls run
    /// on the VM's queue; restore leaves the VM paused, resume unsticks it.
    async fn restore_and_resume(&self, snapshot_path: &str) -> Result<()> {
        let owned = snapshot_path.to_string();
        let handle = Arc::clone(&self.handle);
        let (tx, rx) = oneshot::channel();
        self.queue
            .dispatch(move || {
                // NSURL is !Send — build it on the queue.
                let url = nsurl_from_path(&owned);
                let block = completion_block(tx);
                // SAFETY: restoreMachineStateFromURL_completionHandler runs on the queue.
                unsafe {
                    handle
                        .vm
                        .restoreMachineStateFromURL_completionHandler(&url, &block)
                };
            })
            .await?;
        rx.await
            .map_err(|_| anyhow!("restore completion handler was never called"))??;
        self.connector().resume().await?;
        self.push_current_state().await;
        Ok(())
    }

    /// Bind one `<socket_dir>/vsock-<port>.sock` (mode 0700) UNIX listener per
    /// requested guest port and spawn an accept loop that dials the guest and
    /// splices the two. The host-dials-guest direction mvmctl's agent RPC uses.
    fn start_vsock_proxy(&mut self, socket_dir: &str, ports: &[u32]) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if ports.is_empty() {
            return Ok(());
        }
        let dir = Path::new(socket_dir);
        std::fs::create_dir_all(dir).map_err(|e| anyhow!("create {}: {e}", dir.display()))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| anyhow!("chmod 0700 {}: {e}", dir.display()))?;
        for &port in ports {
            let path = dir.join(format!("vsock-{port}.sock"));
            // UnixListener::bind fails on a stale socket file — best-effort unlink.
            let _ = std::fs::remove_file(&path);
            let listener =
                UnixListener::bind(&path).map_err(|e| anyhow!("bind {}: {e}", path.display()))?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| anyhow!("chmod 0700 {}: {e}", path.display()))?;
            self.vsock_tasks.push(tokio::spawn(run_port_proxy(
                self.connector(),
                listener,
                port,
            )));
            self.vsock_paths.push(path);
        }
        Ok(())
    }

    /// Bind the per-VM control socket (`control.sock`, mode 0700) and spawn its
    /// accept loop. Speaks the newline-framed `VERB args\n` → `OK …`/`ERR …`
    /// protocol the host-side `mvm_backend::vz_control` client drives.
    fn start_control_socket(&mut self, path: &str) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let path = Path::new(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow!("create {}: {e}", parent.display()))?;
        }
        let _ = std::fs::remove_file(path);
        let listener =
            UnixListener::bind(path).map_err(|e| anyhow!("bind {}: {e}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| anyhow!("chmod 0700 {}: {e}", path.display()))?;
        self.control_task = Some(tokio::spawn(run_control_socket(self.connector(), listener)));
        self.control_path = Some(path.to_path_buf());
        Ok(())
    }

    /// Set a guest→host `VZVirtioSocketListener` on the workload-exit port and
    /// spawn the capture task. A finished one-shot workload's `/init` dials this
    /// port (via the baked `mvm-exit-report`) with its 4-byte LE exit code
    /// before `poweroff`; we persist it to `workload.exit` and surface it from
    /// [`wait`](Self::wait). Long-running workloads never connect.
    async fn start_exit_listener(&mut self, vm_state_dir: &str) -> Result<()> {
        let (tx, rx) = mpsc::unbounded_channel::<SendableConnection>();
        let handle = Arc::clone(&self.handle);
        let listener_handle = self
            .queue
            .dispatch(move || -> Result<ExitListenerHandle> {
                // SAFETY: socketDevices() is a queue-bound accessor.
                let devices = unsafe { handle.vm.socketDevices() };
                let device = devices
                    .to_vec()
                    .into_iter()
                    .next()
                    .and_then(|d| Retained::downcast::<VZVirtioSocketDevice>(d).ok())
                    .ok_or_else(|| anyhow!("VM has no virtio-socket device for exit listener"))?;
                let delegate = VsockListenerDelegate::new(tx);
                // SAFETY: new() returns a default socket listener.
                let listener = unsafe { VZVirtioSocketListener::new() };
                // SAFETY: setDelegate installs our accept delegate.
                unsafe { listener.setDelegate(Some(delegate.as_protocol())) };
                // SAFETY: setSocketListener_forPort must run on the VM's queue.
                unsafe { device.setSocketListener_forPort(&listener, WORKLOAD_EXIT_PORT) };
                Ok(ExitListenerHandle {
                    _listener: listener,
                    _delegate: delegate,
                })
            })
            .await??;
        let dir = PathBuf::from(vm_state_dir);
        let slot = Arc::clone(&self.captured_exit);
        self.exit_task = Some(tokio::spawn(run_exit_listener(rx, dir, slot)));
        self._exit_listener = Some(listener_handle);
        Ok(())
    }

    /// Install a guest→host `VZVirtioSocketListener` per host-listen port and
    /// spawn an accept loop that splices each accepted guest connection to the
    /// per-VM `<socket_dir>/vsock-<port>.sock` a separate host process binds (the
    /// egress substitution endpoint). Opposite direction from
    /// [`start_vsock_proxy`](Self::start_vsock_proxy) (host dials guest); here the
    /// guest dials the port and the host forwards into the endpoint's UDS. The
    /// listener must be installed before boot so the guest's first dial is
    /// accepted. We do NOT bind the UDS — the endpoint owns it; if it hasn't bound
    /// yet (no secrets in the plan) the connect fails and the guest dial is
    /// refused, fail-closed.
    async fn start_host_listen_proxy(&mut self, socket_dir: &str, ports: &[u32]) -> Result<()> {
        if ports.is_empty() {
            return Ok(());
        }
        let dir = PathBuf::from(socket_dir);
        for &port in ports {
            let (tx, rx) = mpsc::unbounded_channel::<SendableConnection>();
            let handle = Arc::clone(&self.handle);
            let listener_handle = self
                .queue
                .dispatch(move || -> Result<ExitListenerHandle> {
                    // SAFETY: socketDevices() is a queue-bound accessor.
                    let devices = unsafe { handle.vm.socketDevices() };
                    let device = devices
                        .to_vec()
                        .into_iter()
                        .next()
                        .and_then(|d| Retained::downcast::<VZVirtioSocketDevice>(d).ok())
                        .ok_or_else(|| {
                            anyhow!("VM has no virtio-socket device for host-listen proxy")
                        })?;
                    let delegate = VsockListenerDelegate::new(tx);
                    // SAFETY: new() returns a default socket listener.
                    let listener = unsafe { VZVirtioSocketListener::new() };
                    // SAFETY: setDelegate installs our accept delegate.
                    unsafe { listener.setDelegate(Some(delegate.as_protocol())) };
                    // SAFETY: setSocketListener_forPort must run on the VM's queue.
                    unsafe { device.setSocketListener_forPort(&listener, port) };
                    Ok(ExitListenerHandle {
                        _listener: listener,
                        _delegate: delegate,
                    })
                })
                .await??;
            let endpoint_sock = dir.join(format!("vsock-{port}.sock"));
            self.host_listen_tasks
                .push(tokio::spawn(run_host_listen_port_proxy(
                    rx,
                    endpoint_sock,
                    port,
                )));
            self._host_listen_listeners.push(listener_handle);
        }
        Ok(())
    }

    /// Abort the vsock proxy + control + exit accept loops and unlink their
    /// sockets. Best-effort; process exit would reap them anyway, but this keeps
    /// the state dir clean.
    pub fn shutdown(&self) {
        for task in &self.vsock_tasks {
            task.abort();
        }
        for task in &self.host_listen_tasks {
            task.abort();
        }
        for task in self.control_task.iter().chain(self.exit_task.iter()) {
            task.abort();
        }
        // NB: the host-listen `vsock-<port>.sock` paths are deliberately NOT
        // unlinked here — the egress substitution endpoint process binds and owns
        // them, so removing them would yank a live listener out from under it.
        for path in self.vsock_paths.iter().chain(self.control_path.iter()) {
            let _ = std::fs::remove_file(path);
        }
    }

    async fn start(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        let handle = Arc::clone(&self.handle);
        self.queue
            .dispatch(move || {
                let block = completion_block(tx);
                // SAFETY: startWithCompletionHandler must run on the VM's queue.
                unsafe { handle.vm.startWithCompletionHandler(&block) };
            })
            .await?;
        rx.await
            .map_err(|_| anyhow!("start completion handler was never called"))??;
        self.push_current_state().await;
        Ok(())
    }

    /// Re-read the framework's authoritative state and publish it. Called after
    /// `start()` so the watcher sees `Running` (or an already-terminal state if
    /// the guest exited instantly) without guessing.
    ///
    /// Only promotes out of `Pending`: if the delegate already pushed a terminal
    /// state, leave it. The state re-read carries no error message
    /// (`collapse_state(Error)` is empty), so overwriting a delegate-reported
    /// `Errored(msg)` here would silently drop the diagnostic.
    async fn push_current_state(&self) {
        let handle = Arc::clone(&self.handle);
        let tx = self.state_tx.clone();
        let _ = self
            .queue
            .dispatch(move || {
                // SAFETY: `state` is a queue-bound property; we are on the queue.
                let observed = collapse_state(unsafe { handle.vm.state() });
                tx.send_if_modified(|current| {
                    if matches!(current, RunState::Pending) {
                        *current = observed;
                        true
                    } else {
                        false
                    }
                });
            })
            .await;
    }

    /// Request a graceful guest shutdown (ACPI power button). Returns once the
    /// request is delivered; observe [`wait`](Self::wait) for the actual stop.
    pub async fn request_stop(&self) -> Result<()> {
        let handle = Arc::clone(&self.handle);
        self.queue
            .dispatch(move || {
                // SAFETY: requestStopWithError must run on the VM's queue.
                unsafe { handle.vm.requestStopWithError() }
                    .map_err(|e| anyhow!("requestStop failed: {}", ns_error_to_string(&e)))
            })
            .await?
    }

    /// Block until the guest reaches a terminal state. Returns the captured
    /// one-shot workload exit code if the guest reported one over the exit port
    /// (the guest acks that report before powering off, so it is durably set by
    /// the time we observe the stop); otherwise the VZ outcome — 0 on a clean
    /// power-off, 1 on a framework error stop.
    pub async fn wait(&self) -> Result<i32> {
        let mut rx = self.state_rx.clone();
        loop {
            match rx.borrow_and_update().clone() {
                RunState::Stopped => return Ok(self.captured_exit_code().unwrap_or(0)),
                RunState::Errored(msg) => {
                    if !msg.is_empty() {
                        eprintln!("mvm-vz-supervisor: guest stopped with error: {msg}");
                    }
                    return Ok(self.captured_exit_code().unwrap_or(1));
                }
                RunState::Pending | RunState::Running => {}
            }
            if rx.changed().await.is_err() {
                bail!("state channel closed before the guest reached a terminal state");
            }
        }
    }

    fn captured_exit_code(&self) -> Option<i32> {
        *self.captured_exit.lock().expect("exit slot mutex")
    }
}

/// Accept loop for one proxied vsock port: each host connection dials the guest
/// and is spliced to it until either side closes. Per-connection failures are
/// logged and dropped; the loop only ends if the listener itself errors.
async fn run_port_proxy(conn: VmConn, listener: UnixListener, port: u32) {
    loop {
        let host = match listener.accept().await {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                tracing::warn!(port, error = %e, "vsock accept failed; stopping port proxy");
                return;
            }
        };
        let conn = conn.clone();
        tokio::spawn(async move {
            match conn.connect(port).await {
                Ok(mut guest) => {
                    let mut host = host;
                    if let Err(e) = tokio::io::copy_bidirectional(&mut host, &mut guest).await {
                        tracing::debug!(port, error = %e, "vsock bridge closed with error");
                    }
                }
                Err(e) => tracing::warn!(port, error = %e, "vsock connect to guest failed"),
            }
        });
    }
}

/// Accept loop for one host-listen (guest→host) port: each guest connection
/// the listener accepted (forwarded over `rx`) is built into a `VsockStream`,
/// then spliced to the per-VM `endpoint_sock` UDS the egress substitution
/// endpoint binds. Per-connection failures are logged and dropped; the loop ends
/// when the listener delegate's sender is dropped (VM teardown). When no endpoint
/// is bound (a secret-free plan), `UnixStream::connect` fails and the guest's
/// dial is refused — fail-closed.
async fn run_host_listen_port_proxy(
    mut rx: mpsc::UnboundedReceiver<SendableConnection>,
    endpoint_sock: PathBuf,
    port: u32,
) {
    while let Some(conn) = rx.recv().await {
        let guest = match VsockStream::from_connection(conn.0) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(port, error = %e, "host-listen: build guest stream failed");
                continue;
            }
        };
        let endpoint_sock = endpoint_sock.clone();
        tokio::spawn(async move {
            let host = match UnixStream::connect(&endpoint_sock).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        port,
                        socket = %endpoint_sock.display(),
                        error = %e,
                        "host-listen: connect to substitution endpoint socket failed"
                    );
                    return;
                }
            };
            let mut guest = guest;
            let mut host = host;
            if let Err(e) = tokio::io::copy_bidirectional(&mut host, &mut guest).await {
                tracing::debug!(port, error = %e, "host-listen bridge closed with error");
            }
        });
    }
}

/// Accept loop for the control socket. Each connection carries one command
/// (matching the host client's single-short-lived-connection-per-command
/// model): read a line, dispatch, write `OK …`/`ERR …\n`.
async fn run_control_socket(conn: VmConn, listener: UnixListener) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                tracing::warn!(error = %e, "control-socket accept failed; stopping");
                return;
            }
        };
        let conn = conn.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            let (read_half, mut write_half) = stream.into_split();
            let mut lines = BufReader::new(read_half).lines();
            if let Ok(Some(line)) = lines.next_line().await {
                let reply = dispatch_control(&conn, line.trim()).await;
                let _ = write_half.write_all(reply.as_bytes()).await;
                let _ = write_half.write_all(b"\n").await;
                let _ = write_half.flush().await;
            }
        });
    }
}

/// Execute one control verb and format the single-line response. RESTORE is
/// deliberately refused — it is a supervisor startup mode, not a runtime
/// command (matches the Swift response).
async fn dispatch_control(conn: &VmConn, command: &str) -> String {
    let (verb, arg) = command
        .split_once(' ')
        .map(|(v, a)| (v, a.trim()))
        .unwrap_or((command, ""));
    match verb {
        "STATUS" => match conn.status_word().await {
            Ok(word) => format!("OK {word}"),
            Err(e) => err_reply(&e),
        },
        "PAUSE" => ok_reply(conn.pause().await),
        "RESUME" => ok_reply(conn.resume().await),
        "BALLOON" => match arg.parse::<u64>() {
            Ok(mib) => ok_reply(conn.set_balloon_inflate(mib).await),
            Err(_) => format!("ERR BALLOON requires a MiB integer argument, got {arg:?}"),
        },
        "SAVE" => {
            if arg.is_empty() {
                "ERR SAVE requires a path argument".to_string()
            } else {
                ok_reply(conn.save(arg).await)
            }
        }
        "RESTORE" => "ERR RESTORE is a supervisor startup mode, not a control-socket command — \
                      spawn a new supervisor with startup_mode={kind:restore,...} on stdin"
            .to_string(),
        other => format!("ERR unknown control command {other:?}"),
    }
}

fn ok_reply(result: Result<()>) -> String {
    match result {
        Ok(()) => "OK".to_string(),
        Err(e) => err_reply(&e),
    }
}

/// Format an error as a single `ERR …` line — newlines collapsed so the
/// response stays one line (the client reads up to the first `\n`).
fn err_reply(e: &anyhow::Error) -> String {
    format!("ERR {}", e.to_string().replace('\n', "; "))
}

// ---------------------------------------------------------------------------
// Config translation
// ---------------------------------------------------------------------------

/// Translate a [`SupervisorConfig`] into a validated
/// `VZVirtualMachineConfiguration` plus the machine-identifier bytes (for the
/// SAVE sidecar). All `unsafe` objc2 calls are here.
///
/// Fail-closed on the one surface not yet ported (see module docs):
/// flow-audited networking. Both `Boot` and `Restore` startup modes build the
/// same device config; the caller picks `start()` vs `restore + resume`.
type BuiltConfig = (
    Retained<VZVirtualMachineConfiguration>,
    Option<Vec<u8>>,
    Option<PendingBridge>,
);

/// Resource-cap parity — refuse an over- or
/// under-allocated request with a legible error rather than VZ's opaque
/// `validateWithError`. Defense in depth: host admission already gates resources
/// against the signed plan (claim 8), but an entitled hypervisor-driving process
/// fails closed on its own too. The caps are host-determined (the live machine),
/// not constants.
fn validate_requested_resources(cpu_count: u32, memory_mib: u64) -> Result<()> {
    // SAFETY: class-method accessors with no preconditions.
    let max_cpu = unsafe { VZVirtualMachineConfiguration::maximumAllowedCPUCount() };
    let min_mem = unsafe { VZVirtualMachineConfiguration::minimumAllowedMemorySize() };
    let max_mem = unsafe { VZVirtualMachineConfiguration::maximumAllowedMemorySize() };
    let cpu = cpu_count as usize;
    if cpu < 1 || cpu > max_cpu {
        bail!("requested cpu_count={cpu_count} is outside the host range 1..={max_cpu}");
    }
    let mem = mib_to_bytes(memory_mib);
    if mem < min_mem || mem > max_mem {
        bail!(
            "requested memory_mib={memory_mib} ({mem} bytes) is outside the host range {}..={} MiB",
            min_mem / (1024 * 1024),
            max_mem / (1024 * 1024)
        );
    }
    Ok(())
}

fn build_vz_config(config: &SupervisorConfig) -> Result<BuiltConfig> {
    validate_requested_resources(config.resources.cpu_count, config.resources.memory_mib)?;
    // Set when the flow-audited gvproxy bridge is wired (audit substrate present):
    // the supervisor's half of the guest-NIC socketpair, handed to the bridge.
    let mut pending_bridge: Option<PendingBridge> = None;
    // SAFETY: new() returns a default-initialized configuration.
    let vz_config = unsafe { VZVirtualMachineConfiguration::new() };
    // SAFETY: plain setters; values were range-checked above.
    unsafe {
        vz_config.setCPUCount(config.resources.cpu_count as usize);
        vz_config.setMemorySize(mib_to_bytes(config.resources.memory_mib));
    }

    // Direct kernel boot (VZLinuxBootLoader) — no EFI, smaller surface.
    let kernel_url = nsurl_from_path(&config.kernel.path);
    // SAFETY: initWithKernelURL builds a Linux boot loader from the kernel path.
    let boot_loader =
        unsafe { VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &kernel_url) };
    let cmdline = NSString::from_str(&config.kernel.cmdline);
    // SAFETY: setCommandLine copies the command-line string.
    unsafe { boot_loader.setCommandLine(&cmdline) };
    if let Some(initrd) = &config.kernel.initrd_path {
        let initrd_url = nsurl_from_path(initrd);
        // SAFETY: setInitialRamdiskURL accepts an optional initrd URL.
        unsafe { boot_loader.setInitialRamdiskURL(Some(&initrd_url)) };
    }
    // SAFETY: setBootLoader accepts any VZBootLoader subclass.
    unsafe { vz_config.setBootLoader(Some(&boot_loader)) };

    // Linux guests require a generic platform. Pin an explicit machine
    // identifier: Boot mints a fresh one; Restore reloads the `.machine-id`
    // sidecar so the restored guest keeps its identity (systemd machine-id /
    // boot-id continuity). The identifier's bytes are returned for SAVE to
    // re-emit the sidecar. A missing/unreadable sidecar falls back to a fresh
    // identifier — restore still works, only identity continuity is lost.
    // SAFETY: new() returns a valid generic platform configuration.
    let platform = unsafe { VZGenericPlatformConfiguration::new() };
    let identifier = match &config.startup_mode {
        StartupMode::Restore {
            machine_id_path: Some(path),
            ..
        } => load_machine_identifier(path).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "machine-id sidecar unreadable; using a fresh identifier");
            // SAFETY: new() always returns a valid fresh identifier.
            unsafe { VZGenericMachineIdentifier::new() }
        }),
        // SAFETY: new() returns a fresh machine identifier.
        _ => unsafe { VZGenericMachineIdentifier::new() },
    };
    // SAFETY: dataRepresentation returns the identifier's opaque bytes.
    let machine_id = unsafe { identifier.dataRepresentation() }.to_vec();
    // SAFETY: setMachineIdentifier applies a validated identifier.
    unsafe { platform.setMachineIdentifier(&identifier) };
    // SAFETY: setPlatform accepts any VZPlatformConfiguration subclass.
    unsafe { vz_config.setPlatform(&platform) };

    // Disks → virtio-blk in declared order (rootfs /dev/vda, overlay, verity
    // sidecar, app-deps volume …). Raw image format.
    if !config.disks.is_empty() {
        let mut devices = Vec::with_capacity(config.disks.len());
        for disk in &config.disks {
            let url = nsurl_from_path(&disk.path);
            // SAFETY: initWithURL_readOnly_error validates the disk image path.
            let attachment = unsafe {
                VZDiskImageStorageDeviceAttachment::initWithURL_readOnly_error(
                    VZDiskImageStorageDeviceAttachment::alloc(),
                    &url,
                    disk.read_only,
                )
            }
            .map_err(|e| anyhow!("disk {:?}: {}", disk.id, ns_error_to_string(&e)))?;
            // SAFETY: initWithAttachment wraps the attachment in a virtio-block device.
            let device = unsafe {
                VZVirtioBlockDeviceConfiguration::initWithAttachment(
                    VZVirtioBlockDeviceConfiguration::alloc(),
                    &attachment,
                )
            };
            devices.push(Retained::into_super(device));
        }
        let array = NSArray::from_retained_slice(&devices);
        // SAFETY: setStorageDevices installs the block devices.
        unsafe { vz_config.setStorageDevices(&array) };
    }

    // virtio-fs shares. Workload microVMs get none by default; the builder VM
    // mounts /work + /job read-only and /out read-write. `read_only` is
    // enforced by Vz itself — the guest can't remount rw.
    if !config.virtio_fs.is_empty() {
        let mut devices = Vec::with_capacity(config.virtio_fs.len());
        for share in &config.virtio_fs {
            let url = nsurl_from_path(&share.host_path);
            // SAFETY: initWithURL_readOnly describes a shared host directory.
            let shared = unsafe {
                VZSharedDirectory::initWithURL_readOnly(
                    VZSharedDirectory::alloc(),
                    &url,
                    share.read_only,
                )
            };
            // SAFETY: initWithDirectory wraps it in a single-directory share.
            let single = unsafe {
                VZSingleDirectoryShare::initWithDirectory(VZSingleDirectoryShare::alloc(), &shared)
            };
            let tag = NSString::from_str(&share.tag);
            // SAFETY: initWithTag creates the virtio-fs device for the mount tag.
            let device = unsafe {
                VZVirtioFileSystemDeviceConfiguration::initWithTag(
                    VZVirtioFileSystemDeviceConfiguration::alloc(),
                    &tag,
                )
            };
            // SAFETY: setShare assigns the directory share.
            unsafe { device.setShare(Some(&single)) };
            devices.push(Retained::into_super(device));
        }
        let array = NSArray::from_retained_slice(&devices);
        // SAFETY: setDirectorySharingDevices installs the shares.
        unsafe { vz_config.setDirectorySharingDevices(&array) };
    }

    // virtio-vsock device. CID 3 is the Vz default for the first guest; the
    // host dials per-port unix sockets via the vsock proxy.
    // SAFETY: new() returns a default vsock device configuration.
    let vsock = unsafe { VZVirtioSocketDeviceConfiguration::new() };
    let vsock_array = NSArray::from_retained_slice(&[Retained::into_super(vsock)]);
    // SAFETY: setSocketDevices installs the vsock device.
    unsafe { vz_config.setSocketDevices(&vsock_array) };

    // Console: always attach a serial port so `console=hvc0` has a sink. Writes
    // go to the requested capture file (created if absent), else /dev/null.
    // Capture is write-only — no host input fd (claim 15 / sealed-prod parity).
    let console_path = match &config.console_output_path {
        Some(path) => {
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)
                .map_err(|e| anyhow!("create console log {path}: {e}"))?;
            path.as_str()
        }
        None => "/dev/null",
    };
    let console_ns = NSString::from_str(console_path);
    let console_fh = NSFileHandle::fileHandleForWritingAtPath(&console_ns)
        .ok_or_else(|| anyhow!("open console handle at {console_path}"))?;
    // SAFETY: attachment built from a writable handle, no reader.
    let attachment = unsafe {
        VZFileHandleSerialPortAttachment::initWithFileHandleForReading_fileHandleForWriting(
            VZFileHandleSerialPortAttachment::alloc(),
            None,
            Some(&console_fh),
        )
    };
    // SAFETY: new() + setAttachment build a virtio console serial port.
    let serial = unsafe { VZVirtioConsoleDeviceSerialPortConfiguration::new() };
    // SAFETY: setAttachment assigns the file-handle attachment.
    unsafe { serial.setAttachment(Some(&attachment)) };
    let serial_array = NSArray::from_retained_slice(&[Retained::into_super(serial)]);
    // SAFETY: setSerialPorts installs the console.
    unsafe { vz_config.setSerialPorts(&serial_array) };

    // Entropy — minimal Linux guests block in early getrandom(2) without it.
    // SAFETY: new() returns a default entropy device configuration.
    let entropy = unsafe { VZVirtioEntropyDeviceConfiguration::new() };
    let entropy_array = NSArray::from_retained_slice(&[Retained::into_super(entropy)]);
    // SAFETY: setEntropyDevices installs the entropy device.
    unsafe { vz_config.setEntropyDevices(&entropy_array) };

    // Memory balloon (host-driven reclaim). The floor is enforced host-side;
    // here we only wire the device when enabled.
    if let Some(balloon) = &config.balloon
        && balloon.enabled
    {
        // SAFETY: new() returns a default traditional balloon configuration.
        let device = unsafe { VZVirtioTraditionalMemoryBalloonDeviceConfiguration::new() };
        let array = NSArray::from_retained_slice(&[Retained::into_super(device)]);
        // SAFETY: setMemoryBalloonDevices installs the balloon (Apple caps at one).
        unsafe { vz_config.setMemoryBalloonDevices(&array) };
    }

    // Network (optional). gvproxy-backed virtio-net (passt is Linux-only).
    // The flow-audited path (events_ingest set) is the in-process
    // payload_tap slice; until then it fails closed so claim-10 egress audit is
    // never silently bypassed.
    match &config.network {
        None => {}
        Some(NetworkConfig::Gvproxy {
            socket_path, mac, ..
        }) => {
            // Flow-audited (audit substrate present): interpose the in-process
            // gvproxy bridge. The guest NIC attaches to one half of a SOCK_DGRAM
            // socketpair; the bridge gets the other (`supervisor_fd`) and splices
            // to gvproxy through the observer + chain-signing pipeline. Without a
            // substrate (dev / builder VMs) the NIC attaches straight to gvproxy.
            let device = if config.has_audit_substrate() {
                let (vz_fd, supervisor_fd) = dgram_socketpair()?;
                pending_bridge = Some(PendingBridge {
                    supervisor_fd,
                    gvproxy_socket_path: socket_path.clone(),
                });
                net_device_from_fd(vz_fd, mac)?
            } else {
                build_gvproxy_device(socket_path, mac)?
            };
            let array = NSArray::from_retained_slice(&[Retained::into_super(device)]);
            // SAFETY: setNetworkDevices installs the virtio-net device.
            unsafe { vz_config.setNetworkDevices(&array) };
        }
    }

    // SAFETY: validateWithError checks the assembled configuration's invariants.
    unsafe { vz_config.validateWithError() }
        .map_err(|e| anyhow!("VZ configuration invalid: {}", ns_error_to_string(&e)))?;

    // Save/restore is a separate, weaker guarantee than validity (VZ boots
    // configs it can't snapshot). A `Boot` that never snapshots is fine, so this
    // is a warning, not a gate — SAVE / `Restore` startup surface the real error
    // if they're used against an unsupported config.
    if let Err(e) = unsafe { vz_config.validateSaveRestoreSupportWithError() } {
        tracing::warn!(
            error = %ns_error_to_string(&e),
            "VZ config does not support save/restore"
        );
    }

    Ok((vz_config, Some(machine_id), pending_bridge))
}

/// Load a `VZGenericMachineIdentifier` from a SAVE-written `.machine-id` sidecar.
fn load_machine_identifier(path: &str) -> Result<Retained<VZGenericMachineIdentifier>> {
    let bytes = std::fs::read(path).map_err(|e| anyhow!("read {path}: {e}"))?;
    let data = NSData::with_bytes(&bytes);
    // SAFETY: initWithDataRepresentation validates the opaque payload (nil on bad bytes).
    unsafe {
        VZGenericMachineIdentifier::initWithDataRepresentation(
            VZGenericMachineIdentifier::alloc(),
            &data,
        )
    }
    .ok_or_else(|| anyhow!("{path} is not a valid machine identifier"))
}

/// The supervisor's half of the guest-NIC socketpair, handed to the in-process
/// gvproxy bridge. Carried out of `build_vz_config`
/// because the bridge is spawned after the VM is created.
struct PendingBridge {
    supervisor_fd: OwnedFd,
    gvproxy_socket_path: String,
}

/// Build a gvproxy-backed virtio-net device: a SOCK_DGRAM unix socket connected
/// to gvproxy's `--listen-vfkit` listener (direct, no flow audit), handed to Vz
/// via a file-handle attachment with the per-VM MAC pinned.
fn build_gvproxy_device(
    socket_path: &str,
    mac: &str,
) -> Result<Retained<VZVirtioNetworkDeviceConfiguration>> {
    net_device_from_fd(connect_gvproxy_dgram(socket_path)?, mac)
}

/// Wrap an owned SOCK_DGRAM fd as a `VZVirtioNetworkDeviceConfiguration` with
/// the pinned MAC. The fd is either connected straight to gvproxy (direct) or
/// the guest half of the bridge socketpair (flow-audited). Ownership transfers
/// to the NSFileHandle (`closeOnDealloc: true`); the VM reads/writes vfkit
/// frames on it for its lifetime.
fn net_device_from_fd(
    fd: OwnedFd,
    mac: &str,
) -> Result<Retained<VZVirtioNetworkDeviceConfiguration>> {
    let raw = fd.into_raw_fd();
    let handle =
        NSFileHandle::initWithFileDescriptor_closeOnDealloc(NSFileHandle::alloc(), raw, true);
    // SAFETY: initWithFileHandle wraps the datagram endpoint as a VZ attachment.
    let attachment = unsafe {
        VZFileHandleNetworkDeviceAttachment::initWithFileHandle(
            VZFileHandleNetworkDeviceAttachment::alloc(),
            &handle,
        )
    };
    // SAFETY: new() returns a default virtio-net device configuration.
    let device = unsafe { VZVirtioNetworkDeviceConfiguration::new() };
    // SAFETY: setAttachment accepts any VZNetworkDeviceAttachment subclass.
    unsafe { device.setAttachment(Some(&attachment)) };

    let mac_ns = NSString::from_str(mac);
    // SAFETY: initWithString validates the MAC string (nil on malformed).
    let vz_mac = unsafe { VZMACAddress::initWithString(VZMACAddress::alloc(), &mac_ns) }
        .ok_or_else(|| anyhow!("invalid MAC address {mac:?} for gvproxy network"))?;
    // SAFETY: setMACAddress pins the validated address.
    unsafe { device.setMACAddress(&vz_mac) };

    Ok(device)
}

/// A connected SOCK_DGRAM socketpair (both halves 1 MiB-buffered) — one half
/// becomes the guest NIC, the other the bridge's guest-facing socket.
fn dgram_socketpair() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0_i32; 2];
    // SAFETY: socketpair fills the two-element array with a connected pair.
    let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    if r != 0 {
        bail!(
            "socketpair(AF_UNIX, SOCK_DGRAM): {}",
            io::Error::last_os_error()
        );
    }
    // SAFETY: both are fresh fds we own.
    let a = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let b = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    bump_socket_buffers(a.as_raw_fd());
    bump_socket_buffers(b.as_raw_fd());
    Ok((a, b))
}

/// Best-effort 1 MiB SO_SNDBUF/SO_RCVBUF so an MTU-sized datagram survives a
/// backlog (matches Apple's sample).
fn bump_socket_buffers(fd: std::os::fd::RawFd) {
    let buf: libc::c_int = 1024 * 1024;
    let buf_ptr = std::ptr::addr_of!(buf).cast::<libc::c_void>();
    let buf_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // SAFETY: setsockopt with a valid int option + length; failure is benign.
        unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, opt, buf_ptr, buf_len) };
    }
}

/// Construct the gateway `BridgeConfig` from the config's audit substrate and
/// spawn the in-process flow-audited gvproxy bridge.
/// Mirrors the libkrun supervisor's `run_with_bridge`: decode the signed plan +
/// bundle, open the chain `FileAuditSigner`, resolve the observer chain, then
/// `spawn_bridge_thread(VzGvproxy)`. Fail-closed: a malformed substrate refuses
/// the boot rather than running unaudited. The returned bridge thread runs until
/// the guest stops (or process exit reaps it).
fn spawn_payload_tap(
    config: &SupervisorConfig,
    pending: PendingBridge,
) -> Result<std::thread::JoinHandle<()>> {
    use ed25519_dalek::SigningKey;
    use mvm_core::plan::{ExecutionPlan, SignedExecutionPlan};
    use mvm_core::policy::PolicyBundle;
    use mvm_hostd::supervisor::audit::AuditSigner;
    use mvm_hostd::supervisor::audit_file::FileAuditSigner;
    use mvm_hostd::supervisor::gateway_bridge::{
        AllowAll, BridgeConfig, BridgeEndpoints, spawn_bridge_thread,
    };
    use mvm_hostd::supervisor::network::{
        ObserverAllowlist, Pipeline, ProviderCapabilities, resolve_observer_chain_from_plan,
    };

    let plan_value = config
        .plan
        .clone()
        .ok_or_else(|| anyhow!("has_audit_substrate but plan missing"))?;
    let signed: SignedExecutionPlan = serde_json::from_value(plan_value)
        .map_err(|e| anyhow!("decode SignedExecutionPlan: {e}"))?;
    let plan: ExecutionPlan = serde_json::from_slice(&signed.0.payload)
        .map_err(|e| anyhow!("decode ExecutionPlan from signed payload: {e}"))?;
    let bundle: Option<PolicyBundle> = match config.bundle.clone() {
        Some(v) => {
            Some(serde_json::from_value(v).map_err(|e| anyhow!("decode PolicyBundle: {e}"))?)
        }
        None => None,
    };

    let audit_dir = config.audit_dir.clone().expect("has_audit_substrate");
    let audit_socket = config
        .gateway_audit_socket
        .clone()
        .expect("has_audit_substrate");
    let signing_key_path = config
        .signing_key_path
        .clone()
        .expect("has_audit_substrate");

    let key_bytes =
        std::fs::read(&signing_key_path).map_err(|e| anyhow!("read signing key: {e}"))?;
    let key_array: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("signing key is {} bytes, expected 32", key_bytes.len()))?;
    let signer = FileAuditSigner::open(SigningKey::from_bytes(&key_array), Path::new(&audit_dir))
        .map_err(|e| anyhow!("open FileAuditSigner: {e}"))?;
    let signer: Arc<dyn AuditSigner> = Arc::new(signer);

    // Leaf capabilities: the Rust Vz supervisor splices in-process, so it can
    // observe + rewrite payloads (payload_tap), like the libkrun gvproxy path.
    let leaf_caps = ProviderCapabilities {
        flow_events: true,
        payload_tap: true,
    };
    let observer_names =
        resolve_observer_chain_from_plan(&plan).map_err(|e| anyhow!("resolve observers: {e}"))?;
    let observers = if observer_names.is_empty() {
        Vec::new()
    } else {
        let allowlist = ObserverAllowlist::load_from_host_config()
            .map_err(|e| anyhow!("load observer allowlist: {e}"))?;
        let mut pipe = Pipeline::new();
        for name in observer_names {
            let obs = allowlist
                .resolve(&name)
                .map_err(|e| anyhow!("resolve observer {name:?}: {e}"))?;
            pipe = pipe
                .observe(obs, leaf_caps)
                .map_err(|e| anyhow!("observer capability gate: {e}"))?;
        }
        pipe.build_observers()
    };

    let bridge_cfg = BridgeConfig {
        vm_name: config.name.clone(),
        plan: Arc::new(plan),
        bundle: bundle.map(Arc::new),
        audit_socket: PathBuf::from(audit_socket),
        signer,
        policy: Arc::new(AllowAll),
        observers,
    };
    let endpoints = BridgeEndpoints::VzGvproxy {
        supervisor_fd: pending.supervisor_fd,
        gvproxy_socket_path: PathBuf::from(pending.gvproxy_socket_path),
    };
    Ok(spawn_bridge_thread(endpoints, bridge_cfg))
}

/// Populate a `sockaddr_un` from `path`, checking the `sun_path` length limit.
fn sockaddr_un_from_path(path: &str) -> Result<libc::sockaddr_un> {
    // SAFETY: zeroed sockaddr_un is a valid starting point.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        bail!(
            "unix socket path too long ({} bytes, limit {}): {path}",
            bytes.len(),
            addr.sun_path.len() - 1
        );
    }
    for (i, &b) in bytes.iter().enumerate() {
        addr.sun_path[i] = b as libc::c_char;
    }
    Ok(addr)
}

/// Open and connect a SOCK_DGRAM AF_UNIX socket to gvproxy's vfkit listener,
/// with 1 MiB send/recv buffers so an MTU-sized datagram survives a backlog
/// (matches Apple's sample). Returns an owned fd that closes
/// on any early-return error path.
///
/// An unbound unix-datagram socket has no return address, so gvproxy's
/// `sendto()` replies are dropped by the kernel. We bind to a sibling path
/// (`<dir>/vz-net-reply.sock`) so gvproxy has an address to reply to. The
/// state-dir removal on VM teardown cleans up the bind socket alongside the
/// rest of the per-VM files.
fn connect_gvproxy_dgram(path: &str) -> Result<OwnedFd> {
    // SAFETY: socket() with constant valid arguments.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        bail!(
            "socket(AF_UNIX, SOCK_DGRAM) for gvproxy: {}",
            io::Error::last_os_error()
        );
    }
    // SAFETY: `fd` is a fresh fd we own; OwnedFd closes it on any early return.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let buf: libc::c_int = 1024 * 1024;
    let buf_ptr = std::ptr::addr_of!(buf).cast::<libc::c_void>();
    let buf_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // SAFETY: setsockopt with a valid int option and length; failure is
        // non-fatal (best-effort buffer bump), so the result is ignored.
        unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, opt, buf_ptr, buf_len) };
    }

    // Derive the reply-socket path: sibling to the gvproxy listener in the
    // same VM state dir. This gives gvproxy a return address for sendto().
    let reply_path = {
        let parent = std::path::Path::new(path)
            .parent()
            .ok_or_else(|| anyhow!("gvproxy socket path has no parent dir: {path}"))?;
        parent.join("vz-net-reply.sock")
    };
    let reply_path_str = reply_path
        .to_str()
        .ok_or_else(|| anyhow!("reply socket path is not valid UTF-8"))?;

    // Remove any stale bind socket from a previous run before binding;
    // a missing file is the normal first-boot case.
    let _ = std::fs::remove_file(&reply_path);

    let bind_addr = sockaddr_un_from_path(reply_path_str)?;
    // SAFETY: bind() with a correctly-populated sockaddr_un and its size.
    let ret = unsafe {
        libc::bind(
            fd,
            std::ptr::addr_of!(bind_addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        bail!(
            "bind() gvproxy reply socket at {reply_path_str}: {}",
            io::Error::last_os_error()
        );
    }

    let connect_addr = sockaddr_un_from_path(path)?;
    // SAFETY: connect() with a correctly-populated sockaddr_un and its size.
    let ret = unsafe {
        libc::connect(
            fd,
            std::ptr::addr_of!(connect_addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        bail!(
            "connect() gvproxy at {path}: {}",
            io::Error::last_os_error()
        );
    }
    Ok(owned)
}

// ---------------------------------------------------------------------------
// PID file
// ---------------------------------------------------------------------------

/// Write the supervisor PID into `vm_state_dir` (created mode 0700 if absent),
/// the convention `mvmctl` reads to find a running Vz guest. Mirrors the Swift
/// supervisor's `writePidFile`.
pub fn write_pid_file(config: &SupervisorConfig) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = Path::new(&config.vm_state_dir);
    std::fs::create_dir_all(dir).map_err(|e| anyhow!("create {}: {e}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| anyhow!("chmod 0700 {}: {e}", dir.display()))?;
    let pid_path = config.resolved_pid_file();
    std::fs::write(&pid_path, format!("{}\n", std::process::id()))
        .map_err(|e| anyhow!("write pid file {}: {e}", pid_path.display()))
}

/// Best-effort PID-file removal on supervisor exit.
pub fn remove_pid_file(config: &SupervisorConfig) {
    let _ = std::fs::remove_file(config.resolved_pid_file());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mib_to_bytes_is_binary_megabytes() {
        assert_eq!(mib_to_bytes(1), 1024 * 1024);
        assert_eq!(mib_to_bytes(512), 512 * 1024 * 1024);
    }

    #[tokio::test]
    async fn capture_exit_persists_code_and_acks() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = tempfile::tempdir().unwrap();
        let (mut client, server) = tokio::io::duplex(64);
        let slot = Arc::new(Mutex::new(None));
        let task = tokio::spawn(capture_exit(
            server,
            dir.path().to_path_buf(),
            Arc::clone(&slot),
        ));
        client.write_all(&(-7i32).to_le_bytes()).await.unwrap();
        let mut ack = [0u8; 1];
        client.read_exact(&mut ack).await.unwrap();
        task.await.unwrap();
        assert_eq!(ack[0], 1);
        assert_eq!(*slot.lock().unwrap(), Some(-7));
        assert_eq!(mvm_core::exit_capture::read_captured(dir.path()), Some(-7));
    }

    #[test]
    fn status_word_covers_lifecycle_states() {
        assert_eq!(status_word(VZVirtualMachineState::Running), "running");
        assert_eq!(status_word(VZVirtualMachineState::Paused), "paused");
        assert_eq!(status_word(VZVirtualMachineState::Stopped), "stopped");
        assert_eq!(status_word(VZVirtualMachineState::Saving), "saving");
        assert_eq!(status_word(VZVirtualMachineState(9999)), "unknown");
    }

    #[test]
    fn collapse_state_terminal_vs_running() {
        assert_eq!(
            collapse_state(VZVirtualMachineState::Stopped),
            RunState::Stopped
        );
        assert_eq!(
            collapse_state(VZVirtualMachineState::Error),
            RunState::Errored(String::new())
        );
        assert_eq!(
            collapse_state(VZVirtualMachineState::Running),
            RunState::Running
        );
        assert_eq!(
            collapse_state(VZVirtualMachineState::Starting),
            RunState::Running
        );
    }

    /// Verify that `connect_gvproxy_dgram` binds a local address so gvproxy
    /// has a return address for replies. The defect: an unbound unix-datagram
    /// socket has no return address and all sendto() replies from gvproxy are
    /// silently dropped by the kernel.
    #[test]
    fn bound_dgram_socket_receives_reply() {
        use std::os::fd::AsRawFd;

        // Use a short /tmp dir to stay well within the 104-byte sun_path limit.
        let dir = tempfile::Builder::new()
            .prefix("mvm-vz-t")
            .tempdir_in("/tmp")
            .unwrap();

        // The "gvproxy" listener side: a bound SOCK_DGRAM socket.
        let listener_path = dir.path().join("gvproxy.sock");
        let listener_path_str = listener_path.to_str().unwrap();
        let listener_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
        assert!(listener_fd >= 0, "listener socket");
        let listener_addr = sockaddr_un_from_path(listener_path_str).unwrap();
        let ret = unsafe {
            libc::bind(
                listener_fd,
                std::ptr::addr_of!(listener_addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        assert_eq!(ret, 0, "listener bind");

        // Connect the client fd.
        let client_owned = connect_gvproxy_dgram(listener_path_str).unwrap();
        let client_raw = client_owned.as_raw_fd();

        // Client sends a datagram to the listener.
        let msg = b"hello";
        let sent = unsafe { libc::send(client_raw, msg.as_ptr().cast(), msg.len(), 0) };
        assert_eq!(sent as usize, msg.len(), "client send");

        // Listener receives it and captures the sender address.
        let mut buf = [0u8; 64];
        let mut src_addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        let mut src_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
        let recvd = unsafe {
            libc::recvfrom(
                listener_fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                std::ptr::addr_of_mut!(src_addr).cast::<libc::sockaddr>(),
                &mut src_len,
            )
        };
        assert_eq!(recvd as usize, msg.len(), "listener recv");
        assert!(&buf[..msg.len()] == msg);

        // The sender address must be non-empty — the fix ensures bind() was called.
        let sun_path_bytes =
            unsafe { std::ffi::CStr::from_ptr(src_addr.sun_path.as_ptr()).to_bytes() };
        assert!(
            !sun_path_bytes.is_empty(),
            "sender address is empty — bind() was not called on the client socket"
        );

        // Listener replies back to the sender address.
        let reply = b"pong";
        let replied = unsafe {
            libc::sendto(
                listener_fd,
                reply.as_ptr().cast(),
                reply.len(),
                0,
                std::ptr::addr_of!(src_addr).cast::<libc::sockaddr>(),
                src_len,
            )
        };
        assert_eq!(replied as usize, reply.len(), "listener sendto reply");

        // Client receives the reply — this is the defect path that was broken.
        let mut rbuf = [0u8; 64];
        let got = unsafe { libc::recv(client_raw, rbuf.as_mut_ptr().cast(), rbuf.len(), 0) };
        assert_eq!(got as usize, reply.len(), "client recv reply");
        assert_eq!(&rbuf[..reply.len()], reply);

        unsafe { libc::close(listener_fd) };
    }
}
