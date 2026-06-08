//! Rust-native Vz supervisor objc2 bridge (Plan 152 WS-B).
//!
//! Drives Apple's `Virtualization.framework` directly from Rust via the
//! `objc2` stack — the replacement for the Swift `crates/mvm-vz-supervisor`.
//! One guest per process; nothing depends on this as a library beyond the
//! sibling `mvm-vz-supervisor` `[[bin]]`.
//!
//! **Threading (Plan 152 WS-B decision).** Every `VZVirtualMachine` call runs
//! on a private serial dispatch queue — the model the Swift supervisor already
//! shipped (`Supervisor.swift`), ported rather than swapped for a main-thread
//! `CFRunLoop`. The non-`Send` objc2 handles live behind that queue; a small
//! [`SerialQueue::dispatch`] bridges each queue hop to an `async` await so the
//! process main thread stays free for the control socket + vsock proxy (later
//! slices). All `unsafe` is contained in this module.
//!
//! **Scope so far.** Cold boot + clean lifecycle/exit propagation; config
//! translation (cpu/memory/kernel/disks/virtio-fs/vsock-device/console/entropy/
//! balloon/platform); the vsock host-side proxy (per-port UNIX listeners spliced
//! to the guest); and the direct gvproxy virtio-net attachment. Deliberately
//! fail-closed (not silently dropped) on the one surface still on the Swift
//! supervisor behind the parity gate: **flow-audited** networking (the
//! `events_ingest` path — porting it as an in-process `payload_tap` is a later
//! slice, and direct-attaching it would bypass the claim-10 egress audit). Also
//! wired: the control socket (STATUS/PAUSE/RESUME/BALLOON/SAVE), `Restore`
//! startup mode, and the machine-id sidecar. Still to come: the in-process
//! payload_tap, the workload-exit channel, and the parity matrix.

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
use tokio::net::UnixListener;
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

// SAFETY: only retained to defer deallocation; never touched concurrently.
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

// SAFETY: created on the queue and only held to defer deallocation.
unsafe impl Send for ExitListenerHandle {}
// SAFETY: shared access is funnelled through the queue.
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

/// Holds the VM and its delegate together. Both are non-`Send`; access is only
/// ever made from inside [`SerialQueue::dispatch`], which is what makes the
/// `unsafe impl Send`/`Sync` sound.
struct VmHandle {
    vm: Retained<VZVirtualMachine>,
    _delegate: Retained<VmDelegate>,
}

// SAFETY: every field touch happens on the VM's serial dispatch queue.
unsafe impl Send for VmHandle {}
// SAFETY: shared access is funnelled through the same serial queue.
unsafe impl Sync for VmHandle {}

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

    /// Control verb `SAVE <path>` (macOS 14+): checkpoint the (paused) guest to
    /// `path`, then best-effort write the `<path>.machine-id` sidecar (mode
    /// 0600) so RESTORE preserves guest identity. The caller pauses first; an
    /// unpaused VM makes `saveMachineStateToURL` error (surfaced as `ERR`).
    async fn save(&self, path: &str) -> Result<()> {
        // VZ refuses to overwrite an existing save file.
        let _ = std::fs::remove_file(path);
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
            .map_err(|_| anyhow!("save completion handler was never called"))??;
        if let Some(bytes) = &self.machine_id {
            let sidecar = format!("{path}.machine-id");
            if let Err(e) = write_machine_id_sidecar(&sidecar, bytes) {
                tracing::warn!(error = %e, "SAVE machine-id sidecar write failed (RESTORE will use a fresh identifier)");
            }
        }
        Ok(())
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
        let vm_state_dir = config.vm_state_dir.clone();
        let control_path = config.control_socket_path.clone();
        let mem_total_bytes = mib_to_bytes(config.resources.memory_mib);
        let startup_mode = config.startup_mode.clone();

        let config = config.clone();
        let queue_inner = queue.clone_inner();
        // The create closure returns the VM handle and the machine-identifier
        // bytes (for the SAVE sidecar) together — both produced on the queue.
        let (handle, machine_id) = queue
            .dispatch(move || -> Result<(Arc<VmHandle>, Option<Vec<u8>>)> {
                let (vz_config, machine_id) = build_vz_config(&config)?;
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

    /// Abort the vsock proxy + control + exit accept loops and unlink their
    /// sockets. Best-effort; process exit would reap them anyway, but this keeps
    /// the state dir clean.
    pub fn shutdown(&self) {
        for task in &self.vsock_tasks {
            task.abort();
        }
        for task in self.control_task.iter().chain(self.exit_task.iter()) {
            task.abort();
        }
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
    async fn push_current_state(&self) {
        let handle = Arc::clone(&self.handle);
        let tx = self.state_tx.clone();
        let _ = self
            .queue
            .dispatch(move || {
                // SAFETY: `state` is a queue-bound property; we are on the queue.
                let _ = tx.send(collapse_state(unsafe { handle.vm.state() }));
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

/// Execute one control verb and format the single-line response. SAVE/RESTORE
/// are deliberately refused — snapshot is a later WS-B slice, and RESTORE is a
/// supervisor startup mode, not a runtime command (matches the Swift response).
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
fn build_vz_config(
    config: &SupervisorConfig,
) -> Result<(Retained<VZVirtualMachineConfiguration>, Option<Vec<u8>>)> {
    // SAFETY: new() returns a default-initialized configuration.
    let vz_config = unsafe { VZVirtualMachineConfiguration::new() };
    // SAFETY: plain setters with validated scalar values.
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
    // sidecar, app-deps volume …). Raw image format per Plan 97.
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
    // host dials per-port unix sockets via the (later-slice) vsock proxy.
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

    // Network (optional). gvproxy-backed virtio-net (ADR-055 — passt is
    // Linux-only). The flow-audited path (events_ingest set) is the in-process
    // payload_tap slice; until then it fails closed so claim-10 egress audit is
    // never silently bypassed.
    match &config.network {
        None => {}
        Some(NetworkConfig::Gvproxy {
            socket_path,
            mac,
            events_ingest_socket_path,
        }) => {
            if events_ingest_socket_path.is_some() {
                bail!(
                    "vz flow-audited networking (in-process payload_tap, claim 10) is not yet \
                     ported to the Rust supervisor (Plan 152 WS-B slice 4); the Swift supervisor \
                     still backs flow-audited guests"
                );
            }
            let device = build_gvproxy_device(socket_path, mac)?;
            let array = NSArray::from_retained_slice(&[Retained::into_super(device)]);
            // SAFETY: setNetworkDevices installs the virtio-net device.
            unsafe { vz_config.setNetworkDevices(&array) };
        }
    }

    // SAFETY: validateWithError checks the assembled configuration's invariants.
    unsafe { vz_config.validateWithError() }
        .map_err(|e| anyhow!("VZ configuration invalid: {}", ns_error_to_string(&e)))?;

    // Save/restore is a separate, weaker guarantee than validity (VZ boots
    // configs it can't snapshot). Surface it as a warning now; SAVE/RESTORE
    // land in a later slice (Plan 152 WS-E).
    if let Err(e) = unsafe { vz_config.validateSaveRestoreSupportWithError() } {
        tracing::warn!(
            error = %ns_error_to_string(&e),
            "VZ config does not support save/restore"
        );
    }

    Ok((vz_config, Some(machine_id)))
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

/// Build a gvproxy-backed virtio-net device: a SOCK_DGRAM unix socket connected
/// to gvproxy's `--listen-vfkit` listener, handed to Vz via a file-handle
/// attachment, with the per-VM MAC pinned (deterministic across save/restore
/// and collision-free across concurrent VMs).
fn build_gvproxy_device(
    socket_path: &str,
    mac: &str,
) -> Result<Retained<VZVirtioNetworkDeviceConfiguration>> {
    let fd = connect_gvproxy_dgram(socket_path)?;
    // Ownership transfers to the NSFileHandle (closeOnDealloc: true); the VM
    // reads/writes vfkit frames on it for its lifetime.
    // `raw` is a valid connected fd we just relinquished; the handle now owns it
    // (closeOnDealloc: true).
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

/// Open and connect a SOCK_DGRAM AF_UNIX socket to gvproxy's vfkit listener,
/// with 1 MiB send/recv buffers so an MTU-sized datagram survives a backlog
/// (matches cloud-hypervisor / Apple's sample). Returns an owned fd that closes
/// on any early-return error path.
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

    // SAFETY: zeroed sockaddr_un is a valid starting point.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_bytes();
    if bytes.len() >= addr.sun_path.len() {
        bail!(
            "gvproxy socket path too long ({} bytes): {path}",
            bytes.len()
        );
    }
    for (i, &b) in bytes.iter().enumerate() {
        addr.sun_path[i] = b as libc::c_char;
    }
    // SAFETY: connect() with a correctly-populated sockaddr_un and its size.
    let ret = unsafe {
        libc::connect(
            fd,
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
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
}
