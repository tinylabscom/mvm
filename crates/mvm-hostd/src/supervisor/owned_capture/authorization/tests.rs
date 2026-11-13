//! Real socket/signature components with synthetic enrollment/startup context.
//! These are not admitted HVF, native credential or FD-inheritance witnesses.

use super::*;
use ed25519_dalek::SigningKey;
use mvm_core::crypto::entrypoint_delegation::RegistrationBinding;
use mvm_core::crypto::entrypoint_identity::EnrolledIdentity;
use std::io::{BufRead, Read, Write};
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use uuid::Uuid;

const CHILD: &str = "supervisor::owned_capture::authorization::tests::socket_fixture";
const VM: &str = "capture-auth-fixture";
const WAIT: Duration = Duration::from_secs(5);

// Public RFC 8032 test-vector seed, never a runtime credential.
fn key() -> SigningKey {
    SigningKey::from_bytes(&[
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ])
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Setup {
    boot: [u8; 32],
    now: u64,
}

fn binding(producer: u32, supervisor: u32, setup: &Setup) -> CaptureBinding {
    CaptureBinding::builder(
        EnrolledIdentity {
            installation: Uuid::from_u128(1),
            public_key: key().verifying_key().to_bytes(),
        },
        RegistrationBinding {
            tenant: "fixture".into(),
            instance: format!("{VM}/{}", Uuid::from_u128(2)),
            plan_id: "sha256:".to_owned() + &"22".repeat(32),
            plan_nonce: mvm_core::plan::Nonce::from_bytes([3; 16]),
            run: Uuid::from_u128(4),
            producer: Uuid::from_u128(5),
            session: Uuid::from_u128(6),
            not_before: setup.now - 1,
            not_after: setup.now + 120,
        },
        VM,
    )
    .with_startup([4; 32])
    .with_call(Uuid::from_u128(7))
    .with_boot(setup.boot)
    .with_capture_run("fixture-run")
    .with_peer_pids(producer, supervisor)
    .build()
    .unwrap()
}

enum Event {
    Setup(Setup),
    Spent,
}

struct ChildGuard {
    child: Child,
    observer: ProcessExitObserver,
    output: Option<JoinHandle<()>>,
}

impl ChildGuard {
    fn start(mut command: Command) -> Result<Self> {
        let mut child = command.spawn()?;
        let observer = match ProcessExitObserver::arm(i32::try_from(child.id())?) {
            Ok(observer) => observer,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
        };
        let mut guard = Self {
            child,
            observer,
            output: None,
        };
        guard
            .child
            .stdin
            .as_mut()
            .context("fixture start gate")?
            .write_all(b"s")?;
        Ok(guard)
    }

    fn finish(mut self) -> Result<()> {
        ensure!(
            self.observer.wait_event(Instant::now() + WAIT)? == ProcessExitWait::Exited,
            "fixture exit deadline"
        );
        ensure!(self.child.wait()?.success(), "fixture child failed");
        Ok(())
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(output) = self.output.take() {
            let _ = output.join();
        }
    }
}

struct Fixture {
    child: ChildGuard,
    setup: Setup,
    events: mpsc::Receiver<Event>,
    socket: std::path::PathBuf,
    _root: tempfile::TempDir,
}

fn command(mode: &str, socket: &std::path::Path) -> Result<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--ignored",
            "--exact",
            CHILD,
            "--nocapture",
            "--test-threads=1",
        ])
        .env("CAPTURE_AUTH_MODE", mode)
        .env("CAPTURE_AUTH_SOCKET", socket)
        .env("TMPDIR", socket.parent().context("fixture root")?)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    Ok(command)
}

impl Fixture {
    fn start(mode: &str) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let socket = root.path().join("c.sock");
        let mut child = ChildGuard::start(command(mode, &socket)?)?;
        let stdout = child.child.stdout.take().context("fixture stdout")?;
        let (send, events) = mpsc::sync_channel(4);
        child.output = Some(std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            for _ in 0..32 {
                let mut line = String::new();
                // Bounded control output from this test executable, not guest data.
                if reader.by_ref().take(2049).read_line(&mut line).unwrap_or(0) == 0
                    || line.len() > 2048
                {
                    return;
                }
                if let Some((_, json)) = line.split_once("CAPTURE_AUTH_SETUP=")
                    && let Ok(setup) = serde_json::from_str(json.trim())
                {
                    let _ = send.send(Event::Setup(setup));
                }
                if line.contains("CAPTURE_AUTH_SPENT") {
                    let _ = send.send(Event::Spent);
                }
            }
        }));
        let Event::Setup(setup) = events.recv_timeout(WAIT)? else {
            anyhow::bail!("fixture setup missing")
        };
        Ok(Self {
            child,
            setup,
            events,
            socket,
            _root: root,
        })
    }

    fn connect(&self) -> Result<UnixStream> {
        Ok(UnixStream::connect(&self.socket)?)
    }

    fn challenge(&self, stream: &mut UnixStream) -> Result<(CaptureChallenge, Vec<u8>)> {
        let bytes = read_control(stream, Instant::now() + WAIT)?;
        let expected = binding(std::process::id(), self.child.child.id(), &self.setup);
        let challenge = CaptureChallenge::decode(&bytes, &expected, unix_now()?)?;
        let proof =
            CaptureProof::sign(&key(), expected.identity(), &challenge, unix_now()?)?.encode()?;
        Ok((challenge, proof))
    }

    fn ready(&self, stream: &mut UnixStream, challenge: &CaptureChallenge) -> Result<()> {
        ensure!(
            read_control(stream, Instant::now() + WAIT)? == ready_frame(challenge.nonce()),
            "Ready differs"
        );
        Ok(())
    }
}

#[test]
fn binary_control_lengths_are_rejected_before_body_allocation() {
    for length in [0, u32::MAX, 4093] {
        assert!(control_body_length(length).is_err());
    }
    assert_eq!(control_body_length(1).unwrap(), 1);
    assert_eq!(control_body_length(4092).unwrap(), 4092);
}

#[test]
fn ready_has_only_the_exact_connection_nonce() {
    let nonce = [3; 32];
    let bytes = ready_frame(&nonce);
    assert_eq!(&bytes[..5], &[0, 0, 0, 33, 3]);
    assert_eq!(&bytes[5..], &nonce);
}

#[test]
fn real_connection_spends_once_even_for_zero_output() -> Result<()> {
    let fixture = Fixture::start("happy")?;
    let mut first = fixture.connect()?;
    let (challenge, proof) = fixture.challenge(&mut first)?;
    io::write_all(&mut first, &proof, Instant::now() + WAIT)?;
    fixture.ready(&mut first, &challenge)?;
    let mut second = fixture.connect()?;
    assert!(read_control(&mut second, Instant::now() + WAIT).is_err());
    fixture.child.finish()
}

#[test]
fn invalid_signature_and_copied_proof_release_only_the_reservation() -> Result<()> {
    let fixture = Fixture::start("bad-proof")?;
    let mut first = fixture.connect()?;
    let (challenge, original) = fixture.challenge(&mut first)?;
    let mut bad = original.clone();
    *bad.last_mut().unwrap() ^= 1;
    io::write_all(&mut first, &bad, Instant::now() + WAIT)?;
    assert!(read_control(&mut first, Instant::now() + WAIT).is_err());
    let mut second = fixture.connect()?;
    let (fresh, _) = fixture.challenge(&mut second)?;
    assert_ne!(fresh.nonce(), challenge.nonce());
    io::write_all(&mut second, &original, Instant::now() + WAIT)?;
    assert!(read_control(&mut second, Instant::now() + WAIT).is_err());
    let mut third = fixture.connect()?;
    let (challenge, proof) = fixture.challenge(&mut third)?;
    io::write_all(&mut third, &proof, Instant::now() + WAIT)?;
    fixture.ready(&mut third, &challenge)?;
    fixture.child.finish()
}

#[test]
fn competing_connection_cannot_start_a_second_verifier() -> Result<()> {
    let fixture = Fixture::start("busy")?;
    let mut first = fixture.connect()?;
    let (challenge, proof) = fixture.challenge(&mut first)?;
    let mut second = fixture.connect()?;
    assert!(read_control(&mut second, Instant::now() + WAIT).is_err());
    io::write_all(&mut first, &proof, Instant::now() + WAIT)?;
    fixture.ready(&mut first, &challenge)?;
    fixture.child.finish()
}

#[test]
fn retirement_and_native_stop_win_before_late_spend() -> Result<()> {
    for mode in ["retire-race", "stop-race", "retire-ready"] {
        let fixture = Fixture::start(mode)?;
        let mut stream = fixture.connect()?;
        let (_, proof) = fixture.challenge(&mut stream)?;
        io::write_all(&mut stream, &proof, Instant::now() + WAIT)?;
        assert!(read_control(&mut stream, Instant::now() + WAIT).is_err());
        fixture.child.finish()?;
    }
    Ok(())
}

#[test]
fn a_spent_permit_is_not_refunded_when_ready_is_lost() -> Result<()> {
    let mut fixture = Fixture::start("lost-ready")?;
    let mut stream = fixture.connect()?;
    let (_, proof) = fixture.challenge(&mut stream)?;
    io::write_all(&mut stream, &proof, Instant::now() + WAIT)?;
    assert!(matches!(fixture.events.recv_timeout(WAIT)?, Event::Spent));
    stream.shutdown(Shutdown::Both)?;
    drop(stream);
    fixture
        .child
        .child
        .stdin
        .as_mut()
        .context("fixture control")?
        .write_all(b"x")?;
    let mut second = fixture.connect()?;
    assert!(read_control(&mut second, Instant::now() + WAIT).is_err());
    fixture.child.finish()
}

#[test]
fn a_partial_or_oversized_proof_retires_without_ready() -> Result<()> {
    for (mode, bytes) in [
        ("timeout", vec![0, 0]),
        ("oversize", 4093_u32.to_be_bytes().to_vec()),
    ] {
        let fixture = Fixture::start(mode)?;
        let mut stream = fixture.connect()?;
        fixture.challenge(&mut stream)?;
        io::write_all(&mut stream, &bytes, Instant::now() + WAIT)?;
        assert!(read_control(&mut stream, Instant::now() + WAIT).is_err());
        fixture.child.finish()?;
    }
    Ok(())
}

#[test]
fn a_sibling_process_is_refused_before_the_challenge() -> Result<()> {
    let fixture = Fixture::start("wrong-peer")?;
    let mut proxy = command("proxy", &fixture.socket)?;
    proxy.stdout(Stdio::null());
    ChildGuard::start(proxy)?.finish()?;
    let mut stream = fixture.connect()?;
    let (challenge, proof) = fixture.challenge(&mut stream)?;
    io::write_all(&mut stream, &proof, Instant::now() + WAIT)?;
    fixture.ready(&mut stream, &challenge)?;
    fixture.child.finish()
}

#[test]
fn missing_cloexec_is_refused_without_claiming_creation_atomicity() -> Result<()> {
    let fixture = Fixture::start("no-cloexec")?;
    let mut stream = fixture.connect()?;
    assert!(read_control(&mut stream, Instant::now() + WAIT).is_err());
    fixture.child.finish()
}

#[test]
fn busy_native_control_is_refused_instead_of_extending_authentication() -> Result<()> {
    let fixture = Fixture::start("native-busy")?;
    let mut stream = fixture.connect()?;
    assert!(read_control(&mut stream, Instant::now() + WAIT).is_err());
    fixture.child.finish()
}

#[test]
#[ignore = "child component fixture, started only by the owning tests"]
fn socket_fixture() -> Result<()> {
    use crate::supervisor::hvf_stop::StopControl;
    let mode = std::env::var("CAPTURE_AUTH_MODE")?;
    let path = std::path::PathBuf::from(
        std::env::var_os("CAPTURE_AUTH_SOCKET").context("fixture socket")?,
    );
    let mut start = [0_u8; 1];
    std::io::stdin().read_exact(&mut start)?;
    ensure!(start == *b"s", "fixture start gate differs");
    // SAFETY: read-only kernel metadata in this dedicated child process.
    let parent = u32::try_from(unsafe { libc::getppid() })?;
    let driver = ProcessExitObserver::arm(i32::try_from(parent)?)?;
    let home = tempfile::tempdir()?;
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.isolate_mvm_home(home.path());
    std::thread::spawn(move || {
        // Bound even an abruptly killed driver; no orphan may wait on accept.
        let _ = driver.wait_event(Instant::now() + Duration::from_secs(10));
        std::process::exit(91);
    });
    if mode == "proxy" {
        let mut stream = UnixStream::connect(path)?;
        ensure!(
            read_control(&mut stream, Instant::now() + WAIT).is_err(),
            "proxy received challenge"
        );
        return Ok(());
    }
    let stop = Box::leak(Box::new(AtomicBool::new(false)));
    let control = StopControl::start(VM, stop)?;
    let setup = Setup {
        boot: control
            .authority()
            .with_capture_instance(VM, |instance| Ok(instance.boot_nonce))?,
        now: unix_now()?,
    };
    let mut permit = OwnedCapturePermit::new(
        binding(parent, std::process::id(), &setup),
        control
            .authority()
            .with_capture_instance(VM, |instance| Ok(instance.clone()))?,
        OriginalParent::observe(parent)?,
        control.authority(),
    );
    let listener = UnixListener::bind(&path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    println!("CAPTURE_AUTH_SETUP={}", serde_json::to_string(&setup)?);
    match mode.as_str() {
        "happy" => {
            let connection = permit.authenticate(listener.accept()?.0)?;
            connection.validate()?;
            assert!(permit.authenticate(listener.accept()?.0).is_err());
            assert!(!permit.retire(), "live socket cannot be confirmed closed");
            assert!(connection.validate().is_err());
            drop(connection);
            assert!(permit.retire());
        }
        "bad-proof" => {
            for _ in 0..2 {
                assert!(permit.authenticate(listener.accept()?.0).is_err());
                assert!(matches!(
                    permit.shared.state.lock().unwrap().phase,
                    Phase::Bound
                ));
            }
            drop(permit.authenticate(listener.accept()?.0)?);
            assert!(matches!(
                permit.shared.state.lock().unwrap().phase,
                Phase::Retired
            ));
        }
        "busy" => {
            let first = listener.accept()?.0;
            let shared = Arc::clone(&permit.shared);
            let worker = std::thread::spawn(move || shared.authenticate(first));
            // The parent opens this only after reading the first challenge.
            assert!(permit.authenticate(listener.accept()?.0).is_err());
            drop(
                worker
                    .join()
                    .map_err(|_| anyhow::anyhow!("fixture worker"))??,
            );
        }
        "retire-race" | "stop-race" | "retire-ready" | "lost-ready" => {
            let (entered, noticed) = mpsc::sync_channel(1);
            let (release, released) = mpsc::sync_channel(1);
            let hook = if mode == "lost-ready" || mode == "retire-ready" {
                &permit.shared.before_ready
            } else {
                &permit.shared.before_spend
            };
            *hook.lock().unwrap() = Some((entered, released));
            let stream = listener.accept()?.0;
            let shared = Arc::clone(&permit.shared);
            let worker = std::thread::spawn(move || shared.authenticate(stream));
            noticed.recv_timeout(WAIT)?;
            if mode == "lost-ready" {
                assert!(matches!(
                    permit.shared.state.lock().unwrap().phase,
                    Phase::Spent { ready: false, .. }
                ));
                println!("CAPTURE_AUTH_SPENT");
                let mut signal = [0_u8; 1];
                std::io::Read::read_exact(&mut std::io::stdin(), &mut signal)?;
            } else if mode == "stop-race" {
                stop.store(true, Ordering::Release);
                assert!(permit.current_binding().is_err());
                stop.store(false, Ordering::Release);
            } else {
                assert!(!permit.retire());
            }
            release.send(())?;
            let result = worker
                .join()
                .map_err(|_| anyhow::anyhow!("fixture worker"))?;
            if mode != "lost-ready" {
                assert!(result.is_err());
            }
            drop(result);
            assert!(matches!(
                permit.shared.state.lock().unwrap().phase,
                Phase::Retired
            ));
            if mode == "lost-ready" {
                assert!(permit.authenticate(listener.accept()?.0).is_err());
            }
            assert!(permit.retire());
        }
        "timeout" | "oversize" => {
            assert!(permit.authenticate(listener.accept()?.0).is_err());
            assert!(matches!(
                permit.shared.state.lock().unwrap().phase,
                Phase::Retired
            ));
            assert!(permit.retire());
        }
        "wrong-peer" => {
            assert!(permit.authenticate(listener.accept()?.0).is_err());
            assert!(matches!(
                permit.shared.state.lock().unwrap().phase,
                Phase::Bound
            ));
            drop(permit.authenticate(listener.accept()?.0)?);
        }
        "no-cloexec" => {
            let stream = listener.accept()?.0;
            // SAFETY: only this test owns this accepted socket; no spawn follows.
            let flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) };
            assert!(flags >= 0);
            // SAFETY: change only this test socket's descriptor flags.
            assert_eq!(
                unsafe {
                    libc::fcntl(stream.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC)
                },
                0
            );
            assert!(permit.authenticate(stream).is_err());
            assert!(matches!(
                permit.shared.state.lock().unwrap().phase,
                Phase::Bound
            ));
        }
        "native-busy" => {
            let (entered, noticed) = mpsc::sync_channel(1);
            let (release, released) = mpsc::sync_channel(1);
            let native = control.authority();
            let worker = std::thread::spawn(move || {
                native.with_capture_instance(VM, |_| {
                    entered.send(())?;
                    released.recv_timeout(WAIT)?;
                    Ok(())
                })
            });
            noticed.recv_timeout(WAIT)?;
            assert!(permit.authenticate(listener.accept()?.0).is_err());
            release.send(())?;
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("fixture native gate"))??;
            assert!(permit.retire());
        }
        _ => anyhow::bail!("unknown component fixture mode"),
    }
    Ok(())
}
