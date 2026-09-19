//! Guest-to-host display-frame source for a workload stream.
//!
//! The socket is read-only at the protocol boundary: the guest dials it and
//! the host only reads bounded, length-prefixed [`DisplayFrame`] values. No
//! byte is ever written back, so this source cannot become an input path.

use std::fs::Permissions;
use std::io::{self, ErrorKind, Read};
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use mvm_contract::stream::{DisplayFrame, MAX_ENCODED_DISPLAY_FRAME_BYTES};

use crate::stream::console_source::{SharedBroker, lock_broker};

const READ_DEADLINE: Duration = Duration::from_millis(200);

/// A listener that accepts display frames from the guest-only relay.
pub struct DisplaySource;

impl DisplaySource {
    pub fn listen(path: &Path, broker: SharedBroker) -> io::Result<DisplaySourceHandle> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        reclaim_socket(path)?;
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, Permissions::from_mode(0o600))?;

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_path = path.to_path_buf();
        let thread = std::thread::Builder::new()
            .name(format!("mvm-display-source-{}", path.display()))
            .spawn(move || run(listener, &broker, &thread_stop))?;
        Ok(DisplaySourceHandle {
            stop,
            path: thread_path,
            thread: Some(thread),
        })
    }
}

/// Owns the listener thread and wakes it during teardown.
pub struct DisplaySourceHandle {
    stop: Arc<AtomicBool>,
    path: PathBuf,
    thread: Option<JoinHandle<()>>,
}

impl DisplaySourceHandle {
    pub fn stop(mut self) {
        self.join();
    }

    fn join(&mut self) {
        self.stop.store(true, Ordering::Release);
        // A connect is the owned event that wakes a listener blocked in
        // accept. The connection carries no frame and is discarded because
        // the stop flag is checked before it is read.
        let _ = UnixStream::connect(&self.path);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for DisplaySourceHandle {
    fn drop(&mut self) {
        self.join();
    }
}

fn run(listener: UnixListener, broker: &SharedBroker, stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) {
        let Ok((mut stream, _)) = listener.accept() else {
            if !stop.load(Ordering::Acquire) {
                tracing::warn!("display-frame listener stopped accepting connections");
            }
            return;
        };
        if stop.load(Ordering::Acquire) {
            return;
        }
        if let Err(error) = stream.set_read_timeout(Some(READ_DEADLINE)) {
            tracing::warn!(error = %error, "display-frame connection could not set a read deadline");
            continue;
        }
        if let Err(error) = ingest_connection(&mut stream, broker, stop) {
            tracing::warn!(error = %error, "display-frame connection was refused");
        }
    }
}

fn ingest_connection(
    stream: &mut UnixStream,
    broker: &SharedBroker,
    stop: &AtomicBool,
) -> io::Result<()> {
    loop {
        let Some(length) = read_length(stream, stop)? else {
            return Ok(());
        };
        if length > MAX_ENCODED_DISPLAY_FRAME_BYTES {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "display frame exceeds the encoded byte limit",
            ));
        }
        let mut encoded = vec![0; length];
        read_exact_until_stopped(stream, &mut encoded, stop)?;
        let frame = DisplayFrame::decode(&encoded)
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
        lock_broker(broker)
            .ingest_frame(&frame)
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    }
}

fn read_length(stream: &mut UnixStream, stop: &AtomicBool) -> io::Result<Option<usize>> {
    let mut encoded = [0u8; 4];
    let mut offset = 0;
    while offset < encoded.len() {
        if stop.load(Ordering::Acquire) {
            return Ok(None);
        }
        match stream.read(&mut encoded[offset..]) {
            Ok(0) if offset == 0 => return Ok(None),
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "truncated frame length",
                ));
            }
            Ok(read) => offset += read,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(error) => return Err(error),
        }
    }
    usize::try_from(u32::from_be_bytes(encoded))
        .map(Some)
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "invalid frame length"))
}

fn read_exact_until_stopped(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    stop: &AtomicBool,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if stop.load(Ordering::Acquire) {
            return Err(io::Error::new(
                ErrorKind::Interrupted,
                "display source stopped",
            ));
        }
        match stream.read(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "truncated display frame",
                ));
            }
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn reclaim_socket(path: &Path) -> io::Result<()> {
    match UnixStream::connect(path) {
        Ok(_) => Err(io::Error::new(
            ErrorKind::AddrInUse,
            "display-frame socket already has a listener",
        )),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => {
            let metadata = match std::fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error),
            };
            if !metadata.file_type().is_socket() {
                return Err(io::Error::new(
                    ErrorKind::AddrInUse,
                    "display-frame path exists and is not a socket",
                ));
            }
            match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::{StreamBroker, StreamRedaction};
    use mvm_contract::stream::{DisplayMime, StreamKind, StreamSource};
    use mvm_core::policy::RedactionPolicy;
    use std::io::Write as _;

    fn frame() -> DisplayFrame {
        DisplayFrame {
            step_id: Some("step-1".into()),
            mime: DisplayMime::Jpeg,
            width: 640,
            height: 480,
            bytes: vec![0xff, 0xd8, 0xff, 0xd9],
        }
    }

    #[test]
    fn a_guest_frame_reaches_the_broker_with_display_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("display.sock");
        let broker = Arc::new(std::sync::Mutex::new(StreamBroker::live_only(
            "display-vm",
            StreamRedaction::curated(&RedactionPolicy::default()),
        )));
        let mut reader = broker.lock().unwrap().subscribe();
        let source = DisplaySource::listen(&path, Arc::clone(&broker)).unwrap();
        let mut guest = UnixStream::connect(&path).unwrap();
        let encoded = frame().encode().unwrap();
        guest
            .write_all(&(encoded.len() as u32).to_be_bytes())
            .unwrap();
        guest.write_all(&encoded).unwrap();

        let start = std::time::Instant::now();
        let record = loop {
            if let Some(record) = reader.recv() {
                break record;
            }
            assert!(start.elapsed() < Duration::from_secs(2));
            std::thread::yield_now();
        };
        assert_eq!(record.source, StreamSource::Display);
        assert_eq!(record.kind, StreamKind::Frame);
        assert_eq!(DisplayFrame::decode(&record.payload).unwrap(), frame());
        source.stop();
    }

    #[test]
    fn an_oversized_length_is_refused_without_allocating_it() {
        let broker = Arc::new(std::sync::Mutex::new(StreamBroker::live_only(
            "display-vm",
            StreamRedaction::curated(&RedactionPolicy::default()),
        )));
        let (mut host, mut guest) = UnixStream::pair().unwrap();
        guest
            .write_all(
                &u32::try_from(MAX_ENCODED_DISPLAY_FRAME_BYTES + 1)
                    .unwrap()
                    .to_be_bytes(),
            )
            .unwrap();
        let error = ingest_connection(&mut host, &broker, &AtomicBool::new(false)).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert_eq!(broker.lock().unwrap().ingested_count(), 0);
    }

    #[test]
    fn socket_reclamation_never_removes_a_non_socket_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("display.sock");
        std::fs::write(&path, b"keep me").unwrap();

        let error = reclaim_socket(&path).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::AddrInUse);
        assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
    }
}
