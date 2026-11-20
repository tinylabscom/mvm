//! Size- and deadline-bounded transport for the native user-manager connection.
//!
//! Only framing is checked here. Authentication and D-Bus decoding remain in zbus.

use std::{
    io,
    net::Shutdown,
    os::fd::{BorrowedFd, OwnedFd},
};

use tokio::{
    io::AsyncWriteExt as _,
    net::{
        UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
    time::Instant,
};
use zbus::{
    connection::{
        Builder,
        socket::{ReadHalf, Socket, Split, WriteHalf},
    },
    fdo::ConnectionCredentials,
};

#[cfg(target_os = "linux")]
#[path = "native_bus/platforms/linux.rs"]
mod platform;
#[cfg(all(test, unix, not(target_os = "linux")))]
#[path = "native_bus/platforms/fixture.rs"]
mod platform;

const MAX_AUTH_BYTES: usize = 4096;
const MAX_MESSAGE_BYTES: usize = 16 * 1024;
const PREFIX_BYTES: usize = 16;

pub(super) struct NativeConnection {
    pub(super) connection: zbus::Connection,
    shutdown: std::os::unix::net::UnixStream,
    #[cfg(test)]
    pub(super) reader_released: Option<tokio::sync::oneshot::Receiver<()>>,
    #[cfg(test)]
    ancillary_refused: Option<tokio::sync::oneshot::Receiver<()>>,
}

impl Drop for NativeConnection {
    fn drop(&mut self) {
        // Wake the library reader even if the peer keeps its end open.
        let _ = self.shutdown.shutdown(Shutdown::Both);
    }
}

struct ShutdownOnDrop(Option<std::os::unix::net::UnixStream>);

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        if let Some(stream) = &self.0 {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

pub(super) async fn connect(
    stream: UnixStream,
    deadline: Instant,
) -> anyhow::Result<NativeConnection> {
    let standard = stream.into_std()?;
    let mut shutdown = ShutdownOnDrop(Some(standard.try_clone()?));
    let stream = UnixStream::from_std(standard)?;
    let socket = bounded_socket(stream, deadline)?;
    #[cfg(test)]
    let (socket, reader_released, ancillary_refused) = {
        let mut socket = socket;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let (refusal_sender, refusal_receiver) = tokio::sync::oneshot::channel();
        let reader = socket.0.read_mut().inner.as_mut().expect("new reader");
        reader.released = Some(ReaderReleased(Some(sender)));
        reader.ancillary_refused = Some(refusal_sender);
        (socket, Some(receiver), Some(refusal_receiver))
    };
    let connection = tokio::time::timeout_at(
        deadline,
        Builder::socket(socket)
            .p2p()
            .auth_mechanism(zbus::connection::AuthMechanism::External)
            .max_queued(std::num::NonZeroUsize::MIN)
            .build(),
    )
    .await??;
    // A failed or canceled handshake closes the same socket through the guard.
    Ok(NativeConnection {
        connection,
        shutdown: shutdown.0.take().ok_or_else(closed)?,
        #[cfg(test)]
        reader_released,
        #[cfg(test)]
        ancillary_refused,
    })
}

fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "native manager connection closed",
    )
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or oversized native manager frame",
    )
}

async fn before<T>(
    deadline: Instant,
    operation: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::time::timeout_at(deadline, operation)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "native manager deadline expired"))?
}

#[derive(Debug)]
struct CheckedRead {
    stream: OwnedReadHalf,
    deadline: Instant,
    uid: u32,
    #[cfg(test)]
    released: Option<ReaderReleased>,
    #[cfg(test)]
    ancillary_refused: Option<tokio::sync::oneshot::Sender<()>>,
}

#[cfg(test)]
#[derive(Debug)]
struct ReaderReleased(Option<tokio::sync::oneshot::Sender<()>>);

#[cfg(test)]
impl Drop for ReaderReleased {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

#[async_trait::async_trait]
impl ReadHalf for CheckedRead {
    async fn recvmsg(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
        let stream = self.stream.as_ref();
        #[cfg(test)]
        let ancillary_refused = &mut self.ancillary_refused;
        before(self.deadline, async {
            loop {
                stream.readable().await?;
                let result = stream.try_io(tokio::io::Interest::READABLE, || {
                    let mut data = [io::IoSliceMut::new(buffer)];
                    let mut control = [std::mem::MaybeUninit::uninit(); platform::ANCILLARY_BYTES];
                    let mut ancillary = rustix::net::RecvAncillaryBuffer::new(&mut control);
                    let message = rustix::net::recvmsg(
                        stream,
                        &mut data,
                        &mut ancillary,
                        platform::recv_flags(),
                    )?;
                    let mut received_control = false;
                    for item in ancillary.drain() {
                        received_control = true;
                        if let rustix::net::RecvAncillaryMessage::ScmRights(rights) = item {
                            for descriptor in rights {
                                drop(descriptor);
                            }
                        }
                    }
                    if received_control || message.flags.contains(rustix::net::ReturnFlags::CTRUNC)
                    {
                        #[cfg(test)]
                        if let Some(sender) = ancillary_refused.take() {
                            let _ = sender.send(());
                        }
                        return Err(invalid());
                    }
                    Ok((message.bytes, Vec::new()))
                });
                match result {
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    result => return result,
                }
            }
        })
        .await
    }

    async fn peer_credentials(&mut self) -> io::Result<ConnectionCredentials> {
        Ok(ConnectionCredentials::default().set_unix_user_id(self.uid))
    }
}

#[derive(Debug)]
struct BoundedRead {
    inner: Option<CheckedRead>,
    auth_bytes: usize,
    previous_auth_byte: Option<u8>,
}

#[async_trait::async_trait]
impl ReadHalf for BoundedRead {
    async fn recvmsg(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Vec<OwnedFd>)> {
        let remaining = MAX_AUTH_BYTES
            .checked_sub(self.auth_bytes)
            .filter(|n| *n > 0)
            .ok_or_else(invalid)?;
        // Avoid authentication read-ahead mixing binary frames into line framing.
        let length = buffer.len().min(remaining).min(1);
        let inner = self.inner.as_mut().ok_or_else(closed)?;
        let (count, fds) = inner.recvmsg(&mut buffer[..length]).await?;
        for byte in &buffer[..count] {
            // Reject malformed line framing before the library's CRLF indexing.
            if *byte == b'\n' && self.previous_auth_byte != Some(b'\r') {
                return Err(invalid());
            }
            self.previous_auth_byte = Some(*byte);
        }
        self.auth_bytes += count;
        Ok((count, fds))
    }

    async fn receive_message(
        &mut self,
        seq: u64,
        buffered: &mut Vec<u8>,
        fds: &mut Vec<OwnedFd>,
    ) -> zbus::Result<zbus::Message> {
        let mut inner = self.inner.take().ok_or_else(closed)?;
        if buffered.len() > MAX_MESSAGE_BYTES || !fds.is_empty() {
            return Err(invalid().into());
        }
        while buffered.len() < PREFIX_BYTES {
            let mut prefix = [0; PREFIX_BYTES];
            let needed = PREFIX_BYTES - buffered.len();
            let (count, _) = inner.recvmsg(&mut prefix[..needed]).await?;
            if count == 0 {
                return Err(closed().into());
            }
            buffered.extend_from_slice(&prefix[..count]);
        }
        checked_message_size(buffered[..PREFIX_BYTES].try_into().map_err(|_| invalid())?)?;
        // Only this already-checked prefix reaches the library's allocating reader.
        // The library retains its normal validation, sequence and buffered-message handling.
        let message = inner.receive_message(seq, buffered, fds).await?;
        self.inner = Some(inner);
        Ok(message)
    }

    async fn peer_credentials(&mut self) -> io::Result<ConnectionCredentials> {
        self.inner
            .as_mut()
            .ok_or_else(closed)?
            .peer_credentials()
            .await
    }
}

fn checked_message_size(prefix: &[u8; PREFIX_BYTES]) -> io::Result<usize> {
    let number = |bytes: [u8; 4]| match prefix[0] {
        b'l' => Ok(u32::from_le_bytes(bytes)),
        b'B' => Ok(u32::from_be_bytes(bytes)),
        _ => Err(invalid()),
    };
    let body = usize::try_from(number([prefix[4], prefix[5], prefix[6], prefix[7]])?)
        .map_err(|_| invalid())?;
    let fields = usize::try_from(number([prefix[12], prefix[13], prefix[14], prefix[15]])?)
        .map_err(|_| invalid())?;
    let header = PREFIX_BYTES.checked_add(fields).ok_or_else(invalid)?;
    let aligned = header
        .checked_add((8 - header % 8) % 8)
        .ok_or_else(invalid)?;
    let total = aligned
        .checked_add(body)
        .filter(|size| *size <= MAX_MESSAGE_BYTES)
        .ok_or_else(invalid)?;
    Ok(total)
}

#[derive(Debug)]
struct BoundedWrite {
    stream: OwnedWriteHalf,
    deadline: Instant,
    uid: u32,
}

#[async_trait::async_trait]
impl WriteHalf for BoundedWrite {
    async fn sendmsg(&mut self, buffer: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<usize> {
        if !fds.is_empty() || buffer.len() > MAX_MESSAGE_BYTES {
            return Err(invalid());
        }
        before(self.deadline, self.stream.write(buffer)).await
    }

    async fn close(&mut self) -> io::Result<()> {
        before(self.deadline, self.stream.shutdown()).await
    }

    async fn peer_credentials(&mut self) -> io::Result<ConnectionCredentials> {
        Ok(ConnectionCredentials::default().set_unix_user_id(self.uid))
    }
}

struct BoundedSocket(Split<BoundedRead, BoundedWrite>);

impl Socket for BoundedSocket {
    type ReadHalf = BoundedRead;
    type WriteHalf = BoundedWrite;

    fn split(self) -> Split<Self::ReadHalf, Self::WriteHalf> {
        self.0
    }
}

fn bounded_socket(stream: UnixStream, deadline: Instant) -> io::Result<BoundedSocket> {
    let uid = stream.peer_cred()?.uid();
    let (read, write) = stream.into_split();
    Ok(BoundedSocket(Split::new(
        BoundedRead {
            inner: Some(CheckedRead {
                stream: read,
                deadline,
                uid,
                #[cfg(test)]
                released: None,
                #[cfg(test)]
                ancillary_refused: None,
            }),
            auth_bytes: 0,
            previous_auth_byte: None,
        },
        BoundedWrite {
            stream: write,
            deadline,
            uid,
        },
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncReadExt as _;

    #[test]
    fn prefix_bound_includes_both_endians_headers_padding_and_body() {
        for endian in *b"lB" {
            let encode = |n: u32| {
                if endian == b'l' {
                    n.to_le_bytes()
                } else {
                    n.to_be_bytes()
                }
            };
            let mut prefix = [0; PREFIX_BYTES];
            prefix[0] = endian;
            prefix[12..16].copy_from_slice(&encode(1));
            prefix[4..8].copy_from_slice(&encode(8));
            assert_eq!(checked_message_size(&prefix).unwrap(), 32);
            prefix[4..8].copy_from_slice(&encode((MAX_MESSAGE_BYTES - 24) as u32));
            assert_eq!(checked_message_size(&prefix).unwrap(), MAX_MESSAGE_BYTES);
            prefix[4..8].copy_from_slice(&encode((MAX_MESSAGE_BYTES - 23) as u32));
            assert!(checked_message_size(&prefix).is_err());
            for offset in [4, 12] {
                prefix[offset..offset + 4].copy_from_slice(&encode(u32::MAX));
                assert!(checked_message_size(&prefix).is_err());
            }
        }
        assert!(checked_message_size(&[0; PREFIX_BYTES]).is_err());
    }

    #[tokio::test]
    async fn oversized_declaration_refuses_without_waiting_for_a_body() {
        let (mut peer, client) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let (mut read, _) = bounded_socket(client, deadline).unwrap().split().take();
        let mut prefix = [0; PREFIX_BYTES];
        prefix[0] = b'l';
        prefix[1] = 2;
        prefix[3] = 1;
        prefix[4..8].copy_from_slice(&(MAX_MESSAGE_BYTES as u32).to_le_bytes());
        prefix[8..12].copy_from_slice(&1_u32.to_le_bytes());
        peer.write_all(&prefix).await.unwrap();
        let error = read
            .receive_message(1, &mut Vec::new(), &mut Vec::new())
            .await
            .unwrap_err();
        assert!(
            matches!(error, zbus::Error::InputOutput(ref error) if error.kind() == io::ErrorKind::InvalidData)
        );
        assert!(read.inner.is_none(), "a malformed stream is terminal");
    }

    #[tokio::test]
    async fn malformed_and_overlong_authentication_is_bounded_before_library_parsing() {
        for bytes in [b"\n".to_vec(), vec![b'A'; MAX_AUTH_BYTES + 1]] {
            let (mut peer, client) = UnixStream::pair().unwrap();
            let deadline = Instant::now() + Duration::from_secs(1);
            peer.write_all(&bytes).await.unwrap();
            let error = connect(client, deadline)
                .await
                .err()
                .expect("authentication must refuse");
            assert!(
                format!("{error:#}").contains("invalid or oversized native manager frame"),
                "{error:#}"
            );
        }
    }

    #[tokio::test]
    async fn buffered_and_fragmented_messages_still_use_the_library_decoder() {
        let message = |body: &str| {
            zbus::Message::signal("/fixture", "dev.mvm.Fixture", "Update")
                .build(&body)
                .unwrap()
        };
        let first = message("one");
        let second = message("two");
        let mut buffered = first.data().bytes().to_vec();
        buffered.extend_from_slice(second.data().bytes());
        let (_peer, client) = UnixStream::pair().unwrap();
        let (mut read, _) = bounded_socket(client, Instant::now() + Duration::from_secs(1))
            .unwrap()
            .split()
            .take();
        for (seq, expected) in [(1, "one"), (2, "two")] {
            let decoded = read
                .receive_message(seq, &mut buffered, &mut Vec::new())
                .await
                .unwrap();
            assert_eq!(decoded.body().deserialize::<String>().unwrap(), expected);
        }
        assert!(buffered.is_empty());

        let (mut peer, client) = UnixStream::pair().unwrap();
        let (mut read, _) = bounded_socket(client, Instant::now() + Duration::from_secs(1))
            .unwrap()
            .split()
            .take();
        let writer = tokio::spawn(async move {
            for bytes in first.data().bytes().chunks(3) {
                peer.write_all(bytes).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let decoded = read
            .receive_message(3, &mut Vec::new(), &mut Vec::new())
            .await
            .unwrap();
        assert_eq!(decoded.body().deserialize::<String>().unwrap(), "one");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn descriptor_passing_and_oversized_read_ahead_are_refused() {
        use std::os::fd::AsFd as _;
        let (_peer, client) = UnixStream::pair().unwrap();
        let (mut read, mut write) = bounded_socket(client, Instant::now() + Duration::from_secs(1))
            .unwrap()
            .split()
            .take();
        assert!(!read.can_pass_unix_fd());
        assert!(!write.can_pass_unix_fd());
        let file = tempfile::tempfile().unwrap();
        assert!(write.sendmsg(b"x", &[file.as_fd()]).await.is_err());
        let mut rights = vec![rustix::io::dup(&file).unwrap()];
        assert!(
            read.receive_message(1, &mut Vec::new(), &mut rights)
                .await
                .is_err()
        );

        let (_peer, client) = UnixStream::pair().unwrap();
        let (mut read, _) = bounded_socket(client, Instant::now() + Duration::from_secs(1))
            .unwrap()
            .split()
            .take();
        assert!(
            read.receive_message(1, &mut vec![0; MAX_MESSAGE_BYTES + 1], &mut Vec::new())
                .await
                .is_err()
        );
    }

    fn send_rights(stream: &UnixStream, bytes: &[u8], rights: &[BorrowedFd<'_>]) {
        let mut control = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
        let mut ancillary = rustix::net::SendAncillaryBuffer::new(&mut control);
        assert!(ancillary.push(rustix::net::SendAncillaryMessage::ScmRights(rights)));
        assert_eq!(
            rustix::net::sendmsg(
                stream,
                &[io::IoSlice::new(bytes)],
                &mut ancillary,
                rustix::net::SendFlags::empty(),
            )
            .unwrap(),
            bytes.len()
        );
    }

    #[tokio::test]
    async fn native_rights_fixture_transfers_and_releases_exactly_one_descriptor() {
        use std::os::fd::AsFd as _;
        let (peer, client) = UnixStream::pair().unwrap();
        let (probe, rights) = std::os::unix::net::UnixStream::pair().unwrap();
        probe.set_nonblocking(true).unwrap();
        let mut probe = UnixStream::from_std(probe).unwrap();
        send_rights(&peer, b"x", &[rights.as_fd()]);
        drop(rights);
        let mut byte = [0];
        let mut control = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
        let mut ancillary = rustix::net::RecvAncillaryBuffer::new(&mut control);
        let message = rustix::net::recvmsg(
            &client,
            &mut [io::IoSliceMut::new(&mut byte)],
            &mut ancillary,
            super::platform::recv_flags(),
        )
        .unwrap();
        let mut received = Vec::new();
        for item in ancillary.drain() {
            if let rustix::net::RecvAncillaryMessage::ScmRights(rights) = item {
                received.extend(rights);
            }
        }
        assert_eq!((message.bytes, byte), (1, *b"x"));
        assert_eq!(received.len(), 1, "the fixture must actually send a right");
        drop(received);
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(1), probe.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn unsolicited_rights_are_refused_and_closed_before_decoding() {
        use std::os::fd::AsFd as _;
        let (peer, client) = UnixStream::pair().unwrap();
        let (probe, rights) = std::os::unix::net::UnixStream::pair().unwrap();
        probe.set_nonblocking(true).unwrap();
        let mut probe = UnixStream::from_std(probe).unwrap();
        send_rights(&peer, b"x", &[rights.as_fd()]);
        drop(rights);
        let deadline = Instant::now() + Duration::from_secs(1);
        let (mut reader, _) = bounded_socket(client, deadline).unwrap().split().take();
        let mut byte = [0];
        assert_eq!(
            reader.recvmsg(&mut byte).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // The queued right was the last write endpoint. A leaked received FD
        // would keep this read pending even after consuming its ancillary data.
        assert_eq!(
            tokio::time::timeout_at(deadline, probe.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn native_authentication_refuses_multiple_rights_and_closes_every_endpoint() {
        use std::os::fd::AsFd as _;
        let (peer, client) = UnixStream::pair().unwrap();
        let (probes, rights): (Vec<_>, Vec<_>) = (0..8)
            .map(|_| std::os::unix::net::UnixStream::pair().unwrap())
            .unzip();
        let descriptors: Vec<_> = rights.iter().map(|right| right.as_fd()).collect();
        send_rights(&peer, b"x", &descriptors);
        drop(descriptors);
        drop(rights);
        let deadline = Instant::now() + Duration::from_secs(1);
        let error = connect(client, deadline)
            .await
            .err()
            .expect("rights must refuse");
        assert!(
            format!("{error:#}").contains("invalid or oversized native manager frame"),
            "{error:#}"
        );
        for probe in probes {
            probe.set_nonblocking(true).unwrap();
            let mut probe = UnixStream::from_std(probe).unwrap();
            let mut byte = [0];
            assert_eq!(
                tokio::time::timeout_at(deadline, probe.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn frozen_and_trickled_native_input_cannot_renew_the_deadline() {
        let (mut peer, client) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut read, _) = bounded_socket(client, deadline).unwrap().split().take();
        let task = tokio::spawn(async move {
            read.receive_message(1, &mut Vec::new(), &mut Vec::new())
                .await
        });
        for byte in b"l\0\0\0" {
            peer.write_all(&[*byte]).await.unwrap();
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        assert!(!task.is_finished());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn authenticated_message_rights_are_refused_disposed_and_close_the_connection() {
        use std::os::fd::AsFd as _;
        let (server, client) = UnixStream::pair().unwrap();
        let server = server.into_std().unwrap();
        let injector = UnixStream::from_std(server.try_clone().unwrap()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let server = Builder::unix_stream(server)
            .p2p()
            .server(zbus::Guid::generate())
            .build();
        let (server, client) = tokio::join!(server, connect(client, deadline));
        let server = server.unwrap();
        let mut client = client.unwrap();
        let (probes, rights): (Vec<_>, Vec<_>) = (0..8)
            .map(|_| std::os::unix::net::UnixStream::pair().unwrap())
            .unzip();
        let descriptors: Vec<_> = rights.iter().map(|right| right.as_fd()).collect();
        let message = zbus::Message::signal("/fixture", "dev.mvm.Fixture", "Notice")
            .build(&())
            .unwrap();
        let bytes = message.data().bytes();
        send_rights(&injector, bytes, &descriptors);
        drop(descriptors);
        drop(rights);
        // A normal transport deadline must not substitute for ancillary refusal.
        tokio::time::timeout_at(deadline, client.ancillary_refused.take().unwrap())
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout_at(deadline, client.connection.closed())
            .await
            .unwrap();
        let released = client.reader_released.take().unwrap();
        drop(client);
        tokio::time::timeout_at(deadline, released)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout_at(deadline, server.closed())
            .await
            .unwrap();
        for probe in probes {
            probe.set_nonblocking(true).unwrap();
            let mut probe = UnixStream::from_std(probe).unwrap();
            let mut byte = [0];
            assert_eq!(
                tokio::time::timeout_at(deadline, probe.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
    }

    #[tokio::test]
    async fn canceling_authentication_closes_the_same_native_socket() {
        let (mut peer, client) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let task = tokio::spawn(connect(client, deadline));
        let mut initial = [0];
        peer.read_exact(&mut initial).await.unwrap();
        task.abort();
        assert!(task.await.is_err());
        let mut remaining = Vec::new();
        tokio::time::timeout_at(
            deadline,
            peer.take(MAX_AUTH_BYTES as u64).read_to_end(&mut remaining),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn canceling_a_partial_message_releases_and_poisons_reads() {
        use std::{future::Future as _, task::Poll};

        let message = zbus::Message::signal("/fixture", "dev.mvm.Fixture", "Update")
            .build(&"incomplete")
            .unwrap();
        for buffered_bytes in [0, PREFIX_BYTES] {
            let (_peer, client) = UnixStream::pair().unwrap();
            let deadline = Instant::now() + Duration::from_secs(1);
            let (mut read, _) = bounded_socket(client, deadline).unwrap().split().take();
            let (sender, released) = tokio::sync::oneshot::channel();
            read.inner.as_mut().unwrap().released = Some(ReaderReleased(Some(sender)));
            let mut buffered = message.data().bytes()[..buffered_bytes].to_vec();
            let mut rights = Vec::new();
            {
                let receiving = read.receive_message(1, &mut buffered, &mut rights);
                tokio::pin!(receiving);
                std::future::poll_fn(|context| {
                    assert!(receiving.as_mut().poll(context).is_pending());
                    Poll::Ready(())
                })
                .await;
            }
            tokio::time::timeout_at(deadline, released)
                .await
                .unwrap()
                .unwrap();
            assert!(read.inner.is_none(), "a canceled stream is terminal");
            assert!(
                read.receive_message(2, &mut buffered, &mut rights)
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn authentication_budget_is_cumulative_across_crlf_lines() {
        let (mut peer, client) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        let (mut read, _) = bounded_socket(client, deadline).unwrap().split().take();
        let line = b"A\r\n";
        let mut bytes = line.repeat(MAX_AUTH_BYTES / line.len() + 1);
        bytes.truncate(MAX_AUTH_BYTES + 1);
        peer.write_all(&bytes).await.unwrap();
        let mut buffer = [0; 32];
        for expected in &bytes[..MAX_AUTH_BYTES] {
            let (count, rights) = read.recvmsg(&mut buffer).await.unwrap();
            assert_eq!(count, 1, "authentication must not read ahead");
            assert_eq!(buffer[0], *expected);
            assert!(rights.is_empty());
        }
        assert_eq!(
            read.recvmsg(&mut buffer).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn real_library_authentication_and_decoding_use_the_bounded_transport() {
        let (server, client) = UnixStream::pair().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let server = Builder::socket(bounded_socket(server, deadline).unwrap())
            .p2p()
            .server(zbus::Guid::generate())
            .max_queued(std::num::NonZeroUsize::MIN)
            .build();
        let (server, client) = tokio::join!(server, connect(client, deadline));
        let server = server.unwrap();
        let mut client = client.unwrap();
        assert!(!client.connection.is_closed());
        let released = client.reader_released.take().unwrap();
        drop(client);
        tokio::time::timeout_at(deadline, released)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout_at(deadline, server.closed())
            .await
            .unwrap();
    }
}
