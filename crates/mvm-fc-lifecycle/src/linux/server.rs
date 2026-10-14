use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::files::{object, open_path, trusted_file};
use super::{LinuxProcesses, RootStorage};
use crate::admission::Admission;
use crate::core::{Peer, Service};
use crate::identity::authenticate_server;
use crate::protocol::{Operation, Request, Response};
use crate::transport::{CONNECTION_BUDGET, connect, receive, send};
use crate::{EXECUTABLE, Error, Result, SOCKET};

fn credentials(stream: &UnixStream) -> Result<libc::ucred> {
    let mut peer = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut size =
        libc::socklen_t::try_from(std::mem::size_of_val(&peer)).map_err(|_| Error::Refused)?;
    // SAFETY: getsockopt receives correctly sized initialized ucred storage.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut size,
        )
    } != 0
        || usize::try_from(size).ok() != Some(std::mem::size_of_val(&peer))
        || peer.pid <= 1
    {
        return Err(Error::Refused);
    }
    Ok(peer)
}

fn installed_identity(pid: i32, uid: u32) -> Result<()> {
    let installed = trusted_file(EXECUTABLE)?;
    let running = File::open(format!("/proc/{pid}/exe"))?;
    authenticate_server(
        uid,
        &object(&installed.metadata()?),
        &object(&running.metadata()?),
    )?;
    if std::fs::read_link(format!("/proc/{pid}/exe"))? != std::path::Path::new(EXECUTABLE) {
        return Err(Error::Refused);
    }
    Ok(())
}

pub(crate) fn serve() -> Result<()> {
    // SAFETY: uid queries have no memory or privilege-changing side effects.
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getuid() } != 0 {
        return Err(Error::Refused);
    }
    installed_identity(
        i32::try_from(std::process::id()).map_err(|_| Error::Refused)?,
        0,
    )?;
    let storage = RootStorage::open()?;
    let service = Arc::new(Mutex::new(Service::recover(LinuxProcesses, storage)?));
    let admission = Arc::new(Mutex::new(Admission::default()));
    let _parent = open_path("/run/mvm", None, libc::O_RDONLY | libc::O_DIRECTORY)?;
    // Refuse preexisting sockets, including stale ones. No pathname cleanup
    // authority is delegated to a request or performed automatically.
    let listener = UnixListener::bind(SOCKET)?;
    std::fs::set_permissions(SOCKET, std::fs::Permissions::from_mode(0o666))?;
    let socket = open_path(SOCKET, None, libc::O_PATH)?;
    if !socket.metadata()?.file_type().is_socket() {
        return Err(Error::Refused);
    }
    for connection in listener.incoming() {
        let mut stream = connection?;
        let deadline = Instant::now() + CONNECTION_BUDGET;
        // Kernel credentials and admission precede all request-body reads.
        // Refusal closes immediately, never occupying the intake loop on I/O.
        let Ok(peer) = credentials(&stream) else {
            continue;
        };
        if !service
            .lock()
            .map_err(|_| Error::Refused)?
            .admits_uid(peer.uid)
        {
            continue;
        }
        let Ok(permit) = Admission::acquire(&admission, peer.uid) else {
            continue;
        };
        let service = service.clone();
        std::thread::Builder::new().spawn(move || {
            let _permit = permit;
            let response = (|| {
                let request = receive::<Request>(&mut stream, deadline)?;
                if matches!(&request.operation, Operation::Register { .. }) {
                    service
                        .lock()
                        .map_err(|_| Error::Refused)?
                        .execute(Peer { uid: peer.uid }, request)
                } else {
                    let action = service
                        .lock()
                        .map_err(|_| Error::Refused)?
                        .action(Peer { uid: peer.uid }, request)?;
                    action.run(&LinuxProcesses)
                }
            })()
            .unwrap_or(Response::Refused);
            let _ = send(&mut stream, &response, deadline);
        })?;
    }
    Ok(())
}

pub(crate) fn request(request: &Request) -> Result<Response> {
    let socket = open_path(SOCKET, None, libc::O_PATH)?;
    let before = socket.metadata()?;
    if !before.file_type().is_socket() || before.uid() != 0 {
        return Err(Error::Refused);
    }
    let deadline = Instant::now() + CONNECTION_BUDGET;
    let mut stream = connect(SOCKET, deadline)?;
    let peer = credentials(&stream)?;
    if peer.uid != 0 {
        return Err(Error::Refused);
    }
    // A non-root client cannot dereference /proc/root-pid/exe on ordinary
    // Linux. Authenticate the root principal and its protected socket instead;
    // root is already in the service TCB and can signal any registered process.
    let _installed = trusted_file(EXECUTABLE)?;
    let after = open_path(SOCKET, None, libc::O_PATH)?.metadata()?;
    authenticate_server(peer.uid, &object(&before), &object(&after))?;
    send(&mut stream, request, deadline)?;
    receive(&mut stream, deadline)
}
