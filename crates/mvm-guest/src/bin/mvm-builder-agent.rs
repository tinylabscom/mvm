use std::io::{BufRead, BufReader, Write};
use std::mem::size_of;
use std::os::fd::{FromRawFd, RawFd};

use mvm_guest::builder_agent::{BuilderRequest, BuilderResponse, handle_request};

const AF_VSOCK: i32 = 40;
const SOCK_STREAM: i32 = 1;
const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;
const PORT: u32 = mvm_guest::vsock::GUEST_AGENT_PORT;

#[repr(C)]
struct SockAddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

unsafe extern "C" {
    fn socket(domain: i32, typ: i32, protocol: i32) -> i32;
    fn bind(sockfd: i32, addr: *const core::ffi::c_void, addrlen: u32) -> i32;
    fn listen(sockfd: i32, backlog: i32) -> i32;
    fn accept(sockfd: i32, addr: *mut core::ffi::c_void, addrlen: *mut u32) -> i32;
    fn close(fd: i32) -> i32;
}

fn handle_client(fd: RawFd) {
    // SAFETY: fd comes from accept and is a valid file descriptor owned by this function.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {
                let line_trim = line.trim();
                if line_trim.is_empty() {
                    continue;
                }
                let resp = match serde_json::from_str::<BuilderRequest>(line_trim) {
                    Ok(req) => match handle_request(req) {
                        Ok(resp) => resp,
                        Err(e) => BuilderResponse::Err {
                            message: format!("agent error: {}", e),
                        },
                    },
                    Err(e) => BuilderResponse::Err {
                        message: format!("parse error: {}", e),
                    },
                };
                let writer = reader.get_mut();
                let _ = writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&resp)
                        .unwrap_or_else(|_| "{\"Err\":{\"message\":\"encode error\"}}".to_string())
                );
                let _ = writer.flush();
            }
            Err(_) => break,
        }
    }
}

fn main() {
    // SAFETY: libc call, arguments are constant values.
    let fd = unsafe { socket(AF_VSOCK, SOCK_STREAM, 0) };
    if fd < 0 {
        eprintln!("failed to create vsock socket");
        std::process::exit(1);
    }

    let addr = SockAddrVm {
        svm_family: AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: PORT,
        svm_cid: VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };

    // SAFETY: pointers are valid for the specified size.
    let bind_rc = unsafe {
        bind(
            fd,
            &addr as *const SockAddrVm as *const core::ffi::c_void,
            size_of::<SockAddrVm>() as u32,
        )
    };
    if bind_rc != 0 {
        eprintln!("failed to bind vsock socket");
        // SAFETY: fd is valid.
        unsafe {
            close(fd);
        }
        std::process::exit(1);
    }

    // SAFETY: fd is valid.
    if unsafe { listen(fd, 16) } != 0 {
        eprintln!("failed to listen on vsock socket");
        // SAFETY: fd is valid.
        unsafe {
            close(fd);
        }
        std::process::exit(1);
    }

    loop {
        // SAFETY: null addr pointers are allowed for accept when peer addr is not needed.
        let cfd = unsafe { accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if cfd < 0 {
            continue;
        }
        handle_client(cfd);
    }
}
