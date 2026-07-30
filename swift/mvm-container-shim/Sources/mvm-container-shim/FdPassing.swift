import Foundation

/// Raw-fd plumbing the Foundation layer does not cover: Unix-domain socket
/// listen/accept, line reads, full writes, and the SCM_RIGHTS fd handoff
/// the `dial_vsock` op needs. Kept small and total — every public function
/// returns or throws, never traps.

enum SocketError: Error, CustomStringConvertible {
    case syscall(name: String, errno: Int32)

    var description: String {
        switch self {
        case .syscall(let name, let errno):
            return "\(name) failed: errno \(errno) (\(String(cString: strerror(errno))))"
        }
    }
}

enum UnixFd {
    /// Bind + listen on a Unix socket at `path` (stale path removed first).
    static func listen(path: String, backlog: Int32 = 4) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SocketError.syscall(name: "socket", errno: errno) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8CString)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count <= capacity else {
            close(fd)
            throw SocketError.syscall(name: "bind(path too long)", errno: ENAMETOOLONG)
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { sunPath in
            sunPath.withMemoryRebound(to: CChar.self, capacity: capacity) { dest in
                pathBytes.withUnsafeBufferPointer { src in
                    if let base = src.baseAddress {
                        dest.update(from: base, count: pathBytes.count)
                    }
                }
            }
        }
        unlink(path)
        let bindRc = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bind(fd, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindRc == 0 else {
            let e = errno
            close(fd)
            throw SocketError.syscall(name: "bind", errno: e)
        }
        guard Darwin.listen(fd, backlog) == 0 else {
            let e = errno
            close(fd)
            throw SocketError.syscall(name: "listen", errno: e)
        }
        return fd
    }

    static func accept(_ listenFd: Int32) throws -> Int32 {
        let fd = Darwin.accept(listenFd, nil, nil)
        guard fd >= 0 else { throw SocketError.syscall(name: "accept", errno: errno) }
        return fd
    }

    /// Read one newline-terminated line (without the newline). Returns nil
    /// on clean EOF before any byte.
    static func readLine(_ fd: Int32) throws -> Data? {
        var out = Data()
        var byte = [UInt8](repeating: 0, count: 1)
        while true {
            let n = read(fd, &byte, 1)
            if n == 0 {
                return out.isEmpty ? nil : out
            }
            guard n > 0 else {
                let e = errno
                if e == EINTR { continue }
                throw SocketError.syscall(name: "read", errno: e)
            }
            if byte[0] == UInt8(ascii: "\n") {
                return out
            }
            out.append(byte[0])
        }
    }

    static func writeAll(_ fd: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { raw in
            var written = 0
            while written < raw.count {
                let n = write(fd, raw.baseAddress!.advanced(by: written), raw.count - written)
                if n < 0 {
                    let e = errno
                    if e == EINTR { continue }
                    throw SocketError.syscall(name: "write", errno: e)
                }
                written += n
            }
        }
    }

    static func writeLine(_ fd: Int32, _ data: Data) throws {
        var line = data
        line.append(UInt8(ascii: "\n"))
        try writeAll(fd, line)
    }
}

/// CMSG helpers mirroring CMSG_ALIGN/CMSG_LEN/CMSG_SPACE from <sys/socket.h>.
enum Cmsg {
    static func align(_ n: Int) -> Int {
        (n + MemoryLayout<Int>.size - 1) & ~(MemoryLayout<Int>.size - 1)
    }

    static func len(_ payloadBytes: Int) -> Int {
        align(MemoryLayout<cmsghdr>.size) + payloadBytes
    }

    static func space(_ payloadBytes: Int) -> Int {
        align(MemoryLayout<cmsghdr>.size) + align(payloadBytes)
    }

    static func data(_ cmsg: UnsafeMutablePointer<cmsghdr>) -> UnsafeMutableRawPointer {
        UnsafeMutableRawPointer(cmsg).advanced(by: align(MemoryLayout<cmsghdr>.size))
    }
}

enum FdPassing {
    /// The wire convention for `dial_vsock`: after the JSON response line,
    /// one sendmsg carries a single dummy byte as payload and the vsock fd
    /// in an SCM_RIGHTS control message. The Rust side does the symmetric
    /// recvmsg. A plain byte is required because a message may not consist
    /// of control data alone.
    static func sendFd(_ socket: Int32, fd fdToSend: Int32) throws {
        var dummy: UInt8 = 0
        try withUnsafeMutableBytes(of: &dummy) { dummyPtr in
            var iov = iovec(iov_base: dummyPtr.baseAddress, iov_len: dummyPtr.count)
            try withUnsafeMutablePointer(to: &iov) { iovPtr in
                let controlBytes = Cmsg.space(MemoryLayout<Int32>.size)
                let control = UnsafeMutableRawPointer.allocate(
                    byteCount: controlBytes,
                    alignment: MemoryLayout<cmsghdr>.alignment
                )
                defer { control.deallocate() }
                control.initializeMemory(as: UInt8.self, repeating: 0, count: controlBytes)

                var msg = msghdr()
                msg.msg_iov = iovPtr
                msg.msg_iovlen = 1
                msg.msg_control = control
                // macOS requires the ancillary length to be CMSG_LEN (the
                // exact header+payload), not CMSG_SPACE, or sendmsg fails
                // EINVAL.
                msg.msg_controllen = socklen_t(Cmsg.len(MemoryLayout<Int32>.size))

                // Single cmsg at the head of the control buffer —
                // CMSG_FIRSTHDR is a function-like macro Swift can't
                // import, but with exactly one header it is simply the
                // buffer start.
                let cmsg = control.assumingMemoryBound(to: cmsghdr.self)
                cmsg.pointee.cmsg_level = SOL_SOCKET
                cmsg.pointee.cmsg_type = SCM_RIGHTS
                cmsg.pointee.cmsg_len = socklen_t(Cmsg.len(MemoryLayout<Int32>.size))
                Cmsg.data(cmsg).withMemoryRebound(to: Int32.self, capacity: 1) { ptr in
                    ptr.pointee = fdToSend
                }

                let rc = sendmsg(socket, &msg, 0)
                guard rc >= 0 else { throw SocketError.syscall(name: "sendmsg", errno: errno) }
            }
        }
    }
}
