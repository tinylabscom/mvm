import Containerization
import ContainerizationOCI
import Foundation
import NIO

/// The shim's job: own one container VM's lifecycle and translate the
/// backend's newline-JSON control protocol into Containerization + vminitd
/// calls. One process per VM, mirroring the other supervisors — the parent
/// backend never shares a VM's fate with another VM's shim. An actor so
/// the signal-source shutdown path and the serving loop can both touch
/// the container without a data race.
actor Shim {
    let spec: ShimSpec
    let group: EventLoopGroup = MultiThreadedEventLoopGroup.singleton
    private var container: LinuxContainer?
    private var vminitd: Vminitd?

    init(spec: ShimSpec) {
        self.spec = spec
    }

    /// Build the VM from the spec, boot it with vminitd as PID 1, and open
    /// the vminitd control channel (vsock port 1024).
    func boot() async throws {
        let kernel = Kernel(
            path: URL(fileURLWithPath: spec.kernelPath),
            platform: .linuxArm,
            commandline: .init(debug: false, panic: 0)
        )
        let initfs = Mount.block(
            format: "ext4",
            source: spec.initfsPath,
            destination: "/",
            options: ["ro"]
        )
        let manager = VZVirtualMachineManager(kernel: kernel, initialFilesystem: initfs)

        var config = LinuxContainer.Configuration()
        config.cpus = spec.cpus
        config.memoryInBytes = spec.memoryMib * 1024 * 1024
        // vminitd boots from the initfs as PID 1; mvm's activation contract
        // then rides its gRPC API rather than an mvm initramfs.
        config.useInit = true
        try FileManager.default.createDirectory(
            atPath: spec.bootLogDir,
            withIntermediateDirectories: true
        )
        config.bootLog = .file(path: URL(fileURLWithPath: spec.bootLogDir + "/boot.log"))

        var mounts = LinuxContainer.defaultMounts()
        for (index, block) in spec.blocks.enumerated() {
            if block.deviceOnly {
                // Verity sidecars are not filesystems: an OCI runtime mount
                // would fail the boot. They attach as bare virtio-blk
                // devices when the stage-4 activation path needs them —
                // there is deliberately no device-only attach through
                // Configuration.mounts.
                FileHandle.standardError.write(
                    Data("mvm-container-shim: deferring device-only block \(block.path)\n".utf8)
                )
                continue
            }
            mounts.append(
                .block(
                    format: "ext4",
                    source: block.path,
                    destination: "/mnt/mvm/blocks/\(index)",
                    options: block.readOnly ? ["ro"] : []
                )
            )
        }
        for share in spec.virtiofsShares {
            mounts.append(
                .share(
                    source: share.hostPath,
                    destination: share.guestPath,
                    options: share.readOnly ? ["ro"] : []
                )
            )
        }
        config.mounts = mounts

        let rootfs = Mount.block(
            format: "ext4",
            source: spec.rootfs.path,
            destination: "/",
            options: spec.rootfs.readOnly ? ["ro"] : []
        )
        let container = try LinuxContainer(
            spec.vmName,
            rootfs: rootfs,
            vmm: manager,
            configuration: config
        )
        try await container.create()
        try await container.start()
        self.container = container

        let connection = try await container.dialVsock(port: 1024)
        self.vminitd = try await Vminitd(connection: connection, group: group)
    }

    /// Stop the container VM if it is up. Idempotent and best-effort — used
    /// by the shutdown path and the `stop` op alike.
    func shutdown() async {
        if let container {
            try? await container.stop()
        }
        self.container = nil
        self.vminitd = nil
    }

    /// Serve the control protocol: one client at a time on the control
    /// Unix socket until the client asks us to stop or goes away.
    func serve() async throws {
        let listenFd = try UnixFd.listen(path: spec.controlSocket)
        defer {
            close(listenFd)
            unlink(spec.controlSocket)
        }
        while true {
            let clientFd = try UnixFd.accept(listenFd)
            let keepServing = try await serveClient(clientFd)
            close(clientFd)
            if !keepServing {
                return
            }
        }
    }

    /// Serve one control connection until EOF or the `stop` op. Returns
    /// false when the shim should exit (the stop op was handled).
    private func serveClient(_ clientFd: Int32) async throws -> Bool {
        while let line = try UnixFd.readLine(clientFd) {
            if line.isEmpty { continue }
            let keepServing = try await handle(line: line, clientFd: clientFd)
            if !keepServing {
                return false
            }
        }
        return true
    }

    private func writeOk(_ fd: Int32, id: Int, result: [String: Any] = [:]) throws {
        try UnixFd.writeLine(fd, Rpc.encodeResponse(id: id, result: result))
    }

    private func writeErr(_ fd: Int32, id: Int, message: String) throws {
        try UnixFd.writeLine(fd, Rpc.encodeError(id: id, message: message))
    }

    /// Dispatch one request. Returns false only for the `stop` op.
    private func handle(line: Data, clientFd: Int32) async throws -> Bool {
        let req: RpcRequest
        let meta: (id: Int, op: String)
        do {
            req = try Rpc.decodeRequest(line)
            meta = try Rpc.requestMeta(req)
        } catch {
            try writeErr(clientFd, id: 0, message: "malformed request: \(error)")
            return true
        }

        do {
            switch meta.op {
            case "ping":
                try writeOk(clientFd, id: meta.id)

            case "stop":
                await shutdown()
                try writeOk(clientFd, id: meta.id)
                return false

            case "kill":
                guard let container else { throw RpcError.malformed("container is not running") }
                try await container.kill(Signal(rawValue: 9))
                try writeOk(clientFd, id: meta.id)

            case "wait":
                guard let container else { throw RpcError.malformed("container is not running") }
                let status = try await container.wait()
                try writeOk(clientFd, id: meta.id, result: ["exit_code": status.exitCode])

            case "vminitd_write_file":
                let path = try Rpc.string(req, "path")
                let b64 = try Rpc.string(req, "data_b64")
                guard let data = Data(base64Encoded: b64) else {
                    throw RpcError.malformed("data_b64 is not valid base64")
                }
                let mode = UInt32(try Rpc.int(req, "mode"))
                guard let container else { throw RpcError.malformed("container is not running") }
                // `WriteFileFlags` is unconstructable outside the
                // Containerization module (its only initializer is
                // internal), so injection rides `copyIn`'s streaming
                // transfer instead: stage the bytes in a temp file and copy
                // them over the dedicated vsock channel. No unary message
                // size cap applies, so there is no append/chunk flag.
                let tmp = FileManager.default.temporaryDirectory
                    .appendingPathComponent("mvm-shim-\(UUID().uuidString)")
                try data.write(to: tmp)
                defer { try? FileManager.default.removeItem(at: tmp) }
                try await container.copyIn(from: tmp, to: URL(fileURLWithPath: path), mode: mode)
                try writeOk(clientFd, id: meta.id)

            case "vminitd_mkdir":
                let path = try Rpc.string(req, "path")
                let all = Rpc.bool(req, "all", default: false)
                let perms = UInt32(try Rpc.int(req, "perms"))
                try await requireVminitd().mkdir(path: path, all: all, perms: perms)
                try writeOk(clientFd, id: meta.id)

            case "vminitd_mount":
                let source = try Rpc.string(req, "source")
                let destination = try Rpc.string(req, "destination")
                let type = try Rpc.string(req, "type")
                let options = Rpc.stringArray(req, "options")
                let mount = ContainerizationOCI.Mount(
                    type: type,
                    source: source,
                    destination: destination,
                    options: options
                )
                try await requireVminitd().mount(mount)
                try writeOk(clientFd, id: meta.id)

            case "vminitd_create_process":
                let procId = try Rpc.string(req, "proc_id")
                let path = try Rpc.string(req, "path")
                let args = Rpc.stringArray(req, "args")
                let env = Rpc.stringArray(req, "env")
                let cwd = (req["cwd"] as? String) ?? "/"
                var process = ContainerizationOCI.Process()
                process.args = [path] + args
                process.env = env
                process.cwd = cwd
                let ociSpec = Spec(version: "", process: process)
                try await requireVminitd().createProcess(
                    id: procId,
                    containerID: nil,
                    stdinPort: nil,
                    stdoutPort: nil,
                    stderrPort: nil,
                    ociRuntimePath: nil,
                    configuration: ociSpec,
                    options: nil
                )
                try writeOk(clientFd, id: meta.id)

            case "vminitd_start_process":
                let procId = try Rpc.string(req, "proc_id")
                let pid = try await requireVminitd().startProcess(id: procId, containerID: nil)
                try writeOk(clientFd, id: meta.id, result: ["pid": pid])

            case "vminitd_wait_process":
                let procId = try Rpc.string(req, "proc_id")
                let status = try await requireVminitd().waitProcess(id: procId, containerID: nil)
                try writeOk(clientFd, id: meta.id, result: ["exit_code": status.exitCode])

            case "vminitd_signal":
                let procId = try Rpc.string(req, "proc_id")
                let sig = Int32(try Rpc.int(req, "signal"))
                try await requireVminitd().signalProcess(id: procId, containerID: nil, signal: sig)
                try writeOk(clientFd, id: meta.id)

            case "dial_vsock":
                guard let container else { throw RpcError.malformed("container is not running") }
                let port = UInt32(try Rpc.int(req, "port"))
                let handle = try await container.dialVsock(port: port)
                // Respond first so the client knows the fd is coming, then
                // hand the connected socket over SCM_RIGHTS.
                try writeOk(clientFd, id: meta.id)
                try FdPassing.sendFd(clientFd, fd: handle.fileDescriptor)
                handle.closeFile()

            default:
                try writeErr(clientFd, id: meta.id, message: "unknown op `\(meta.op)`")
            }
        } catch {
            try writeErr(clientFd, id: meta.id, message: "\(error)")
        }
        return true
    }

    private func requireVminitd() throws -> Vminitd {
        guard let vminitd else { throw RpcError.malformed("vminitd channel is not up") }
        return vminitd
    }
}
