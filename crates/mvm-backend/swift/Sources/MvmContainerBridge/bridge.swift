// Swift bridge for Apple Containerization framework.
//
// Exports C-compatible functions that Rust calls via FFI.
//
// Virtualization.framework requires a running RunLoop on the main
// thread. The init function starts a dedicated thread with a RunLoop,
// and all container operations are dispatched to MainActor to ensure
// they execute on that RunLoop.

import Foundation
import Containerization

// MARK: - Runtime initialization

/// Initialize the Swift/macOS runtime for Virtualization.framework.
///
/// Must be called once before any container operations. Starts a
/// CFRunLoop on a dedicated thread so Virtualization.framework has
/// a functioning event loop.
@_cdecl("mvm_apple_container_init_runtime")
public func initRuntime() {
    // Start the main RunLoop on a background thread.
    // Virtualization.framework needs CFRunLoop to be running for
    // hardware event handling (VM lifecycle, vsock, etc).
    let thread = Thread {
        // Add a dummy source so the RunLoop doesn't exit immediately
        let source = CFRunLoopSourceCreate(nil, 0, nil)
        CFRunLoopAddSource(CFRunLoopGetCurrent(), source, .defaultMode)
        CFRunLoopRun()
    }
    thread.name = "mvm-runloop"
    thread.start()

    // Give the RunLoop a moment to start
    Thread.sleep(forTimeInterval: 0.01)
}

// MARK: - Helpers

/// Run an async @MainActor closure synchronously by blocking on a semaphore.
///
/// All Virtualization.framework calls must happen on MainActor (which
/// uses the main dispatch queue / RunLoop). We block the calling thread
/// until the async work completes.
/// Thread-safe box for passing errors across concurrency boundaries.
final class ErrorBox: @unchecked Sendable {
    var error: (any Error)?
}

func runBlocking(_ body: @Sendable @escaping () async throws -> Void) throws {
    let semaphore = DispatchSemaphore(value: 0)
    let errorBox = ErrorBox()

    Task {
        do {
            try await body()
        } catch {
            errorBox.error = error
        }
        semaphore.signal()
    }
    semaphore.wait()
    if let error = errorBox.error {
        throw error
    }
}

// MARK: - Global state

/// Active containers keyed by ID.
private let containerLock = NSLock()
nonisolated(unsafe) private var activeContainers: [String: LinuxContainer] = [:]

private func storeContainer(_ id: String, _ container: LinuxContainer) {
    containerLock.lock()
    activeContainers[id] = container
    containerLock.unlock()
}

private func removeContainer(_ id: String) -> LinuxContainer? {
    containerLock.lock()
    let container = activeContainers.removeValue(forKey: id)
    containerLock.unlock()
    return container
}

// MARK: - Availability check

@_cdecl("mvm_apple_container_is_available")
public func isAvailable() -> Bool {
    if #available(macOS 26, *) {
        return true
    }
    return false
}

// MARK: - Free a C string allocated by the bridge

@_cdecl("mvm_apple_container_free_string")
public func freeString(_ ptr: UnsafeMutablePointer<CChar>?) {
    if let ptr = ptr {
        free(ptr)
    }
}

// MARK: - Container lifecycle

/// Create and start a container from a local ext4 rootfs and kernel.
///
/// Returns "" on success or an error message on failure.
/// Caller must free the returned string.
@_cdecl("mvm_apple_container_start")
public func startContainer(
    _ idPtr: UnsafePointer<CChar>,
    _ kernelPathPtr: UnsafePointer<CChar>,
    _ rootfsPathPtr: UnsafePointer<CChar>,
    _ cpus: Int32,
    _ memoryMiB: UInt64
) -> UnsafeMutablePointer<CChar>? {
    let id = String(cString: idPtr)
    let kernelPath = String(cString: kernelPathPtr)
    let rootfsPath = String(cString: rootfsPathPtr)

    guard #available(macOS 26, *) else {
        return strdup("Apple Containers require macOS 26+")
    }

    let cpuCount = Int(cpus)
    let memBytes = memoryMiB * 1024 * 1024

    do {
        try runBlocking { [id, kernelPath, rootfsPath, cpuCount, memBytes] in
            let kernel = Kernel(
                path: URL(fileURLWithPath: kernelPath),
                platform: .linuxArm
            )

            let network = try ContainerManager.VmnetNetwork()

            // Use the rootfs as the initfs — our Nix-built rootfs has /init.
            let initfs = Mount.block(
                format: "ext4",
                source: rootfsPath,
                destination: "/"
            )

            // Temporary root for container manager state
            let root = FileManager.default.temporaryDirectory
                .appendingPathComponent("mvm-containers")
            try FileManager.default.createDirectory(
                at: root, withIntermediateDirectories: true
            )

            var manager = try ContainerManager(
                kernel: kernel,
                initfs: initfs,
                root: root,
                network: network,
                rosetta: false
            )

            // Mount our Nix rootfs as the container filesystem
            let rootfs = Mount.block(
                format: "ext4",
                source: rootfsPath,
                destination: "/"
            )

            let container = try await manager.create(
                id,
                reference: "docker.io/library/alpine:3.16",
                rootfsSizeInBytes: 512 * 1024 * 1024,
                readOnly: false
            ) { config in
                config.cpus = cpuCount
                config.memoryInBytes = memBytes
                config.process.arguments = ["/init"]
                config.process.workingDirectory = "/"
                config.mounts.append(rootfs)
            }

            try await container.create()
            try await container.start()

            storeContainer(id, container)
        }
        return strdup("")
    } catch {
        return strdup("start failed: \(error)")
    }
}

/// Stop a running container and clean up.
@_cdecl("mvm_apple_container_stop")
public func stopContainer(_ idPtr: UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>? {
    let id = String(cString: idPtr)

    guard #available(macOS 26, *) else {
        return strdup("Apple Containers require macOS 26+")
    }

    guard let container = removeContainer(id) else {
        return strdup("container '\(id)' not found")
    }

    do {
        try runBlocking {
            try await container.stop()
        }
        return strdup("")
    } catch {
        return strdup("stop failed: \(error)")
    }
}

/// List running container IDs as a JSON array string.
@_cdecl("mvm_apple_container_list")
public func listContainers() -> UnsafeMutablePointer<CChar>? {
    containerLock.lock()
    let ids = Array(activeContainers.keys)
    containerLock.unlock()

    do {
        let data = try JSONSerialization.data(withJSONObject: ids)
        let json = String(data: data, encoding: .utf8) ?? "[]"
        return strdup(json)
    } catch {
        return strdup("[]")
    }
}
