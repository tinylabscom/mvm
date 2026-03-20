// Swift bridge for Apple Containerization framework.
//
// Exports C-compatible functions that Rust calls via FFI.
// Each function runs the async Containerization API synchronously
// by blocking on a semaphore — this is intentional since the Rust
// caller is already on a blocking thread.

import Foundation
import Containerization

// MARK: - Helpers

/// Run an async closure synchronously by blocking on a semaphore.
/// The `nonisolated(unsafe)` is intentional — we control access via the semaphore.
func runBlocking(_ body: @Sendable @escaping () async throws -> Void) throws {
    let semaphore = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var caughtError: (any Error)?
    Task { @Sendable in
        do {
            try await body()
        } catch {
            caughtError = error
        }
        semaphore.signal()
    }
    semaphore.wait()
    if let caughtError {
        throw caughtError
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

    // Copy values for @Sendable closure capture
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
            // This avoids needing to pull the vminit OCI image.
            let initfs = Mount.block(
                format: "ext4",
                source: rootfsPath,
                destination: "/"
            )

            // Use a temporary root for the container manager state
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

            // Create the container using a minimal base image.
            // Our Nix rootfs is mounted as an additional block device
            // that overrides the root filesystem via /init.
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
///
/// Returns "" on success or an error message on failure.
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
