import Foundation

/// mvm-container-shim — one container VM per process. Usage:
///
///   mvm-container-shim --spec <path>
///
/// Reads the boot spec JSON, creates + starts the container VM, and serves
/// the newline-JSON control protocol on the spec's control socket until
/// told to stop. On exit (any reason) the container VM is stopped so a
/// shim death never orphans a running VM.

func writeStderr(_ message: String) {
    FileHandle.standardError.write(Data((message + "\n").utf8))
}

guard CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--spec" else {
    writeStderr("usage: mvm-container-shim --spec <path>")
    exit(2)
}
let specPath = CommandLine.arguments[2]

let spec: ShimSpec
do {
    spec = try Rpc.loadSpec(path: specPath)
} catch {
    writeStderr("mvm-container-shim: failed to load spec \(specPath): \(error)")
    exit(1)
}

let shim = Shim(spec: spec)

// SIGTERM/SIGINT → stop the container, then exit. A plain C handler can't
// await, so the dispatch source hops to a task.
let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
let intSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
signal(SIGTERM, SIG_IGN)
signal(SIGINT, SIG_IGN)
termSource.setEventHandler {
    Task {
        await shim.shutdown()
        exit(0)
    }
}
intSource.setEventHandler {
    Task {
        await shim.shutdown()
        exit(0)
    }
}
termSource.resume()
intSource.resume()

let exitCode: Int32 = await {
    do {
        try await shim.boot()
        try await shim.serve()
        await shim.shutdown()
        return 0
    } catch {
        writeStderr("mvm-container-shim: \(error)")
        await shim.shutdown()
        return 1
    }
}()

exit(exitCode)
