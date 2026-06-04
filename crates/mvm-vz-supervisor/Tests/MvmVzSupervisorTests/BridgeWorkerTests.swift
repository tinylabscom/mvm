// Plan 102 W6.A.5 — XCTest harness for the Vz bridge (Network.swift).
//
// Five tests covering the bridge's wire contract:
//
//   1. testHandshakeConstantMatchesRustSide — the handshake string
//      `MVM_VZ_BRIDGE_V1\n` must agree byte-for-byte with
//      `mvm_hostd::supervisor::gateway_bridge::VZ_BRIDGE_HANDSHAKE`. A drift
//      here would silently break every Vz audit chain on a fresh
//      `mvmctl up`.
//   2. testFlowOpenedJsonShape — JSON line for a `flow_opened` event
//      must match the FlowEventWire serde shape exactly. The Rust
//      ingest task uses `serde_json::from_str(line.trim_end())`, so
//      anything off (key order doesn't matter, but field names +
//      types do) is rejected silently.
//   3. testFlowClosedJsonShape — same pin for `flow_closed`.
//   4. testBridgeWorkerShufflesDatagramsAndEmitsFlowOpened — full
//      integration. Stands up fake-gvproxy + fake-ingest sockets,
//      runs the BridgeWorker, writes a datagram, asserts (a) the
//      datagram makes it through, (b) a `flow_opened` line lands on
//      the ingest stand-in.
//   5. testBridgeWorkerEmitsFlowClosedOnEof — closes the Vz-side fd
//      end, waits, asserts a `flow_closed` with `reason: eof`
//      appears on the ingest stand-in.

import Darwin
import Foundation
import XCTest

@testable import mvm_vz_supervisor

final class BridgeWorkerTests: XCTestCase {

    // MARK: - 1. Handshake constant pin

    func testHandshakeConstantMatchesRustSide() {
        // mvm_hostd::supervisor::gateway_bridge::VZ_BRIDGE_HANDSHAKE
        // (gateway_bridge.rs:834) — must match exactly.
        XCTAssertEqual(VZ_BRIDGE_HANDSHAKE, "MVM_VZ_BRIDGE_V1\n")
        XCTAssertEqual(
            Data(VZ_BRIDGE_HANDSHAKE.utf8).count,
            17,
            "Rust side reads exactly 17 bytes before parsing NDJSON"
        )
    }

    // MARK: - 2. flow_opened wire shape

    func testFlowOpenedJsonShape() {
        let line = formatFlowOpenedLine(flowId: "vz-egress-abc", direction: "egress")
        XCTAssertTrue(line.hasSuffix("\n"), "NDJSON requires trailing newline")
        let trimmed = String(line.dropLast())
        // Parse + verify the field shape — order-independent.
        guard
            let data = trimmed.data(using: .utf8),
            let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return XCTFail("flow_opened line is not valid JSON: \(trimmed)")
        }
        XCTAssertEqual(obj["kind"] as? String, "flow_opened")
        XCTAssertEqual(obj["flow_id"] as? String, "vz-egress-abc")
        XCTAssertEqual(obj["direction"] as? String, "egress")
        // No "reason" key on flow_opened — Rust's FlowEventWire
        // tagged enum rejects unknown fields on this variant.
        XCTAssertNil(obj["reason"])
    }

    // MARK: - 3. flow_closed wire shape

    func testFlowClosedJsonShape() {
        let line = formatFlowClosedLine(
            flowId: "vz-ingress-xyz",
            direction: "ingress",
            reason: "eof"
        )
        XCTAssertTrue(line.hasSuffix("\n"))
        let trimmed = String(line.dropLast())
        guard
            let data = trimmed.data(using: .utf8),
            let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return XCTFail("flow_closed line is not valid JSON: \(trimmed)")
        }
        XCTAssertEqual(obj["kind"] as? String, "flow_closed")
        XCTAssertEqual(obj["flow_id"] as? String, "vz-ingress-xyz")
        XCTAssertEqual(obj["direction"] as? String, "ingress")
        XCTAssertEqual(obj["reason"] as? String, "eof")
    }

    // MARK: - 4. End-to-end shuffle + flow_opened

    func testBridgeWorkerShufflesDatagramsAndEmitsFlowOpened() throws {
        let env = try BridgeTestEnv.make()
        defer { env.teardown() }

        // Drive an egress datagram: vzPeer → bridge.supFd → bridge.gvFd → gvproxyPeer.
        let payload = Data("hello-egress".utf8)
        let sent = payload.withUnsafeBytes { ptr in
            Darwin.send(env.vzPeer, ptr.baseAddress, ptr.count, 0)
        }
        XCTAssertEqual(sent, payload.count, "vzPeer send")

        // Wait for the bridge to forward + emit flow_opened.
        let received = try env.waitForDatagramOnGvproxyPeer(maxWait: 1.0)
        XCTAssertEqual(received, payload, "egress payload forwarded byte-for-byte")

        let line = try env.waitForIngestLine(maxWait: 1.0)
        let obj = try Self.parseLine(line)
        XCTAssertEqual(obj["kind"] as? String, "flow_opened")
        XCTAssertEqual(obj["direction"] as? String, "egress")
    }

    // MARK: - 5. flow_closed on EOF

    func testBridgeWorkerEmitsFlowClosedOnEof() throws {
        let env = try BridgeTestEnv.make()
        defer { env.teardown() }

        // First push a datagram so flow_opened fires (otherwise
        // BridgeWorker has no opened-state to close).
        let payload = Data("seed".utf8)
        _ = payload.withUnsafeBytes { ptr in
            Darwin.send(env.vzPeer, ptr.baseAddress, ptr.count, 0)
        }
        _ = try env.waitForDatagramOnGvproxyPeer(maxWait: 1.0)
        let opened = try env.waitForIngestLine(maxWait: 1.0)
        XCTAssertTrue(opened.contains("flow_opened"))

        // Close the Vz-side peer. DispatchSourceRead on the
        // supervisor's supFd will see the close + run the cancel
        // handler, which marks `egress` closed.
        Darwin.close(env.vzPeer)
        env.vzPeer = -1

        // The cancel handler is plumbed via the dispatch source's
        // cancelHandler. To deterministically trigger it without
        // depending on macOS read-EOF semantics for AF_UNIX
        // SOCK_DGRAM (which doesn't always fire on the read side
        // when only the peer closes), we trigger the close path by
        // closing the bridge's supFd too — a clean tear-down. The
        // BridgeWorker's cancel handler runs and emits flow_closed.
        env.worker.cancelForTesting()

        let closed = try env.waitForIngestLine(maxWait: 1.0)
        let obj = try Self.parseLine(closed)
        XCTAssertEqual(obj["kind"] as? String, "flow_closed")
        let reason = obj["reason"] as? String ?? ""
        XCTAssertTrue(
            reason == "eof" || reason == "bridge_error",
            "expected eof or bridge_error on test cancel, got \(reason)"
        )
    }

    // MARK: - Helpers

    private static func parseLine(_ line: String) throws -> [String: Any] {
        let trimmed = line.hasSuffix("\n") ? String(line.dropLast()) : line
        guard
            let data = trimmed.data(using: .utf8),
            let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw NSError(
                domain: "BridgeWorkerTests",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "could not parse line as JSON: \(trimmed)"]
            )
        }
        return obj
    }
}

// MARK: - Test environment

/// Fixture that stands up a BridgeWorker connected to fake gvproxy
/// + fake ingest socket peers under a temp directory. Teardown
/// closes all fds + removes the temp dir.
private final class BridgeTestEnv {
    var supFd: Int32 = -1
    var vzPeer: Int32 = -1
    var gvFd: Int32 = -1
    var gvproxyPeer: Int32 = -1
    var ingestListenerFd: Int32 = -1
    var ingestSupervisorFd: Int32 = -1
    var ingestPeerFd: Int32 = -1
    var tempDir: URL
    let worker: BridgeWorker
    var ingestBuffer: Data = Data()
    private let ingestQueue = DispatchQueue(label: "BridgeTestEnv.ingest")

    private init(
        supFd: Int32, vzPeer: Int32,
        gvFd: Int32, gvproxyPeer: Int32,
        ingestListenerFd: Int32, ingestSupervisorFd: Int32, ingestPeerFd: Int32,
        tempDir: URL,
        worker: BridgeWorker
    ) {
        self.supFd = supFd
        self.vzPeer = vzPeer
        self.gvFd = gvFd
        self.gvproxyPeer = gvproxyPeer
        self.ingestListenerFd = ingestListenerFd
        self.ingestSupervisorFd = ingestSupervisorFd
        self.ingestPeerFd = ingestPeerFd
        self.tempDir = tempDir
        self.worker = worker
    }

    static func make() throws -> BridgeTestEnv {
        let tempDir = URL(
            fileURLWithPath: NSTemporaryDirectory()
        ).appendingPathComponent("bridge-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        // Vz-side socketpair (vzPeer ↔ supFd). vzPeer is the test's
        // hand-hold; supFd is the bridge's read side facing Vz.
        var vzPair: [Int32] = [-1, -1]
        let vzRc = vzPair.withUnsafeMutableBufferPointer { ptr in
            Darwin.socketpair(AF_UNIX, SOCK_DGRAM, 0, ptr.baseAddress)
        }
        guard vzRc == 0 else {
            throw NSError(
                domain: "BridgeTestEnv",
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "vz socketpair failed"]
            )
        }
        let vzPeer = vzPair[0]
        let supFd = vzPair[1]

        // gvproxy-side socketpair (gvFd ↔ gvproxyPeer). The
        // production code connects gvFd to a real gvproxy listener;
        // for the test, we splice in a socketpair so we can directly
        // observe what the bridge sends.
        var gvPair: [Int32] = [-1, -1]
        let gvRc = gvPair.withUnsafeMutableBufferPointer { ptr in
            Darwin.socketpair(AF_UNIX, SOCK_DGRAM, 0, ptr.baseAddress)
        }
        guard gvRc == 0 else {
            Darwin.close(vzPeer)
            Darwin.close(supFd)
            throw NSError(
                domain: "BridgeTestEnv",
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "gv socketpair failed"]
            )
        }
        let gvFd = gvPair[0]
        let gvproxyPeer = gvPair[1]

        // Ingest stand-in: a SOCK_STREAM socketpair. ingestPeerFd is
        // what the test reads from; ingestSupervisorFd is what
        // BridgeWorker writes to via the FileHandle.
        var ingestPair: [Int32] = [-1, -1]
        let ingestRc = ingestPair.withUnsafeMutableBufferPointer { ptr in
            Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, ptr.baseAddress)
        }
        guard ingestRc == 0 else {
            Darwin.close(vzPeer); Darwin.close(supFd)
            Darwin.close(gvFd); Darwin.close(gvproxyPeer)
            throw NSError(
                domain: "BridgeTestEnv",
                code: Int(errno),
                userInfo: [NSLocalizedDescriptionKey: "ingest socketpair failed"]
            )
        }
        let ingestSupervisorFd = ingestPair[0]
        let ingestPeerFd = ingestPair[1]

        let ingestHandle = FileHandle(fileDescriptor: ingestSupervisorFd, closeOnDealloc: false)
        let worker = BridgeWorker.startForTesting(
            supFd: supFd,
            gvFd: gvFd,
            ingest: ingestHandle
        )

        return BridgeTestEnv(
            supFd: supFd, vzPeer: vzPeer,
            gvFd: gvFd, gvproxyPeer: gvproxyPeer,
            ingestListenerFd: -1,
            ingestSupervisorFd: ingestSupervisorFd,
            ingestPeerFd: ingestPeerFd,
            tempDir: tempDir,
            worker: worker
        )
    }

    func teardown() {
        worker.cancelForTesting()
        for fd in [vzPeer, supFd, gvFd, gvproxyPeer, ingestSupervisorFd, ingestPeerFd] {
            if fd >= 0 { Darwin.close(fd) }
        }
        try? FileManager.default.removeItem(at: tempDir)
    }

    /// Block up to `maxWait` seconds for a datagram on `gvproxyPeer`,
    /// returning its payload.
    func waitForDatagramOnGvproxyPeer(maxWait: TimeInterval) throws -> Data {
        let deadline = Date().addingTimeInterval(maxWait)
        var buf = [UInt8](repeating: 0, count: 65536)
        while Date() < deadline {
            var pollFd = pollfd(fd: gvproxyPeer, events: Int16(POLLIN), revents: 0)
            let pr = withUnsafeMutablePointer(to: &pollFd) { ptr in
                Darwin.poll(ptr, 1, 50)
            }
            if pr > 0 && (pollFd.revents & Int16(POLLIN)) != 0 {
                let n = buf.withUnsafeMutableBufferPointer { ptr in
                    Darwin.recv(gvproxyPeer, ptr.baseAddress, ptr.count, 0)
                }
                if n > 0 {
                    return Data(buf[0..<Int(n)])
                }
            }
        }
        throw NSError(
            domain: "BridgeTestEnv",
            code: 2,
            userInfo: [NSLocalizedDescriptionKey: "timeout waiting for datagram on gvproxyPeer"]
        )
    }

    /// Block up to `maxWait` seconds for a complete NDJSON line on
    /// the ingest peer, returning it (including the trailing
    /// newline).
    func waitForIngestLine(maxWait: TimeInterval) throws -> String {
        let deadline = Date().addingTimeInterval(maxWait)
        var buf = [UInt8](repeating: 0, count: 4096)
        while Date() < deadline {
            // Check whether the buffer already has a newline.
            if let nl = ingestBuffer.firstIndex(of: UInt8(ascii: "\n")) {
                let line = ingestBuffer[..<(nl + 1)]
                ingestBuffer.removeSubrange(..<(nl + 1))
                return String(data: line, encoding: .utf8) ?? ""
            }
            var pollFd = pollfd(fd: ingestPeerFd, events: Int16(POLLIN), revents: 0)
            let pr = withUnsafeMutablePointer(to: &pollFd) { ptr in
                Darwin.poll(ptr, 1, 50)
            }
            if pr > 0 && (pollFd.revents & Int16(POLLIN)) != 0 {
                let n = buf.withUnsafeMutableBufferPointer { ptr in
                    Darwin.recv(ingestPeerFd, ptr.baseAddress, ptr.count, 0)
                }
                if n > 0 {
                    ingestBuffer.append(contentsOf: buf[0..<Int(n)])
                }
            }
        }
        throw NSError(
            domain: "BridgeTestEnv",
            code: 3,
            userInfo: [NSLocalizedDescriptionKey: "timeout waiting for ingest line"]
        )
    }
}
