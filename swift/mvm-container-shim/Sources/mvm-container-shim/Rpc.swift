import Foundation

/// Wire types for the shim's newline-delimited-JSON control protocol and
/// the `--spec` boot description. One request line in, one response line
/// out; `dial_vsock` is the only op that also transfers an fd (see
/// FdPassing.swift).

/// The boot description the backend writes before spawning the shim.
/// Decoded with `.convertFromSnakeCase`, so the on-disk keys are the
/// snake_case names the Rust side serializes.
struct ShimSpec: Codable {
    struct Rootfs: Codable {
        var path: String
        var readOnly: Bool
    }

    struct Block: Codable {
        var path: String
        var readOnly: Bool
        /// True for blocks that are not mountable filesystems (dm-verity
        /// hash sidecars): they ride along as virtio-blk devices for the
        /// guest to assemble, never as OCI runtime mounts.
        var deviceOnly: Bool
    }

    struct Share: Codable {
        /// mvm's virtio-fs tag for the activation contract (uvol{idx}).
        var tag: String
        var hostPath: String
        var guestPath: String
        var readOnly: Bool
    }

    var vmName: String
    var kernelPath: String
    var initfsPath: String
    var cpus: Int
    var memoryMib: UInt64
    var rootfs: Rootfs
    var blocks: [Block]
    var virtiofsShares: [Share]
    var controlSocket: String
    var agentPort: UInt32
    var bootLogDir: String
}

/// One control request. Heterogeneous params stay a JSON dictionary so the
/// wire format is explicit in the dispatcher (no schema drift between a
/// Codable here and the Rust encoder).
typealias RpcRequest = [String: Any]

enum RpcError: Error, CustomStringConvertible {
    case malformed(String)

    var description: String {
        switch self {
        case .malformed(let message): return message
        }
    }
}

enum Rpc {
    /// Read the op name and id out of a request dictionary.
    static func requestMeta(_ req: RpcRequest) throws -> (id: Int, op: String) {
        guard let id = req["id"] as? Int, let op = req["op"] as? String else {
            throw RpcError.malformed("request requires numeric `id` and string `op`")
        }
        return (id, op)
    }

    static func int(_ req: RpcRequest, _ key: String) throws -> Int {
        guard let value = req[key] as? Int else {
            throw RpcError.malformed("request requires numeric `\(key)`")
        }
        return value
    }

    static func string(_ req: RpcRequest, _ key: String) throws -> String {
        guard let value = req[key] as? String else {
            throw RpcError.malformed("request requires string `\(key)`")
        }
        return value
    }

    static func stringArray(_ req: RpcRequest, _ key: String) -> [String] {
        (req[key] as? [String]) ?? []
    }

    static func bool(_ req: RpcRequest, _ key: String, default defaultValue: Bool) -> Bool {
        (req[key] as? Bool) ?? defaultValue
    }

    /// Decode one newline-terminated request line.
    static func decodeRequest(_ line: Data) throws -> RpcRequest {
        let object = try JSONSerialization.jsonObject(with: line)
        guard let req = object as? RpcRequest else {
            throw RpcError.malformed("request line is not a JSON object")
        }
        return req
    }

    /// Encode one response line (always ends without a newline; the writer
    /// appends it).
    static func encodeResponse(id: Int, result: [String: Any] = [:]) throws -> Data {
        var body: [String: Any] = ["id": id, "ok": true]
        body.merge(result) { _, new in new }
        return try JSONSerialization.data(withJSONObject: body)
    }

    static func encodeError(id: Int, message: String) throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "id": id,
            "ok": false,
            "error": message,
        ])
    }

    /// Load and decode the boot spec JSON file.
    static func loadSpec(path: String) throws -> ShimSpec {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(ShimSpec.self, from: data)
    }
}
