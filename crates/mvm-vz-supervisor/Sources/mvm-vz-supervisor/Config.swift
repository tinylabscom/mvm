import Foundation

// Plan 97 Phase A — JSON schema the host pipes in on stdin.
//
// Mirrors the libkrun supervisor schema where the fields overlap
// (`name`, `vm_state_dir`, `pid_file_name`, the disks list, the
// vsock port list, the virtio-fs mounts list, the console output
// path). Vz-specific fields (`network.kind`, the typed balloon block)
// live alongside in a flat top-level object — the plan's "vz: Option<>
// block" notion applies host-side in Rust; here we receive only the
// Vz-relevant fields so the schema stays compact.
//
// Strict decoding: any unknown JSON key causes a decode error. This
// is half of ADR-002 claim 5's "supervisor config JSON is fuzzed" —
// the Rust-side fuzz target (Plan 97 Phase A checklist item) feeds
// this decoder and the Rust serde decoder the same corpus and asserts
// they reject the same inputs.

// MARK: - Top-level

struct SupervisorConfig: Decodable, StrictKeys {
    let name: String
    let vmStateDir: String
    let pidFileName: String?
    let kernel: KernelConfig
    let resources: ResourceConfig
    let disks: [DiskConfig]
    let virtioFs: [VirtioFsShare]
    let vsock: VsockConfig
    let consoleOutputPath: String?
    let network: NetworkConfig?
    let balloon: BalloonConfig?
    let controlSocketPath: String?
    /// Plan 97 Phase E follow-up — supervisor startup mode. Defaults
    /// to `.boot` when absent so existing Boot-only JSON callers
    /// don't need to change.
    let startupMode: StartupMode

    static let knownKeys: Set<String> = [
        "name", "vm_state_dir", "pid_file_name", "kernel", "resources",
        "disks", "virtio_fs", "vsock", "console_output_path", "network",
        "balloon", "control_socket_path", "startup_mode",
    ]

    enum CodingKeys: String, CodingKey {
        case name
        case vmStateDir = "vm_state_dir"
        case pidFileName = "pid_file_name"
        case kernel
        case resources
        case disks
        case virtioFs = "virtio_fs"
        case vsock
        case consoleOutputPath = "console_output_path"
        case network
        case balloon
        case controlSocketPath = "control_socket_path"
        case startupMode = "startup_mode"
    }

    init(from decoder: Decoder) throws {
        try Self.assertKnownKeys(decoder: decoder)
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try c.decode(String.self, forKey: .name)
        self.vmStateDir = try c.decode(String.self, forKey: .vmStateDir)
        self.pidFileName = try c.decodeIfPresent(String.self, forKey: .pidFileName)
        self.kernel = try c.decode(KernelConfig.self, forKey: .kernel)
        self.resources = try c.decode(ResourceConfig.self, forKey: .resources)
        self.disks = try c.decode([DiskConfig].self, forKey: .disks)
        self.virtioFs = try c.decode([VirtioFsShare].self, forKey: .virtioFs)
        self.vsock = try c.decode(VsockConfig.self, forKey: .vsock)
        self.consoleOutputPath = try c.decodeIfPresent(String.self, forKey: .consoleOutputPath)
        self.network = try c.decodeIfPresent(NetworkConfig.self, forKey: .network)
        self.balloon = try c.decodeIfPresent(BalloonConfig.self, forKey: .balloon)
        self.controlSocketPath = try c.decodeIfPresent(String.self, forKey: .controlSocketPath)
        self.startupMode =
            try c.decodeIfPresent(StartupMode.self, forKey: .startupMode) ?? .boot
    }

    var resolvedPidFile: URL {
        URL(fileURLWithPath: vmStateDir)
            .appendingPathComponent(pidFileName ?? "vz.pid")
    }
}

/// Plan 97 Phase E — supervisor startup mode. Mirrors the Rust
/// `mvm_build::vz::StartupMode` tagged enum: JSON looks like
/// `{"kind":"boot"}` or
/// `{"kind":"restore","snapshot_path":"/abs/path","machine_id_path":"..."}`.
/// Strict-keys enforced; unknown keys cause a decode error.
enum StartupMode: Decodable {
    case boot
    case restore(snapshotPath: String, machineIdPath: String?)

    enum Kind: String, Decodable {
        case boot
        case restore
    }

    enum CodingKeys: String, CodingKey {
        case kind
        case snapshotPath = "snapshot_path"
        case machineIdPath = "machine_id_path"
    }

    static let knownKeys: Set<String> = ["kind", "snapshot_path", "machine_id_path"]

    init(from decoder: Decoder) throws {
        try checkStrictKeys(decoder: decoder, knownKeys: Self.knownKeys)
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(Kind.self, forKey: .kind)
        switch kind {
        case .boot:
            self = .boot
        case .restore:
            let snapshot = try c.decode(String.self, forKey: .snapshotPath)
            let machineId = try c.decodeIfPresent(String.self, forKey: .machineIdPath)
            self = .restore(snapshotPath: snapshot, machineIdPath: machineId)
        }
    }
}

// MARK: - Kernel

struct KernelConfig: Decodable, StrictKeys {
    let path: String
    let cmdline: String
    let initrdPath: String?

    static let knownKeys: Set<String> = ["path", "cmdline", "initrd_path"]

    enum CodingKeys: String, CodingKey {
        case path
        case cmdline
        case initrdPath = "initrd_path"
    }

    init(from decoder: Decoder) throws {
        try Self.assertKnownKeys(decoder: decoder)
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.path = try c.decode(String.self, forKey: .path)
        self.cmdline = try c.decode(String.self, forKey: .cmdline)
        self.initrdPath = try c.decodeIfPresent(String.self, forKey: .initrdPath)
    }
}

// MARK: - Resources

struct ResourceConfig: Decodable, StrictKeys {
    let cpuCount: Int
    let memoryMib: UInt64

    static let knownKeys: Set<String> = ["cpu_count", "memory_mib"]

    enum CodingKeys: String, CodingKey {
        case cpuCount = "cpu_count"
        case memoryMib = "memory_mib"
    }

    init(from decoder: Decoder) throws {
        try Self.assertKnownKeys(decoder: decoder)
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.cpuCount = try c.decode(Int.self, forKey: .cpuCount)
        self.memoryMib = try c.decode(UInt64.self, forKey: .memoryMib)
    }

    var memoryBytes: UInt64 { memoryMib * 1024 * 1024 }
}

// MARK: - Disks

struct DiskConfig: Decodable, StrictKeys {
    let id: String
    let path: String
    let readOnly: Bool

    static let knownKeys: Set<String> = ["id", "path", "read_only"]

    enum CodingKeys: String, CodingKey {
        case id
        case path
        case readOnly = "read_only"
    }

    init(from decoder: Decoder) throws {
        try Self.assertKnownKeys(decoder: decoder)
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(String.self, forKey: .id)
        self.path = try c.decode(String.self, forKey: .path)
        self.readOnly = try c.decode(Bool.self, forKey: .readOnly)
    }
}

// MARK: - virtio-fs

struct VirtioFsShare: Decodable, StrictKeys {
    let tag: String
    let hostPath: String
    let readOnly: Bool

    static let knownKeys: Set<String> = ["tag", "host_path", "read_only"]

    enum CodingKeys: String, CodingKey {
        case tag
        case hostPath = "host_path"
        case readOnly = "read_only"
    }

    init(from decoder: Decoder) throws {
        try Self.assertKnownKeys(decoder: decoder)
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.tag = try c.decode(String.self, forKey: .tag)
        self.hostPath = try c.decode(String.self, forKey: .hostPath)
        self.readOnly = try c.decode(Bool.self, forKey: .readOnly)
    }
}

// MARK: - vsock

struct VsockConfig: Decodable, StrictKeys {
    let ports: [UInt32]
    let socketDir: String

    static let knownKeys: Set<String> = ["ports", "socket_dir"]

    enum CodingKeys: String, CodingKey {
        case ports
        case socketDir = "socket_dir"
    }

    init(from decoder: Decoder) throws {
        try Self.assertKnownKeys(decoder: decoder)
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.ports = try c.decode([UInt32].self, forKey: .ports)
        self.socketDir = try c.decode(String.self, forKey: .socketDir)
    }
}

// MARK: - Network

enum NetworkConfig: Decodable {
    /// Plan 102 W6.A.5 — `eventsIngestSocketPath` is where the
    /// supervisor's claim-10 audit bridge listens for NDJSON
    /// `FlowEventWire` entries. `nil` means the Rust side did not
    /// request a bridge (legacy / dev mode); the data-plane fd
    /// goes straight from gvproxy to Vz with no FlowEvent
    /// emission. When `Some`, `Network.makeAttachment` interposes
    /// a socketpair between Vz and gvproxy and emits the
    /// handshake + FlowOpened / FlowClosed lines down a stream
    /// connection to that path.
    case gvproxy(
        socketPath: String,
        mac: MacAddress,
        eventsIngestSocketPath: String?
    )

    enum Kind: String, Decodable {
        case gvproxy
    }

    enum CodingKeys: String, CodingKey {
        case kind
        case socketPath = "socket_path"
        case mac
        case eventsIngestSocketPath = "events_ingest_socket_path"
    }

    static let knownKeys: Set<String> = [
        "kind", "socket_path", "mac", "events_ingest_socket_path",
    ]

    init(from decoder: Decoder) throws {
        // Reuse strict-keys helper via free function (enum can't
        // conform to StrictKeys directly because it lacks a stored
        // type-level anchor).
        try checkStrictKeys(decoder: decoder, knownKeys: Self.knownKeys)
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try c.decode(Kind.self, forKey: .kind)
        switch kind {
        case .gvproxy:
            let socketPath = try c.decode(String.self, forKey: .socketPath)
            let macString = try c.decode(String.self, forKey: .mac)
            guard let mac = MacAddress(string: macString) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .mac,
                    in: c,
                    debugDescription: "invalid MAC address: \(macString)"
                )
            }
            let eventsIngest = try c.decodeIfPresent(
                String.self, forKey: .eventsIngestSocketPath
            )
            self = .gvproxy(
                socketPath: socketPath,
                mac: mac,
                eventsIngestSocketPath: eventsIngest
            )
        }
    }
}

struct MacAddress: Equatable {
    let asArray: [UInt8]

    init?(string: String) {
        let parts = string.split(separator: ":")
        guard parts.count == 6 else { return nil }
        var values: [UInt8] = []
        for part in parts {
            guard part.count == 2, let v = UInt8(part, radix: 16) else { return nil }
            values.append(v)
        }
        // Require locally-administered bit (0x02) on the first octet so
        // we don't collide with real hardware MAC allocations. Matches
        // the libkrun supervisor's contract.
        guard values[0] & 0x02 != 0 else { return nil }
        self.asArray = values
    }
}

// MARK: - Balloon

struct BalloonConfig: Decodable, StrictKeys {
    let enabled: Bool
    let floorMib: UInt64

    static let knownKeys: Set<String> = ["enabled", "floor_mib"]

    enum CodingKeys: String, CodingKey {
        case enabled
        case floorMib = "floor_mib"
    }

    init(from decoder: Decoder) throws {
        try Self.assertKnownKeys(decoder: decoder)
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.enabled = try c.decode(Bool.self, forKey: .enabled)
        self.floorMib = try c.decode(UInt64.self, forKey: .floorMib)
    }
}

// MARK: - Strict-keys helper

/// Decodable types with a deny-unknown-fields contract.
///
/// Conformers expose a `knownKeys` set; `assertKnownKeys` is called
/// from the custom `init(from:)` before any field decoding. ADR-002
/// claim 5: equivalent to Rust's `#[serde(deny_unknown_fields)]`.
protocol StrictKeys {
    static var knownKeys: Set<String> { get }
}

extension StrictKeys {
    static func assertKnownKeys(decoder: Decoder) throws {
        try checkStrictKeys(decoder: decoder, knownKeys: knownKeys)
    }
}

/// Free function so non-StrictKeys conformers (currently
/// `NetworkConfig`) can reuse the same check.
func checkStrictKeys(decoder: Decoder, knownKeys: Set<String>) throws {
    struct RawKey: CodingKey {
        let stringValue: String
        let intValue: Int? = nil
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }
    let c = try decoder.container(keyedBy: RawKey.self)
    for key in c.allKeys {
        if !knownKeys.contains(key.stringValue) {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "unknown field: \(key.stringValue)"
                )
            )
        }
    }
}
