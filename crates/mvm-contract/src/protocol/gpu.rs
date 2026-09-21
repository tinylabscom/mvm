//! GPU compute by API remoting: the wire contract between the guest shim
//! libraries and the host endpoint that owns the GPU.
//!
//! The guest carries no driver and no device nodes — three drop-in shim
//! libraries (`libcuda.so.1`, `libcudart.so`, `libnvidia-ml.so.1`)
//! implement the CUDA C ABI by forwarding each call over the guest's
//! vsock to a per-VM host process, which runs it against a [`GpuBackend`]
//! (the real driver when a GPU is present, a deterministic stub otherwise).
//! This module is the one definition of what those frames mean, shared by
//! the guest shims and the host endpoint so the two ends cannot drift.
//!
//! Everything here is `no_std + alloc` and `forbid(unsafe_code)` like the
//! rest of the crate: the guest side links into the runtime overlay and
//! cannot reach host-only crates.
//!
//! Security shape: the endpoint only ever parses frames that already passed
//! the length cap below, and every handle it mints (contexts, device
//! pointers, modules, functions) is an opaque `u64` meaningful only inside
//! that one endpoint process. A guest that forges a handle gets the same
//! answer as a guest that never saw it: a refusal, never a host address.

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// The vsock port the guest's shim libraries dial to reach the host GPU
/// endpoint.
///
/// Lives here rather than in `mvm-net` because both ends need it and the
/// guest shims link only this crate: `mvm_net::GuestService::Gpu` maps to
/// this constant, so host and guest name one value instead of two literals
/// that can drift — the same arrangement `network_flow::NETWORK_FLOW_PORT`
/// already uses.
pub const GPU_RPC_PORT: u32 = 5256;

/// Wire version of the request/response enums. A frame carrying any other
/// version is refused before its body is looked at.
pub const PROTOCOL_VERSION: u32 = 1;

/// Hard ceiling on one frame's payload, in bytes. Kernel-param blobs,
/// module images (PTX or cubin), and device-memory transfers all ride
/// these frames; 64 MiB is far past any sane v1 exchange and bounds the
/// allocation a hostile guest can force before its bytes are believed.
pub const MAX_MESSAGE_LEN: u64 = 64 * 1024 * 1024;

/// Maximum number of kernel parameters one launch may carry. The driver
/// ABI itself bounds real kernels well below this.
pub const MAX_KERNEL_PARAMS: usize = 256;

/// Maximum byte size of one kernel parameter blob. Scalar and small-vector
/// parameters are the supported shape; a "parameter" bigger than this is a
/// transfer wearing a parameter's clothes.
pub const MAX_PARAM_LEN: u64 = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Error codes (numeric values pinned to the public CUDA/NVML headers, so a
// shim answer is indistinguishable from the real library's)
// ---------------------------------------------------------------------------

/// `CUDA_SUCCESS` / `cudaSuccess` / `NVML_SUCCESS`.
pub const SUCCESS: i32 = 0;

// CUDA driver (`CUresult`) subset.
pub const CUDA_ERROR_INVALID_VALUE: i32 = 1;
pub const CUDA_ERROR_OUT_OF_MEMORY: i32 = 2;
pub const CUDA_ERROR_NOT_INITIALIZED: i32 = 3;
pub const CUDA_ERROR_DEINITIALIZED: i32 = 4;
pub const CUDA_ERROR_STUB_LIBRARY: i32 = 34;
pub const CUDA_ERROR_NO_DEVICE: i32 = 100;
pub const CUDA_ERROR_INVALID_DEVICE: i32 = 101;
pub const CUDA_ERROR_INVALID_CONTEXT: i32 = 201;
pub const CUDA_ERROR_INVALID_IMAGE: i32 = 200;
pub const CUDA_ERROR_INVALID_PTX: i32 = 218;
pub const CUDA_ERROR_INVALID_SOURCE: i32 = 300;
pub const CUDA_ERROR_FILE_NOT_FOUND: i32 = 301;
pub const CUDA_ERROR_SHARED_OBJECT_SYMBOL_NOT_FOUND: i32 = 302;
pub const CUDA_ERROR_SHARED_OBJECT_INIT_FAILED: i32 = 303;
pub const CUDA_ERROR_INVALID_HANDLE: i32 = 400;
pub const CUDA_ERROR_NOT_FOUND: i32 = 500;
pub const CUDA_ERROR_NOT_READY: i32 = 600;
pub const CUDA_ERROR_LAUNCH_OUT_OF_RESOURCES: i32 = 701;
pub const CUDA_ERROR_LAUNCH_FAILED: i32 = 719;
pub const CUDA_ERROR_NOT_SUPPORTED: i32 = 801;
pub const CUDA_ERROR_UNKNOWN: i32 = 999;

// CUDA runtime (`cudaError_t`) subset. Distinct unit from the driver's: the
// runtime numbers its errors on its own scale even where meanings coincide.
pub const CUDA_ERROR_RUNTIME_INVALID_VALUE: i32 = 1;
pub const CUDA_ERROR_RUNTIME_MEMORY_ALLOCATION: i32 = 2;
pub const CUDA_ERROR_RUNTIME_INITIALIZATION: i32 = 3;
pub const CUDA_ERROR_RUNTIME_INVALID_DEVICE_POINTER: i32 = 17;
pub const CUDA_ERROR_RUNTIME_INVALID_MEMCPY_DIRECTION: i32 = 21;
pub const CUDA_ERROR_RUNTIME_INSUFFICIENT_DRIVER: i32 = 35;
pub const CUDA_ERROR_RUNTIME_NO_DEVICE: i32 = 38;
pub const CUDA_ERROR_RUNTIME_NOT_SUPPORTED: i32 = 801;
pub const CUDA_ERROR_RUNTIME_UNKNOWN: i32 = 999;

// NVML (`nvmlReturn_t`) subset.
pub const NVML_ERROR_UNINITIALIZED: i32 = 1;
pub const NVML_ERROR_INVALID_ARGUMENT: i32 = 2;
pub const NVML_ERROR_NOT_SUPPORTED: i32 = 3;
pub const NVML_ERROR_NOT_FOUND: i32 = 6;
pub const NVML_ERROR_INSUFFICIENT_SIZE: i32 = 7;
pub const NVML_ERROR_UNKNOWN: i32 = 999;

// ---------------------------------------------------------------------------
// Wire errors
// ---------------------------------------------------------------------------

/// Why a frame could not be encoded or decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GpuWireError {
    /// The payload length prefix named more bytes than the cap allows. The
    /// cap is checked before any allocation sized by the peer.
    #[error("frame length {0} exceeds the {MAX_MESSAGE_LEN}-byte cap")]
    LengthCapExceeded(u64),
    /// The frame's declared length disagreed with the bytes actually
    /// present — a truncated or desynced stream.
    #[error("frame declared {declared} bytes but {actual} were present")]
    LengthMismatch { declared: u64, actual: u64 },
    /// The frame body was not the JSON the wire contract defines.
    #[error("frame body did not parse: {0}")]
    MalformedBody(String),
}

/// A remote failure. `code` is always in the API's own unit (a `CUresult`
/// value, a `cudaError_t` value, or an `nvmlReturn_t` value), so the shim
/// can return it to the workload unmodified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuError {
    pub code: i32,
    pub message: String,
}

impl GpuError {
    /// Build a wire error with a human-readable explanation.
    #[must_use]
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Requests and responses
// ---------------------------------------------------------------------------

/// One guest → host GPU call.
///
/// Handles are the opaque `u64` values the endpoint minted in response to an
/// earlier request on the same connection. The runtime half of the API is
/// lowered onto these driver-shaped operations server-side, so the wire
/// carries one vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "op",
    content = "args",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum GpuRequest {
    // Driver lifecycle and device enumeration.
    DriverGetVersion,
    DeviceGetCount,
    DeviceGetName {
        ordinal: u32,
    },
    DeviceTotalMem {
        ordinal: u32,
    },
    // Contexts.
    ContextCreate {
        ordinal: u32,
    },
    ContextDestroy {
        context: u64,
    },
    Synchronize {
        context: u64,
    },
    // Device memory.
    MemAlloc {
        context: u64,
        bytes: u64,
    },
    MemFree {
        context: u64,
        ptr: u64,
    },
    MemcpyHtoD {
        context: u64,
        dst: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    MemcpyDtoH {
        context: u64,
        src: u64,
        len: u64,
    },
    MemsetD8 {
        context: u64,
        dst: u64,
        value: u8,
        len: u64,
    },
    // Modules and launches.
    ModuleLoad {
        context: u64,
        #[serde(with = "serde_bytes")]
        image: Vec<u8>,
    },
    ModuleUnload {
        context: u64,
        module: u64,
    },
    ModuleGetFunction {
        context: u64,
        module: u64,
        name: String,
    },
    LaunchKernel {
        context: u64,
        function: u64,
        grid: [u32; 3],
        block: [u32; 3],
        shared_mem_bytes: u32,
        /// Each entry is one kernel argument's raw little-endian bytes,
        /// exactly as the kernel signature expects it laid out.
        #[serde(with = "serde_bytes_vec")]
        params: Vec<Vec<u8>>,
    },
    // NVML device queries, backing the `libnvidia-ml.so.1` shim.
    NvmlDeviceGetCount,
    NvmlSystemGetDriverVersion,
    NvmlDeviceGetName {
        ordinal: u32,
    },
    NvmlDeviceGetMemoryInfo {
        ordinal: u32,
    },
    NvmlDeviceGetUtilizationRates {
        ordinal: u32,
    },
    NvmlDeviceGetCudaComputeCapability {
        ordinal: u32,
    },
}

/// The host's answer to one [`GpuRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "op",
    content = "result",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum GpuResponse {
    Ok,
    Err(GpuError),
    DriverVersion {
        version: i32,
    },
    DeviceCount {
        count: u32,
    },
    DeviceName {
        name: String,
    },
    DeviceTotalMem {
        bytes: u64,
    },
    ContextCreated {
        context: u64,
    },
    DevicePointer {
        ptr: u64,
    },
    Data {
        #[serde(with = "serde_bytes")]
        bytes: Vec<u8>,
    },
    ModuleLoaded {
        module: u64,
    },
    Function {
        handle: u64,
    },
    NvmlDeviceCount {
        count: u32,
    },
    NvmlDriverVersion {
        version: String,
    },
    NvmlMemoryInfo {
        total: u64,
        free: u64,
        used: u64,
    },
    NvmlUtilization {
        gpu: u32,
        memory: u32,
    },
    NvmlComputeCapability {
        major: i32,
        minor: i32,
    },
}

// ---------------------------------------------------------------------------
// Length-prefixed JSON framing
// ---------------------------------------------------------------------------

/// Encode one message as a `u32` big-endian length prefix followed by the
/// JSON body. The length includes only the body, not the prefix.
///
/// Returns [`GpuWireError::LengthCapExceeded`] rather than emitting an
/// oversized frame when the body would not fit the cap.
pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>, GpuWireError> {
    let body = serde_json::to_vec(msg)
        .map_err(|e| GpuWireError::MalformedBody(format!("serialize: {e}")))?;
    let len = u64::try_from(body.len()).unwrap_or(u64::MAX);
    if len > MAX_MESSAGE_LEN {
        return Err(GpuWireError::LengthCapExceeded(len));
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// The body length named by a 4-byte big-endian prefix. No validation that
/// the prefix is a full frame — the caller reads the prefix first, then
/// exactly this many body bytes, then hands both to [`decode_frame`].
#[must_use]
pub fn frame_body_len(prefix: [u8; 4]) -> u64 {
    u64::from(u32::from_be_bytes(prefix))
}

/// Decode one complete frame (4-byte prefix + body) into a message.
pub fn decode_frame<T: serde::de::DeserializeOwned>(frame: &[u8]) -> Result<T, GpuWireError> {
    if frame.len() < 4 {
        return Err(GpuWireError::LengthMismatch {
            declared: frame_body_len([0; 4]),
            actual: frame.len() as u64,
        });
    }
    let declared = frame_body_len(frame[..4].try_into().expect("4-byte prefix"));
    if declared > MAX_MESSAGE_LEN {
        return Err(GpuWireError::LengthCapExceeded(declared));
    }
    let actual = frame.len() as u64 - 4;
    if declared != actual {
        return Err(GpuWireError::LengthMismatch { declared, actual });
    }
    serde_json::from_slice(&frame[4..]).map_err(|e| GpuWireError::MalformedBody(e.to_string()))
}

/// `serde` adapter for a bare byte vector as a JSON array of numbers — no
/// base64, so a frame stays debuggable with any JSON tool.
pub(crate) mod serde_bytes {
    use alloc::vec::Vec;

    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq as _};

    pub fn serialize<S: Serializer>(bytes: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        let mut seq = ser.serialize_seq(Some(bytes.len()))?;
        for b in bytes {
            seq.serialize_element(b)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(de)
    }
}

/// `serde` adapter for a vector of byte vectors, same no-base64 choice.
pub(crate) mod serde_bytes_vec {
    use alloc::vec::Vec;

    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq as _};

    pub fn serialize<S: Serializer>(blobs: &[Vec<u8>], ser: S) -> Result<S::Ok, S::Error> {
        let mut seq = ser.serialize_seq(Some(blobs.len()))?;
        for blob in blobs {
            seq.serialize_element(&ByteSeq(blob))?;
        }
        seq.end()
    }

    struct ByteSeq<'a>(&'a [u8]);

    impl serde::Serialize for ByteSeq<'_> {
        fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
            let mut seq = ser.serialize_seq(Some(self.0.len()))?;
            for b in self.0 {
                seq.serialize_element(b)?;
            }
            seq.end()
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<Vec<u8>>::deserialize(de)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> GpuRequest {
        GpuRequest::LaunchKernel {
            context: 7,
            function: 9,
            grid: [1, 2, 3],
            block: [4, 5, 6],
            shared_mem_bytes: 0,
            params: vec![vec![1, 0, 0, 0], vec![0xff; 8]],
        }
    }

    #[test]
    fn a_request_round_trips_through_its_frame() {
        let frame = encode_frame(&sample_request()).expect("encode");
        let back: GpuRequest = decode_frame(&frame).expect("decode");
        assert_eq!(back, sample_request());
    }

    #[test]
    fn a_response_round_trips_through_its_frame() {
        for response in [
            GpuResponse::Ok,
            GpuResponse::DriverVersion { version: 12_040 },
            GpuResponse::DeviceCount { count: 1 },
            GpuResponse::Err(GpuError::new(CUDA_ERROR_INVALID_VALUE, "bad handle")),
            GpuResponse::Data {
                bytes: vec![0xde, 0xad],
            },
            GpuResponse::NvmlComputeCapability { major: 7, minor: 5 },
        ] {
            let frame = encode_frame(&response).expect("encode");
            let back: GpuResponse = decode_frame(&frame).expect("decode");
            assert_eq!(back, response);
        }
    }

    #[test]
    fn a_frame_with_a_length_mismatch_is_refused() {
        let mut frame = encode_frame(&GpuResponse::Ok).expect("encode");
        frame.pop();
        let err = decode_frame::<GpuResponse>(&frame).expect_err("truncated frame");
        assert!(matches!(err, GpuWireError::LengthMismatch { .. }), "{err}");
    }

    #[test]
    fn a_frame_past_the_cap_is_refused_before_its_body_is_believed() {
        let over = u32::try_from(MAX_MESSAGE_LEN + 1).expect("cap + 1 fits u32");
        let prefix = over.to_be_bytes();
        let mut frame = prefix.to_vec();
        frame.extend_from_slice(&[0_u8; 8]);
        let err = decode_frame::<GpuResponse>(&frame).expect_err("oversized frame");
        assert_eq!(err, GpuWireError::LengthCapExceeded(u64::from(over)));
    }

    #[test]
    fn a_request_with_an_unknown_verb_is_refused() {
        let err = serde_json::from_str::<GpuRequest>(r#"{"op":"steal_the_gpu","args":null}"#)
            .expect_err("unknown verb must not parse");
        assert!(err.to_string().contains("unknown variant"), "{err}");
    }

    #[test]
    fn error_codes_match_the_public_cuda_and_nvml_headers() {
        // Pinned: the whole point of carrying numeric codes is that a
        // workload cannot tell the shim's answer from the real library's.
        assert_eq!(SUCCESS, 0);
        assert_eq!(CUDA_ERROR_INVALID_VALUE, 1);
        assert_eq!(CUDA_ERROR_OUT_OF_MEMORY, 2);
        assert_eq!(CUDA_ERROR_NO_DEVICE, 100);
        assert_eq!(CUDA_ERROR_INVALID_HANDLE, 400);
        assert_eq!(CUDA_ERROR_NOT_SUPPORTED, 801);
        assert_eq!(CUDA_ERROR_UNKNOWN, 999);
        assert_eq!(CUDA_ERROR_RUNTIME_INVALID_DEVICE_POINTER, 17);
        assert_eq!(CUDA_ERROR_RUNTIME_NO_DEVICE, 38);
        assert_eq!(NVML_ERROR_NOT_FOUND, 6);
        assert_eq!(NVML_ERROR_UNKNOWN, 999);
    }

    #[test]
    fn the_port_sits_in_the_free_52xx_guest_dial_range() {
        // Above the agent/egress/telemetry/display cluster (5251-5255),
        // below the 5300 broker, and below the 20000+ console range.
        const { assert!(GPU_RPC_PORT > 5255 && GPU_RPC_PORT < 5300) };
    }
}
