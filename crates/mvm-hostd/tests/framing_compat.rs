//! The legacy hostd path remains the same framing API as core.

use mvm_core::framing as core;
use mvm_hostd::framing as hostd;

const WIRE: &[u8] = b"\0\0\0\x017";

#[tokio::test]
async fn both_paths_exchange_the_same_wire_bytes() {
    assert_eq!(hostd::FRAME_LEN_BYTES, core::FRAME_LEN_BYTES);
    assert_eq!(
        hostd::DEFAULT_MAX_FRAME_BYTES,
        core::DEFAULT_MAX_FRAME_BYTES
    );

    let mut bytes = Vec::new();
    hostd::write_json_frame(&mut bytes, &7u8).await.unwrap();
    assert_eq!(bytes, WIRE);
    let mut reader = std::io::Cursor::new(bytes);
    assert_eq!(
        core::read_json_frame::<_, u8>(&mut reader, 1)
            .await
            .unwrap(),
        7
    );

    let mut bytes = Vec::new();
    core::write_json_frame(&mut bytes, &7u8).await.unwrap();
    assert_eq!(bytes, WIRE);
    let mut reader = std::io::Cursor::new(bytes);
    assert_eq!(
        hostd::read_json_frame::<_, u8>(&mut reader, 1)
            .await
            .unwrap(),
        7
    );
}

#[tokio::test]
async fn facade_preserves_error_identity_and_caller_cap() {
    let mut reader = std::io::Cursor::new(WIRE);
    let error: core::FrameError = hostd::read_json_frame::<_, u8>(&mut reader, 0)
        .await
        .unwrap_err();
    let error: hostd::FrameError = error;
    assert!(matches!(
        error,
        core::FrameError::TooLarge { size: 1, cap: 0 }
    ));
    assert_eq!(reader.position(), 4);
}
