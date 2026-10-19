//! Host image-contract support, independent of image acquisition and VM launch.

/// Protocols this process can validate against its available boot payload.
pub fn current_image_set_protocol_support() -> mvm_core::image_set::HostProtocolSupport {
    #[cfg(test)]
    let builder_boot_abi = crate::builder_boot::payload_supported_abis();
    #[cfg(not(test))]
    let builder_boot_abi = crate::builder_boot::supported_image_abis();
    mvm_core::image_set::HostProtocolSupport {
        base_image_contract: mvm_core::image_set::BaseImageContractRange::SUPPORTED,
        builder_cache_contract: crate::builder_contract::BUILDER_VM_CACHE_CONTRACT_VERSION,
        builder_boot_abi,
    }
}
