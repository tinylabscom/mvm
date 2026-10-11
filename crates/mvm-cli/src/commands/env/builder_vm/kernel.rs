pub(super) use mvm_client::builder_images::kernel::format_compile_start;
pub(crate) use mvm_client::builder_images::kernel::{
    KernelSource, KernelVariant, resolve_kernel_source,
};

pub(crate) fn build_kernel_via_stage0(
    variant: KernelVariant,
    verbose: bool,
) -> anyhow::Result<std::path::PathBuf> {
    let phase = crate::ui::activity::start(format_compile_start(
        variant.label(),
        super::builder_vm_host_arch(),
    ));
    let result = mvm_client::builder_images::kernel::build_kernel_via_stage0(variant, verbose)?;
    phase.finish();
    Ok(result)
}
