pub(crate) use mvm_client::builder_images::bootstrap::{
    bootstrap_builder_vm_image, bootstrap_tool_builder_vm_image, builder_vm_host_arch,
    selected_local_checkout,
};

#[cfg(test)]
pub(super) fn first_nameserver_from_resolv_conf(body: &str) -> Option<String> {
    mvm_agentd::guest_net::first_nameserver_from_resolv_conf(body)
}
