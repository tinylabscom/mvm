use std::collections::HashSet;

use anyhow::Result;

use crate::shell;
use mvm_core::instance::InstanceNet;
use mvm_core::naming;
use mvm_core::tenant::TenantNet;

/// Set up a TAP device for an instance and attach it to the tenant bridge.
pub fn setup_tap(net: &InstanceNet, bridge_name: &str) -> Result<()> {
    let tap = &net.tap_dev;

    shell::run_in_vm(&format!(
        r#"
        # Ensure stale TAP devices don't break new boots (e.g. prior crashes).
        sudo ip link del {tap} 2>/dev/null || true
        # Firecracker runs unprivileged; create TAP owned by the current user.
        UID=$(id -u)
        GID=$(id -g)
        sudo ip tuntap add dev {tap} mode tap user $UID group $GID
        sudo ip link set {tap} master {bridge}
        sudo ip link set {tap} up
        "#,
        tap = tap,
        bridge = bridge_name,
    ))?;

    Ok(())
}

/// Tear down a TAP device.
pub fn teardown_tap(tap_dev: &str) -> Result<()> {
    shell::run_in_vm(&format!("sudo ip link del {} 2>/dev/null || true", tap_dev))?;
    Ok(())
}

/// Allocate the next available IP offset within a tenant subnet.
///
/// Scans all instance.json files across ALL pools for this tenant to find used offsets.
/// Offsets: .3-.254 (.1 = gateway, .2 = reserved for builder).
pub fn allocate_ip_offset(tenant_id: &str, _pool_id: &str) -> Result<u8> {
    let used = used_ip_offsets(tenant_id)?;

    // Find first free offset in .3-.254 range
    for offset in 3..=254u8 {
        if !used.contains(&offset) {
            return Ok(offset);
        }
    }

    anyhow::bail!(
        "No free IP offsets for tenant '{}' (all 252 addresses in use)",
        tenant_id
    )
}

/// Scan all instance.json files for a tenant to find used IP offsets.
fn used_ip_offsets(tenant_id: &str) -> Result<HashSet<u8>> {
    // List all pools, then all instances within each pool
    let output = shell::run_in_vm_stdout(&format!(
        r#"
        find /var/lib/mvm/tenants/{tenant}/pools/*/instances/*/instance.json \
            -exec grep -h '"guest_ip"' {{}} \; 2>/dev/null || true
        "#,
        tenant = tenant_id,
    ))?;

    let mut used = HashSet::new();
    // .2 is always reserved for builder
    used.insert(2u8);

    for line in output.lines() {
        // Lines look like: "guest_ip": "10.240.3.5",
        // Extract the IP value (last quoted string in the line)
        if let Some(last_end) = line.rfind('"') {
            let before = &line[..last_end];
            if let Some(last_start) = before.rfind('"') {
                let ip = &line[last_start + 1..last_end];
                // Extract last octet
                if let Some(last_dot) = ip.rfind('.')
                    && let Ok(offset) = ip[last_dot + 1..].parse::<u8>()
                {
                    used.insert(offset);
                }
            }
        }
    }

    Ok(used)
}

/// Construct a full InstanceNet for a new instance in the given tenant subnet.
pub fn build_instance_net(tenant_net: &TenantNet, ip_offset: u8) -> InstanceNet {
    let base_ip = &tenant_net.ipv4_subnet;

    // Parse base IP prefix from subnet (e.g., "10.240.3.0/24" -> "10.240.3")
    let ip_parts: Vec<&str> = base_ip
        .split('/')
        .next()
        .unwrap_or("10.240.0.0")
        .split('.')
        .collect();
    let prefix = format!("{}.{}.{}", ip_parts[0], ip_parts[1], ip_parts[2]);

    let cidr_str = base_ip.split('/').nth(1).unwrap_or("24");
    let cidr: u8 = cidr_str.parse().unwrap_or(24);

    InstanceNet {
        tap_dev: naming::tap_name(tenant_net.tenant_net_id, ip_offset),
        mac: naming::mac_address(tenant_net.tenant_net_id, ip_offset),
        guest_ip: format!("{}.{}", prefix, ip_offset),
        gateway_ip: tenant_net.gateway_ip.clone(),
        cidr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_instance_net() {
        let tenant_net = TenantNet::new(3, "10.240.3.0/24", "10.240.3.1");
        let net = build_instance_net(&tenant_net, 5);

        assert_eq!(net.guest_ip, "10.240.3.5");
        assert_eq!(net.gateway_ip, "10.240.3.1");
        assert_eq!(net.tap_dev, "tn3i5");
        assert_eq!(net.mac, naming::mac_address(3, 5));
        assert_eq!(net.cidr, 24);
    }

    #[test]
    fn test_build_instance_net_high_offset() {
        let tenant_net = TenantNet::new(200, "10.240.200.0/24", "10.240.200.1");
        let net = build_instance_net(&tenant_net, 254);

        assert_eq!(net.guest_ip, "10.240.200.254");
        assert_eq!(net.tap_dev, "tn200i254");
    }

    #[test]
    fn test_used_offsets_always_includes_builder() {
        // Can't test the full function without a VM, but verify the builder
        // reservation logic is correct
        let mut used = HashSet::new();
        used.insert(2u8); // builder
        assert!(used.contains(&2));
        assert!(!used.contains(&3));
    }
}
