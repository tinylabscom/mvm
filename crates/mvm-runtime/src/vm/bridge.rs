use anyhow::Result;
use serde::Serialize;

use crate::shell;
use mvm_core::tenant::TenantNet;

/// Ensure a per-tenant bridge exists with the coordinator-assigned subnet.
///
/// Idempotent: checks if bridge already exists before creating.
/// Bridge name: br-tenant-<tenant_net_id>
/// Gateway: first usable IP in subnet (e.g., 10.240.3.1/24)
pub fn ensure_tenant_bridge(net: &TenantNet) -> Result<()> {
    let bridge = &net.bridge_name;
    let gateway = &net.gateway_ip;
    let subnet = &net.ipv4_subnet;

    // Parse CIDR prefix length from subnet
    let cidr = subnet.split('/').nth(1).unwrap_or("24");

    shell::run_in_vm(&format!(
        r#"
        # Enable IP forwarding (idempotent)
        sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward' 2>/dev/null || true

        # Create bridge if it doesn't exist
        if ! ip link show {bridge} >/dev/null 2>&1; then
            sudo ip link add {bridge} type bridge
            sudo ip addr add {gateway}/{cidr} dev {bridge}
            sudo ip link set {bridge} up
        fi

        # Ensure NAT rules exist (idempotent with -C check)
        sudo iptables -t nat -C POSTROUTING -s {subnet} ! -o {bridge} -j MASQUERADE 2>/dev/null || \
            sudo iptables -t nat -A POSTROUTING -s {subnet} ! -o {bridge} -j MASQUERADE

        sudo iptables -C FORWARD -i {bridge} ! -o {bridge} -j ACCEPT 2>/dev/null || \
            sudo iptables -A FORWARD -i {bridge} ! -o {bridge} -j ACCEPT

        sudo iptables -C FORWARD ! -i {bridge} -o {bridge} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
            sudo iptables -A FORWARD ! -i {bridge} -o {bridge} -m state --state RELATED,ESTABLISHED -j ACCEPT
        "#,
        bridge = bridge,
        gateway = gateway,
        cidr = cidr,
        subnet = subnet,
    ))?;

    Ok(())
}

/// Destroy a tenant bridge and its NAT rules.
pub fn destroy_tenant_bridge(net: &TenantNet) -> Result<()> {
    let bridge = &net.bridge_name;
    let subnet = &net.ipv4_subnet;

    shell::run_in_vm(&format!(
        r#"
        sudo ip link set {bridge} down 2>/dev/null || true
        sudo ip link del {bridge} 2>/dev/null || true

        sudo iptables -t nat -D POSTROUTING -s {subnet} ! -o {bridge} -j MASQUERADE 2>/dev/null || true
        sudo iptables -D FORWARD -i {bridge} ! -o {bridge} -j ACCEPT 2>/dev/null || true
        sudo iptables -D FORWARD ! -i {bridge} -o {bridge} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
        "#,
        bridge = bridge,
        subnet = subnet,
    ))?;

    Ok(())
}

/// Full network health report for a tenant bridge.
#[derive(Debug, Serialize)]
pub struct BridgeReport {
    pub tenant_id: String,
    pub bridge_name: String,
    pub subnet: String,
    pub gateway: String,
    pub bridge_exists: bool,
    pub bridge_up: bool,
    pub gateway_assigned: bool,
    pub nat_masquerade: bool,
    pub forward_outbound: bool,
    pub forward_established: bool,
    pub tap_devices: Vec<String>,
    pub issues: Vec<String>,
}

/// Verify a tenant bridge is correctly configured.
/// Returns a detailed report of all checks.
pub fn verify_tenant_bridge(net: &TenantNet) -> Result<Vec<String>> {
    let report = full_bridge_report("", net)?;
    Ok(report.issues)
}

/// Generate a full bridge health report for a tenant.
pub fn full_bridge_report(tenant_id: &str, net: &TenantNet) -> Result<BridgeReport> {
    let bridge = &net.bridge_name;
    let subnet = &net.ipv4_subnet;
    let cidr = subnet.split('/').nth(1).unwrap_or("24");
    let expected_gateway = format!("{}/{}", net.gateway_ip, cidr);

    let mut report = BridgeReport {
        tenant_id: tenant_id.to_string(),
        bridge_name: bridge.clone(),
        subnet: subnet.clone(),
        gateway: net.gateway_ip.clone(),
        bridge_exists: false,
        bridge_up: false,
        gateway_assigned: false,
        nat_masquerade: false,
        forward_outbound: false,
        forward_established: false,
        tap_devices: Vec::new(),
        issues: Vec::new(),
    };

    // Check 1: Bridge exists
    let exists = shell::run_in_vm_stdout(&format!(
        "ip link show {} >/dev/null 2>&1 && echo yes || echo no",
        bridge
    ))?;
    report.bridge_exists = exists.trim() == "yes";

    if !report.bridge_exists {
        report
            .issues
            .push(format!("Bridge {} does not exist", bridge));
        return Ok(report);
    }

    // Check 2: Bridge is UP
    let state = shell::run_in_vm_stdout(&format!(
        "ip link show {} | grep -oP '(?<=state )\\w+'",
        bridge
    ))?;
    report.bridge_up = state.trim() == "UP";
    if !report.bridge_up {
        report.issues.push(format!(
            "Bridge {} is not UP (state: {})",
            bridge,
            state.trim()
        ));
    }

    // Check 3: Gateway IP assigned
    let addrs = shell::run_in_vm_stdout(&format!(
        "ip addr show dev {} | grep 'inet ' | awk '{{print $2}}'",
        bridge
    ))?;
    report.gateway_assigned = addrs.contains(&expected_gateway);
    if !report.gateway_assigned {
        report.issues.push(format!(
            "Bridge {} missing gateway {} (found: {})",
            bridge,
            expected_gateway,
            addrs.trim()
        ));
    }

    // Check 4: NAT masquerade rule
    let nat = shell::run_in_vm_stdout(&format!(
        "sudo iptables -t nat -C POSTROUTING -s {} ! -o {} -j MASQUERADE 2>&1 && echo yes || echo no",
        subnet, bridge
    ))?;
    report.nat_masquerade = nat.trim().ends_with("yes");
    if !report.nat_masquerade {
        report.issues.push(format!(
            "Missing NAT masquerade rule for {} on {}",
            subnet, bridge
        ));
    }

    // Check 5: Forward outbound rule
    let fwd_out = shell::run_in_vm_stdout(&format!(
        "sudo iptables -C FORWARD -i {} ! -o {} -j ACCEPT 2>&1 && echo yes || echo no",
        bridge, bridge
    ))?;
    report.forward_outbound = fwd_out.trim().ends_with("yes");
    if !report.forward_outbound {
        report
            .issues
            .push(format!("Missing FORWARD outbound rule for {}", bridge));
    }

    // Check 6: Forward established rule
    let fwd_est = shell::run_in_vm_stdout(&format!(
        "sudo iptables -C FORWARD ! -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>&1 && echo yes || echo no",
        bridge, bridge
    ))?;
    report.forward_established = fwd_est.trim().ends_with("yes");
    if !report.forward_established {
        report
            .issues
            .push(format!("Missing FORWARD established rule for {}", bridge));
    }

    // Check 7: List TAP devices attached to this bridge
    let taps = shell::run_in_vm_stdout(&format!(
        "ls /sys/class/net/{}/brif/ 2>/dev/null || true",
        bridge
    ))?;
    report.tap_devices = taps
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();

    // Check 8: Verify TAP devices belong to this tenant (name prefix tn<net_id>)
    let expected_tap_prefix = format!("tn{}", net.tenant_net_id);
    for tap in &report.tap_devices {
        if !tap.starts_with(&expected_tap_prefix) {
            report.issues.push(format!(
                "TAP {} attached to {} but doesn't match tenant net_id {} (expected prefix {})",
                tap, bridge, net.tenant_net_id, expected_tap_prefix
            ));
        }
    }

    // Check 9: Verify no cross-bridge forwarding (explicit DROP for inter-bridge traffic)
    let cross_bridge_check = shell::run_in_vm_stdout(&format!(
        r#"
        # Check if there's a DROP rule for cross-bridge forwarding
        # We verify that other tenant bridges can't forward to this one
        OTHER_BRIDGES=$(ip link show type bridge 2>/dev/null | grep -oP '(?<=: )\S+(?=:)' | grep -v {bridge} || true)
        ISSUE=""
        for other in $OTHER_BRIDGES; do
            if sudo iptables -C FORWARD -i "$other" -o {bridge} -j DROP 2>/dev/null; then
                : # Good, drop rule exists
            else
                ISSUE="$ISSUE cross-bridge:$other->$bridge"
            fi
        done
        echo "$ISSUE"
        "#,
        bridge = bridge,
    ))?;
    let cross_issues = cross_bridge_check.trim();
    if !cross_issues.is_empty() {
        report
            .issues
            .push(format!("Missing cross-bridge DROP rules: {}", cross_issues));
    }

    Ok(report)
}

/// Deep verification: inspect iptables rule content for a tenant bridge.
/// Returns detailed rule listings for manual audit.
pub fn deep_verify_bridge(net: &TenantNet) -> Result<String> {
    let bridge = &net.bridge_name;
    let subnet = &net.ipv4_subnet;

    shell::run_in_vm_stdout(&format!(
        r#"
        echo "=== Bridge: {bridge} ==="
        echo "--- Interface ---"
        ip addr show dev {bridge} 2>/dev/null || echo "NOT FOUND"
        echo ""
        echo "--- TAP devices ---"
        ls /sys/class/net/{bridge}/brif/ 2>/dev/null || echo "none"
        echo ""
        echo "--- NAT rules for {subnet} ---"
        sudo iptables -t nat -L POSTROUTING -v -n 2>/dev/null | grep '{subnet}' || echo "none"
        echo ""
        echo "--- FORWARD rules for {bridge} ---"
        sudo iptables -L FORWARD -v -n 2>/dev/null | grep '{bridge}' || echo "none"
        echo ""
        echo "--- ARP table ---"
        arp -n -i {bridge} 2>/dev/null || echo "none"
        "#,
        bridge = bridge,
        subnet = subnet,
    ))
}
