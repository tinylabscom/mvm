use anyhow::Result;

use crate::config::*;
use crate::shell::run_in_vm_visible;
use crate::ui;

// ============================================================================
// Legacy dev-mode TAP networking (single VM, used by `mvm start/stop`)
// ============================================================================

/// Set up TAP networking, IP forwarding, and NAT inside the Lima VM.
pub fn setup() -> Result<()> {
    ui::info("Setting up network...");
    run_in_vm_visible(&format!(
        r#"
        set -euo pipefail

        # Create TAP device
        sudo ip link del {tap} 2>/dev/null || true
        sudo ip tuntap add dev {tap} mode tap
        sudo ip addr add {tap_ip}{mask} dev {tap}
        sudo ip link set dev {tap} up

        # Enable IP forwarding
        sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
        sudo iptables -P FORWARD ACCEPT

        # Determine host network interface
        HOST_IFACE=$(ip -j route list default | jq -r '.[0].dev')

        # NAT for internet access
        sudo iptables -t nat -D POSTROUTING -o "$HOST_IFACE" -j MASQUERADE 2>/dev/null || true
        sudo iptables -t nat -A POSTROUTING -o "$HOST_IFACE" -j MASQUERADE

        echo "[mvm] Network ready (tap={tap}, host=$HOST_IFACE)."
        "#,
        tap = TAP_DEV,
        tap_ip = TAP_IP,
        mask = MASK_SHORT,
    ))
}

/// Tear down TAP device and iptables rules.
pub fn teardown() -> Result<()> {
    run_in_vm_visible(&format!(
        r#"
        sudo ip link del {tap} 2>/dev/null || true
        HOST_IFACE=$(ip -j route list default 2>/dev/null | jq -r '.[0].dev' 2>/dev/null) || true
        if [ -n "$HOST_IFACE" ]; then
            sudo iptables -t nat -D POSTROUTING -o "$HOST_IFACE" -j MASQUERADE 2>/dev/null || true
        fi
        "#,
        tap = TAP_DEV,
    ))
}

// ============================================================================
// Bridge-based networking (multi-VM, used by `mvm run`)
// ============================================================================

/// Ensure the br-mvm bridge exists with IP and NAT configured.  Idempotent.
pub fn bridge_ensure() -> Result<()> {
    ui::info("Ensuring bridge network...");
    run_in_vm_visible(&format!(
        r#"
        set -euo pipefail

        # Create bridge if missing
        if ! ip link show {br} >/dev/null 2>&1; then
            sudo ip link add name {br} type bridge
            sudo ip addr add {br_cidr} dev {br}
            sudo ip link set dev {br} up
            echo "[mvm] Created bridge {br}"
        else
            echo "[mvm] Bridge {br} already exists"
        fi

        # Enable IP forwarding
        sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
        sudo iptables -P FORWARD ACCEPT

        # NAT: MASQUERADE traffic from the bridge subnet to the internet.
        # Use -C to check first so we don't duplicate the rule.
        HOST_IFACE=$(ip -j route list default | jq -r '.[0].dev')
        if ! sudo iptables -t nat -C POSTROUTING -s 172.16.0.0/24 -o "$HOST_IFACE" -j MASQUERADE 2>/dev/null; then
            sudo iptables -t nat -A POSTROUTING -s 172.16.0.0/24 -o "$HOST_IFACE" -j MASQUERADE
        fi

        echo "[mvm] Bridge network ready ({br}=$HOST_IFACE)."
        "#,
        br = BRIDGE_DEV,
        br_cidr = BRIDGE_CIDR,
    ))
}

/// Remove the bridge and associated NAT rules.
pub fn bridge_teardown() -> Result<()> {
    run_in_vm_visible(&format!(
        r#"
        sudo ip link del {br} 2>/dev/null || true
        HOST_IFACE=$(ip -j route list default 2>/dev/null | jq -r '.[0].dev' 2>/dev/null) || true
        if [ -n "$HOST_IFACE" ]; then
            sudo iptables -t nat -D POSTROUTING -s 172.16.0.0/24 -o "$HOST_IFACE" -j MASQUERADE 2>/dev/null || true
        fi
        "#,
        br = BRIDGE_DEV,
    ))
}

/// Create a TAP device for a VM slot and attach it to the bridge.
pub fn tap_create(slot: &VmSlot) -> Result<()> {
    ui::info(&format!(
        "Creating TAP {} for VM '{}'...",
        slot.tap_dev, slot.name
    ));
    run_in_vm_visible(&format!(
        r#"
        set -euo pipefail
        sudo ip link del {tap} 2>/dev/null || true
        sudo ip tuntap add dev {tap} mode tap
        sudo ip link set dev {tap} master {br}
        sudo ip link set dev {tap} up
        echo "[mvm] TAP {tap} attached to {br}"
        "#,
        tap = slot.tap_dev,
        br = BRIDGE_DEV,
    ))
}

/// Remove a TAP device for a VM slot.
pub fn tap_destroy(slot: &VmSlot) -> Result<()> {
    run_in_vm_visible(&format!(
        "sudo ip link del {tap} 2>/dev/null || true",
        tap = slot.tap_dev,
    ))
}

// ============================================================================
// Network policy enforcement (domain-based egress filtering)
// ============================================================================

/// Apply iptables-based network policy for a VM slot.
/// Must be called after `tap_create()`. No-op if the policy is unrestricted.
pub fn apply_network_policy(
    slot: &VmSlot,
    policy: &mvm_core::network_policy::NetworkPolicy,
) -> Result<()> {
    if let Some(script) = policy.iptables_script(BRIDGE_DEV, &slot.guest_ip) {
        ui::info(&format!(
            "Applying network policy for VM '{}'...",
            slot.name
        ));
        run_in_vm_visible(&format!("set -euo pipefail\n{}", script))
    } else {
        Ok(())
    }
}

/// Remove all network policy iptables rules for a VM slot.
/// Flushes any FORWARD rules matching this guest IP, regardless of what
/// policy was originally applied. Safe to call even if no policy was set.
pub fn cleanup_network_policy(slot: &VmSlot) -> Result<()> {
    run_in_vm_visible(&format!(
        "# Clean up all FORWARD rules for {ip}\n\
         while sudo iptables -D FORWARD -i {br} -s {ip} -j DROP 2>/dev/null; do :; done\n\
         while sudo iptables -D FORWARD -i {br} -s {ip} -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do :; done\n\
         while sudo iptables -D FORWARD -i {br} -s {ip} -p udp --dport 53 -j ACCEPT 2>/dev/null; do :; done\n\
         while sudo iptables -D FORWARD -i {br} -s {ip} -p tcp --dport 53 -j ACCEPT 2>/dev/null; do :; done\n\
         while sudo iptables -D FORWARD -i {br} -s {ip} -p tcp -j ACCEPT 2>/dev/null; do :; done\n",
        br = BRIDGE_DEV,
        ip = slot.guest_ip,
    ))
}
