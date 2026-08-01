//! Live end-to-end tests for the native-gateway datagram arm against a
//! real gateway subprocess (compat gateway / rvproxy) — no microVM, no
//! KVM. Split out of `native_gateway`'s own test module purely to keep
//! both files a manageable size; every test here is opt-in (env-gated)
//! and soft-skips when the gateway binary is absent.

use super::events::{FlowEventKind, audit_event_channel};
use super::native_gateway::{libkrun_reply_path, run_libkrun_native_gateway_bridge};
use super::test_support::{unrestricted_flow_policy, wiring_with};

// -----------------------------------------------------------------
// Live DHCP handshake through a REAL gateway
// (compat gateway / rvproxy). Opt-in (MVM_GATEWAY_DHCP_E2E=1); skips when
// unset or when the gateway binary is absent. Validates the macOS
// native-gateway datagram arm end-to-end against a real userspace gateway:
// no microVM, no KVM. Doubles as an rvproxy drop-in conformance check
// (point MVM_GATEWAY_BIN at it once it speaks the compat `-listen-vfkit`
// CLI + vfkit/DHCP contract — see rvproxy's GVPROXY_CONFORMANCE.md).
// -----------------------------------------------------------------

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A minimal BOOTP/DHCP DISCOVER wrapped in UDP/IPv4/Ethernet. `src`
/// MAC is the pretend-guest; destination is L2 broadcast, IP
/// 0.0.0.0 → 255.255.255.255, UDP 68 → 67. Option 53 = 1 (DISCOVER).
fn build_dhcp_discover(mac: [u8; 6]) -> Vec<u8> {
    // op = BOOTREQUEST, htype = Ethernet, hlen = 6, hops = 0.
    let mut dhcp = vec![1u8, 1, 6, 0];
    dhcp.extend_from_slice(&0x1234_5678u32.to_be_bytes()); // xid
    dhcp.extend_from_slice(&0u16.to_be_bytes()); // secs
    dhcp.extend_from_slice(&0u16.to_be_bytes()); // flags (unicast)
    dhcp.extend_from_slice(&[0u8; 4]); // ciaddr
    dhcp.extend_from_slice(&[0u8; 4]); // yiaddr
    dhcp.extend_from_slice(&[0u8; 4]); // siaddr
    dhcp.extend_from_slice(&[0u8; 4]); // giaddr
    let mut chaddr = [0u8; 16];
    chaddr[..6].copy_from_slice(&mac);
    dhcp.extend_from_slice(&chaddr); // chaddr (16)
    dhcp.extend_from_slice(&[0u8; 64]); // sname
    dhcp.extend_from_slice(&[0u8; 128]); // file
    dhcp.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]); // DHCP magic cookie
    dhcp.extend_from_slice(&[53, 1, 1]); // option 53 = DISCOVER
    dhcp.push(255); // end
    while dhcp.len() < 300 {
        dhcp.push(0); // pad to a conventional minimum BOOTP size
    }
    let builder = etherparse::PacketBuilder::ethernet2(mac, [0xff; 6])
        .ipv4([0, 0, 0, 0], [255, 255, 255, 255], 64)
        .udp(68, 67);
    let mut out = Vec::with_capacity(builder.size(dhcp.len()));
    builder.write(&mut out, &dhcp).unwrap();
    out
}

/// Extract the DHCP message-type (option 53) from an ethernet frame,
/// or `None` if it isn't a well-formed DHCP packet. 2 = OFFER.
fn dhcp_msg_type(frame: &[u8]) -> Option<u8> {
    let sliced = etherparse::SlicedPacket::from_ethernet(frame).ok()?;
    let payload = match sliced.transport? {
        etherparse::TransportSlice::Udp(u) => u.payload(),
        _ => return None,
    };
    if payload.len() < 240 || payload[236..240] != [0x63, 0x82, 0x53, 0x63] {
        return None;
    }
    let mut i = 240;
    while i < payload.len() {
        match payload[i] {
            255 => break, // end
            0 => i += 1,  // pad
            code => {
                let len = *payload.get(i + 1)? as usize;
                if code == 53 && len >= 1 {
                    return payload.get(i + 2).copied();
                }
                i += 2 + len;
            }
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_gateway_dhcp_offer_roundtrips_through_bridge() {
    if std::env::var("MVM_GATEWAY_DHCP_E2E").is_err() {
        eprintln!("skip: set MVM_GATEWAY_DHCP_E2E=1 to run the live gateway DHCP test");
        return;
    }
    let gw_bin =
        std::env::var("MVM_GATEWAY_BIN").unwrap_or_else(|_| "native gateway helper".to_string());
    let tmp = tempfile::tempdir().unwrap();
    let gw_sock = tmp.path().join("gw.sock");
    let gw_log = tmp.path().join("gw.log");
    let stdio = std::fs::File::create(tmp.path().join("gw-stdio.log")).unwrap();

    // Real gateway: `-listen-vfkit unixgram://<sock>` is the contract
    // (the compat gateway's, and what rvproxy must match). `-ssh-port` is
    // compat-gateway-specific (it always binds an SSH-forward listener); only
    // pass it when the helper is literally `gvproxy` so other gateways aren't tripped by an
    // unknown flag.
    let mut cmd = std::process::Command::new(&gw_bin);
    cmd.arg("-listen-vfkit")
        .arg(format!("unixgram://{}", gw_sock.display()))
        .arg("-log-file")
        .arg(&gw_log)
        .stdout(stdio.try_clone().unwrap())
        .stderr(stdio);
    let is_legacy_gvproxy = std::path::Path::new(&gw_bin)
        .file_name()
        .is_none_or(|n| n == "gvproxy");
    if is_legacy_gvproxy {
        cmd.arg("-ssh-port").arg(free_tcp_port().to_string());
    }
    let mut gateway = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skip: cannot spawn gateway {gw_bin:?}: {e}");
            return;
        }
    };

    // Wait for the gateway to create its listener socket.
    let mut ready = false;
    for _ in 0..100 {
        if gw_sock.exists() {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    if !ready {
        let _ = gateway.kill();
        let log = std::fs::read_to_string(tmp.path().join("gw-stdio.log")).unwrap_or_default();
        panic!(
            "gateway {gw_bin:?} never created {} (stdio: {log})",
            gw_sock.display()
        );
    }

    // Bridge: gateway-facing = the gateway's socket; libkrun-facing =
    // a listener the harness connects to.
    let sup_listen = tmp.path().join("sup.sock");
    let (tx, mut rx) = audit_event_channel(64);
    let policy = unrestricted_flow_policy();
    let bridge = tokio::spawn(run_libkrun_native_gateway_bridge(
        gw_sock.clone(),
        sup_listen.clone(),
        "vm-dhcp".to_string(),
        "t".to_string(),
        policy,
        tx,
        wiring_with(vec![]),
    ));

    // Harness plays the VMM (vfkit/libkrun). It MUST be bound to a
    // pathname so the gateway can address its DHCP reply back.
    let harness_path = libkrun_reply_path(&sup_listen);
    let harness = tokio::net::UnixDatagram::bind(&harness_path).unwrap();
    let mut connected = false;
    for _ in 0..100 {
        if harness.connect(&sup_listen).is_ok() {
            connected = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(connected, "bridge never bound {}", sup_listen.display());

    // vfkit announces itself with a 4-byte "VFKT" handshake datagram,
    // then sends ethernet frames. (Bridge forwards both verbatim.)
    let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];
    harness.send(b"VFKT").await.unwrap();
    harness.send(&build_dhcp_discover(mac)).await.unwrap();

    // Read until we see a DHCP OFFER or time out. The gateway may emit
    // other frames (ARP, etc.) first.
    let mut buf = vec![0u8; 65536];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    let mut got_offer = false;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            harness.recv(&mut buf),
        )
        .await
        {
            Ok(Ok(n)) if dhcp_msg_type(&buf[..n]) == Some(2) => {
                got_offer = true;
                break;
            }
            _ => {}
        }
    }

    // A FlowOpened must have been emitted (observer pipeline fired on
    // the real-gateway path).
    let mut saw_open = false;
    while let Ok(ev) = rx.try_recv() {
        let ev = ev.into_flow().expect("bridge emits a flow event");
        if matches!(ev.kind, FlowEventKind::Opened) {
            saw_open = true;
        }
    }

    let _ = gateway.kill();
    let _ = gateway.wait();
    bridge.abort();

    let log = std::fs::read_to_string(tmp.path().join("gw-stdio.log")).unwrap_or_default();
    assert!(
        got_offer,
        "no DHCP OFFER returned through the bridge from {gw_bin:?} (gateway stdio: {log})"
    );
    assert!(saw_open, "bridge must emit a FlowOpened for the exchange");
}

/// A guest TCP SYN wrapped in IPv4/Ethernet, from `src_ip:src_port` to
/// `dst_ip:dst_port`. Used to drive the native-rvproxy enforcement witness.
fn build_tcp_syn(
    mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let builder = etherparse::PacketBuilder::ethernet2(mac, [0xff; 6])
        .ipv4(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, 1, 64000)
        .syn();
    let mut out = Vec::new();
    builder.write(&mut out, &[]).unwrap();
    out
}

/// Outcome of a single-SYN native-rvproxy probe.
struct NativeProbe {
    /// `Some(reason)` if rvproxy exported a `denied` flow for the probed dst;
    /// `None` if it was admitted (an admitted flow stays silent until its
    /// upstream connect resolves, so absence-of-deny is the admit signal).
    denied_reason: Option<String>,
    export: String,
    stdio: String,
}

/// Scan an rvproxy flow-audit JSONL export for a `flow` record with
/// `verdict:"denied"` for `dst_ip`, returning its `reason`.
fn denied_reason_for(export: &str, dst_ip: &str) -> Option<String> {
    for line in export.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("kind").and_then(|k| k.as_str()) == Some("flow")
            && v.pointer("/event/verdict").and_then(|x| x.as_str()) == Some("denied")
            && v.pointer("/event/endpoints/destination_ip")
                .and_then(|x| x.as_str())
                == Some(dst_ip)
        {
            return Some(
                v.pointer("/event/reason")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
            );
        }
    }
    None
}

/// Spawn native `rvproxy run --config` with `egress`, play the VMM directly
/// against its vfkit socket (no splice) with a SINGLE first-frame TCP SYN to
/// `dst:443`, and report whether rvproxy exported a `denied` flow for that
/// dst. Only the first data frame after the VFKT/DHCP handshake is reliably
/// processed — and only one vfkit connection is accepted per spawn — so each
/// dst must be probed by its own spawn. Returns `None` if the binary can't be
/// spawned (soft-skip); panics if it spawns but never binds (a real failure).
async fn native_first_frame_probe(
    gw_bin: &str,
    id: &str,
    egress: &mvm_core::policy::projection::CanonicalEgress,
    dst: [u8; 4],
    poll_secs: u64,
) -> Option<NativeProbe> {
    let tmp = tempfile::tempdir().unwrap();
    let gw_sock = tmp.path().join("gw.sock");
    let api_sock = tmp.path().join("api.sock");
    let flow_audit = tmp.path().join("flow-audit.jsonl");
    let cfg_path = tmp.path().join("rvproxy.toml");

    let resolvers = [std::net::Ipv4Addr::new(1, 1, 1, 1)];
    let toml = crate::supervisor::network::rvproxy_config::render_rvproxy_config(
        &crate::supervisor::network::rvproxy_config::RvproxyConfigParams {
            id,
            transport_socket: &gw_sock,
            api_socket: &api_sock,
            flow_audit_path: &flow_audit,
            egress,
            dns_allow: &[],
            upstream_resolvers: &resolvers,
            transparent: None,
        },
    )
    .expect("render native config");
    std::fs::write(&cfg_path, toml).unwrap();

    let stdio = std::fs::File::create(tmp.path().join("gw-stdio.log")).unwrap();
    let mut gateway = match std::process::Command::new(gw_bin)
        .arg("run")
        .arg("--config")
        .arg(&cfg_path)
        .stdout(stdio.try_clone().unwrap())
        .stderr(stdio)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skip: cannot spawn native gateway {gw_bin:?}: {e}");
            return None;
        }
    };

    let mut ready = false;
    for _ in 0..100 {
        if gw_sock.exists() {
            ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    if !ready {
        let _ = gateway.kill();
        let log = std::fs::read_to_string(tmp.path().join("gw-stdio.log")).unwrap_or_default();
        panic!(
            "native gateway {gw_bin:?} never bound {} (stdio: {log})",
            gw_sock.display()
        );
    }

    // Play the VMM: bind a unixgram, connect straight to rvproxy (no splice),
    // VFKT handshake, DHCP, then the single TCP SYN to dst:443.
    let harness = tokio::net::UnixDatagram::bind(tmp.path().join("harness.sock")).unwrap();
    harness
        .connect(&gw_sock)
        .expect("connect to rvproxy vfkit socket");
    let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];
    harness.send(b"VFKT").await.unwrap();
    harness.send(&build_dhcp_discover(mac)).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let syn = build_tcp_syn(mac, [192, 168, 127, 2], dst, 40000, 443);
    harness.send(&syn).await.unwrap();

    let dst_ip = format!("{}.{}.{}.{}", dst[0], dst[1], dst[2], dst[3]);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(poll_secs);
    let mut denied_reason = None;
    while tokio::time::Instant::now() < deadline {
        let export = std::fs::read_to_string(&flow_audit).unwrap_or_default();
        if let Some(reason) = denied_reason_for(&export, &dst_ip) {
            denied_reason = Some(reason);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }

    let export = std::fs::read_to_string(&flow_audit).unwrap_or_default();
    let stdio = std::fs::read_to_string(tmp.path().join("gw-stdio.log")).unwrap_or_default();
    let _ = gateway.kill();
    let _ = gateway.wait();
    Some(NativeProbe {
        denied_reason,
        export,
        stdio,
    })
}

/// Native-rvproxy enforcement parity arm (binary-discriminating).
/// Spawns the candidate as **native**
/// `rvproxy run --config` with a deny-all `[policy]` + a flow-audit export,
/// plays the VMM directly against rvproxy's vfkit socket (no splice), and
/// asserts rvproxy ENFORCES deny-by-default by EXPORTING a `flow` record
/// with `verdict:"denied"` for the probed destination. gvproxy can do
/// neither (no `run --config`, no flow export), so this discriminates the
/// candidate. Opt-in (`MVM_GATEWAY_NATIVE_E2E=1` + `MVM_GATEWAY_BIN` = an
/// rvproxy binary); self-skips otherwise.
#[tokio::test]
async fn rvproxy_native_denies_and_exports_flow() {
    if std::env::var("MVM_GATEWAY_NATIVE_E2E").is_err() {
        eprintln!("skip: set MVM_GATEWAY_NATIVE_E2E=1 to run the native-enforcement witness");
        return;
    }
    let Ok(gw_bin) = std::env::var("MVM_GATEWAY_BIN") else {
        eprintln!("skip: set MVM_GATEWAY_BIN to a native rvproxy binary");
        return;
    };

    // Deny-all native config (no allow rules) → a SYN to any dst must be
    // refused + a denied flow exported with reason `deny-by-default`.
    let deny_all = mvm_core::policy::projection::CanonicalEgress::Rules(Vec::new());
    let Some(probe) =
        native_first_frame_probe(&gw_bin, "vm-native-deny", &deny_all, [93, 184, 216, 34], 8).await
    else {
        return;
    };
    let reason = probe.denied_reason.unwrap_or_else(|| {
        panic!(
            "native rvproxy {gw_bin:?} did not export a denied flow for the deny-all SYN \
             (export: {}; stdio: {})",
            probe.export, probe.stdio
        )
    });
    assert_eq!(
        reason, "deny-by-default",
        "native rvproxy {gw_bin:?} denied the deny-all SYN for the wrong reason \
         (export: {}; stdio: {})",
        probe.export, probe.stdio
    );
}

/// Native-rvproxy allow/deny matrix (binary-discriminating). Renders ONE
/// `[policy]` with an **L4 allow rule** for a public /24 + deny-by-default,
/// then probes it twice (rvproxy accepts a single vfkit connection per spawn,
/// and only the first post-handshake frame is reliably processed, so each dst
/// gets its own spawn of the identical config):
///
///   - an UNLISTED dst (8.8.8.8) must be DENIED with reason `l4_allowlist_miss`
///     — proving the rendered allow-list is active and consulted (a deny-all
///     config without an allow-list denies for `deny-by-default` instead);
///   - the LISTED dst (93.184.216.34) must NOT be denied — the allow rule
///     admitted it.
///
/// The asymmetry under the identical config proves the allow-list changes the
/// verdict, not just blanket deny. We assert admission as absence-of-deny
/// rather than a positive `allowed` flow because rvproxy only exports an
/// admitted flow once its upstream connect resolves, and its SSRF guards
/// (`guest_to_host`, `lan_access`) refuse every locally-reachable address
/// before the L4 allow-list is consulted — so no prompt-connectable local
/// listener can stand in for an admitted public dst. Deny decisions, by
/// contrast, are synchronous. The unlisted-deny half demonstrates the frame
/// path works under this config, so the listed-not-denied half is meaningful.
/// Same opt-in gate as the deny witness.
#[tokio::test]
async fn rvproxy_native_admits_listed_denies_unlisted() {
    if std::env::var("MVM_GATEWAY_NATIVE_E2E").is_err() {
        eprintln!("skip: set MVM_GATEWAY_NATIVE_E2E=1 to run the native allow/deny witness");
        return;
    }
    let Ok(gw_bin) = std::env::var("MVM_GATEWAY_BIN") else {
        eprintln!("skip: set MVM_GATEWAY_BIN to a native rvproxy binary");
        return;
    };

    use mvm_core::policy::projection::{CanonicalEgress, CanonicalRule, Proto};
    // Allow tcp 93.184.216.0/24:443 (public, passes rvproxy's SSRF guards);
    // everything else deny-by-default.
    let egress = CanonicalEgress::Rules(vec![CanonicalRule {
        proto: Proto::Tcp,
        net: "93.184.216.0/24".parse().unwrap(),
        port_lo: 443,
        port_hi: 443,
    }]);

    // Unlisted dst → denied, attributed to the allow-list miss (not
    // deny-by-default), proving the rendered allow-list is active.
    let Some(unlisted) =
        native_first_frame_probe(&gw_bin, "vm-native-allow-miss", &egress, [8, 8, 8, 8], 8).await
    else {
        return;
    };
    let reason = unlisted.denied_reason.clone().unwrap_or_else(|| {
        panic!(
            "native rvproxy {gw_bin:?} did not DENY the unlisted dst 8.8.8.8 under an \
             allow-list config (export: {}; stdio: {})",
            unlisted.export, unlisted.stdio
        )
    });
    assert_eq!(
        reason, "l4_allowlist_miss",
        "native rvproxy {gw_bin:?} denied the unlisted dst for the wrong reason — the L4 \
         allow-list was not consulted (export: {}; stdio: {})",
        unlisted.export, unlisted.stdio
    );

    // Listed dst → admitted: it must NOT produce a denied flow. (It may later
    // export an `allowed` flow once its upstream connect resolves — not a
    // deny.) The unlisted probe above already proved the frame path enforces
    // under this config, so absence-of-deny here means the allow rule
    // admitted the dst.
    let Some(listed) = native_first_frame_probe(
        &gw_bin,
        "vm-native-allow-hit",
        &egress,
        [93, 184, 216, 34],
        3,
    )
    .await
    else {
        return;
    };
    assert!(
        listed.denied_reason.is_none(),
        "native rvproxy {gw_bin:?} DENIED the allow-listed dst 93.184.216.34 (reason {:?}) — \
         the rendered L4 allow-list was not honored (export: {}; stdio: {})",
        listed.denied_reason,
        listed.export,
        listed.stdio
    );
}
