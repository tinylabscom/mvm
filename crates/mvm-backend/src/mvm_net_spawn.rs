//! Spawn/reap support for the per-VM `mvm-host-netd` authority process.
//!
//! The backend writes the binary's documented JSON config and starts it in
//! `--listen-uds` mode. This keeps `mvm-backend` from linking `mvm-net` while
//! still sharing the same wire contract through serde-compatible `mvm-core`
//! policy and DNS-pin types.

use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use mvm_core::crypto::secret_store::{SecretStore, default_secret_store};
use mvm_core::plan::{SecretBinding as PlanSecretBinding, SecretGuestMount, SecretSource};
use mvm_core::policy::dns_pin::{DnsPin, DnsPinRegistry};
use mvm_core::policy::network_policy::NetworkPolicy;
use secrecy::ExposeSecret;
use serde_json::json;

use crate::substitution_spawn::{
    build_egress_tls_delivery, clear_egress_intermediate, write_egress_intermediate,
};

pub const HOST_NETD_PID_FILE: &str = "mvm-host-netd.pid";
pub const HOST_NETD_CONFIG_FILE: &str = "mvm-host-netd.json";
pub const HOST_NETD_SOCKET_FILE: &str = "mvm-net-authority.sock";
pub const HOST_NETD_AUDIT_FILE: &str = "mvm-host-netd.audit.jsonl";
pub const HOST_SIGNER_KEY_FILE: &str = "host-signer.ed25519";
pub const HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV: &str = "MVM_HOST_NETD_UPSTREAM_ROOTS_PEM_FILE";
/// Guest bridge authority port. Mirrors `mvm-net`'s guest bridge default without
/// linking `mvm-net` into `mvm-backend`.
pub const TRANSPARENT_NET_VSOCK_PORT: u32 = 5254;
pub const DEFAULT_DNS_PIN_TTL: Duration = Duration::from_secs(3600);
pub const HOST_NETD_READY_TIMEOUT: Duration = Duration::from_secs(10);
pub const HOST_NETD_REAP_GRACE_TIMEOUT: Duration = Duration::from_millis(500);

fn resolve_host_netd_path() -> Result<PathBuf> {
    crate::aux_bin::resolve_or_build(&crate::aux_bin::AuxBin {
        bin: "mvm-host-netd",
        package: "mvm-net",
        env_var: "MVM_HOST_NETD_PATH",
        features: &["host-netd"],
        input_roots: &[
            "Cargo.toml",
            "Cargo.lock",
            "crates/mvm-net/Cargo.toml",
            "crates/mvm-net/src",
            "crates/mvm-core/Cargo.toml",
            "crates/mvm-core/src",
        ],
    })
}

pub fn resolve_host_netd_path_for_runtime() -> Result<PathBuf> {
    resolve_host_netd_path()
}

pub struct MvmNetSpawnParams<'a> {
    pub vm_name: &'a str,
    pub state_dir: &'a Path,
    pub tenant: &'a str,
    pub secrets: &'a [PlanSecretBinding],
    pub network_policy: &'a NetworkPolicy,
}

#[derive(Debug, Clone, Default, serde::Serialize, PartialEq, Eq)]
struct HostNetdStreamTransformsFile {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    secret_replacement_bindings: Vec<mvm_core::policy::secret_binding::SecretBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    response_leak_guard_secret_values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostNetdUpstreamRootsSelection {
    Native,
    PemBundle(String),
}

impl HostNetdUpstreamRootsSelection {
    fn to_config_json(&self) -> serde_json::Value {
        match self {
            Self::Native => json!({
                "type": "native",
            }),
            Self::PemBundle(pem) => json!({
                "type": "pem_bundle",
                "pem": pem,
            }),
        }
    }
}

impl HostNetdStreamTransformsFile {
    fn is_empty(&self) -> bool {
        self.secret_replacement_bindings.is_empty()
            && self.response_leak_guard_secret_values.is_empty()
    }
}

#[derive(Debug, Clone, Copy)]
struct HostNetdConfigJsonParams<'a> {
    network_policy: &'a NetworkPolicy,
    dns_pins: &'a DnsPinRegistry,
    now: &'a str,
    tls_intermediate: Option<&'a (String, String)>,
    upstream_roots: Option<&'a HostNetdUpstreamRootsSelection>,
    stream_transforms: &'a HostNetdStreamTransformsFile,
    tenant: &'a str,
    vm_name: &'a str,
}

#[derive(Debug, Default, Clone, Copy)]
struct HostNetdConfigJsonParamsBuilder<'a> {
    network_policy: Option<&'a NetworkPolicy>,
    dns_pins: Option<&'a DnsPinRegistry>,
    now: Option<&'a str>,
    tls_intermediate: Option<&'a (String, String)>,
    upstream_roots: Option<&'a HostNetdUpstreamRootsSelection>,
    stream_transforms: Option<&'a HostNetdStreamTransformsFile>,
    tenant: Option<&'a str>,
    vm_name: Option<&'a str>,
}

impl<'a> HostNetdConfigJsonParamsBuilder<'a> {
    fn new() -> Self {
        Self::default()
    }

    fn network_policy(mut self, network_policy: &'a NetworkPolicy) -> Self {
        self.network_policy = Some(network_policy);
        self
    }

    fn dns_pins(mut self, dns_pins: &'a DnsPinRegistry) -> Self {
        self.dns_pins = Some(dns_pins);
        self
    }

    fn now(mut self, now: &'a str) -> Self {
        self.now = Some(now);
        self
    }

    fn tls_intermediate(mut self, tls_intermediate: Option<&'a (String, String)>) -> Self {
        self.tls_intermediate = tls_intermediate;
        self
    }

    fn upstream_roots(
        mut self,
        upstream_roots: Option<&'a HostNetdUpstreamRootsSelection>,
    ) -> Self {
        self.upstream_roots = upstream_roots;
        self
    }

    fn stream_transforms(mut self, stream_transforms: &'a HostNetdStreamTransformsFile) -> Self {
        self.stream_transforms = Some(stream_transforms);
        self
    }

    fn tenant(mut self, tenant: &'a str) -> Self {
        self.tenant = Some(tenant);
        self
    }

    fn vm_name(mut self, vm_name: &'a str) -> Self {
        self.vm_name = Some(vm_name);
        self
    }

    fn build(self) -> HostNetdConfigJsonParams<'a> {
        HostNetdConfigJsonParams {
            network_policy: self
                .network_policy
                .expect("network_policy must be set before building host-netd config json"),
            dns_pins: self
                .dns_pins
                .expect("dns_pins must be set before building host-netd config json"),
            now: self
                .now
                .expect("now must be set before building host-netd config json"),
            tls_intermediate: self.tls_intermediate,
            upstream_roots: self.upstream_roots,
            stream_transforms: self
                .stream_transforms
                .expect("stream_transforms must be set before building host-netd config json"),
            tenant: self
                .tenant
                .expect("tenant must be set before building host-netd config json"),
            vm_name: self
                .vm_name
                .expect("vm_name must be set before building host-netd config json"),
        }
    }
}

pub fn mvm_net_authority_socket(state_dir: &Path) -> PathBuf {
    state_dir.join(HOST_NETD_SOCKET_FILE)
}

pub fn spawn_mvm_net_authority(params: MvmNetSpawnParams<'_>) -> Result<PathBuf> {
    std::fs::create_dir_all(params.state_dir)
        .with_context(|| format!("create state dir {}", params.state_dir.display()))?;
    let socket = mvm_net_authority_socket(params.state_dir);
    let config_path = params.state_dir.join(HOST_NETD_CONFIG_FILE);
    let audit_path = params.state_dir.join(HOST_NETD_AUDIT_FILE);
    let pid_path = params.state_dir.join(HOST_NETD_PID_FILE);
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(&pid_path);

    let now = mvm_core::util::time::utc_now();
    let expires_at = mvm_core::util::time::utc_plus_duration(DEFAULT_DNS_PIN_TTL);
    let dns_pins = resolve_dns_pins(params.network_policy, &now, &expires_at)?;
    let tls_intermediate =
        stage_transparent_net_tls_intermediate(params.state_dir, params.network_policy)?;
    let upstream_roots = tls_intermediate
        .as_ref()
        .map(|_| resolve_host_netd_upstream_roots())
        .transpose()?;
    let secret_store = default_secret_store();
    let stream_transforms =
        transparent_net_stream_transforms(params.tenant, params.secrets, secret_store.as_ref())?;
    let config = host_netd_config_json(
        HostNetdConfigJsonParamsBuilder::new()
            .network_policy(params.network_policy)
            .dns_pins(&dns_pins)
            .now(&now)
            .tls_intermediate(tls_intermediate.as_ref())
            .upstream_roots(upstream_roots.as_ref())
            .stream_transforms(&stream_transforms)
            .tenant(params.tenant)
            .vm_name(params.vm_name)
            .build(),
    );
    std::fs::write(&config_path, config.to_string())
        .with_context(|| format!("write {}", config_path.display()))?;

    let bin = resolve_host_netd_path()?;
    let audit_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&audit_path)
        .with_context(|| format!("open {}", audit_path.display()))?;
    let mut cmd = Command::new(&bin);
    cmd.arg("--config")
        .arg(&config_path)
        .arg("--listen-uds")
        .arg(&socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(audit_file));
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            // SAFETY: post-fork, pre-exec; setsid has no preconditions.
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow!("spawn {} for {}: {e}", bin.display(), params.vm_name))?;
    let deadline = Instant::now() + HOST_NETD_READY_TIMEOUT;
    loop {
        if socket.exists() {
            std::fs::write(&pid_path, child.id().to_string())
                .with_context(|| format!("write {}", pid_path.display()))?;
            drop(child);
            return Ok(socket);
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|e| anyhow!("poll mvm-host-netd: {e}"))?
        {
            bail!(
                "mvm-host-netd exited before binding {} (status: {status}); see {}",
                socket.display(),
                audit_path.display()
            );
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            bail!(
                "mvm-host-netd did not bind {} within {:?}; killed",
                socket.display(),
                HOST_NETD_READY_TIMEOUT
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn host_netd_config_json(params: HostNetdConfigJsonParams<'_>) -> serde_json::Value {
    let mut value = json!({
        "network_policy": params.network_policy,
        "dns_pins": params.dns_pins,
        "now": params.now,
        "audit_chain": {
            "path": mvm_core::config::transparent_net_audit_path(params.tenant, params.vm_name),
            "signing_key_path": mvm_core::config::mvm_keys_dir().join(HOST_SIGNER_KEY_FILE),
            "tenant": params.tenant,
            "vm_name": params.vm_name,
        },
    });
    if let Some((cert_pem, key_pem)) = params.tls_intermediate {
        value["tls_intermediate"] = json!({
            "cert_pem": cert_pem,
            "key_pem": key_pem,
        });
        let upstream_roots = params
            .upstream_roots
            .unwrap_or(&HostNetdUpstreamRootsSelection::Native);
        value["upstream_roots"] = upstream_roots.to_config_json();
    }
    if !params.stream_transforms.is_empty() {
        value["stream_transforms"] = json!(params.stream_transforms);
    }
    value
}

fn resolve_host_netd_upstream_roots() -> Result<HostNetdUpstreamRootsSelection> {
    let cfg = mvm_core::user_config::load(None);
    let Some(path) = cfg.effective_host_netd_upstream_roots_pem_file() else {
        return Ok(HostNetdUpstreamRootsSelection::Native);
    };
    let pem = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "read transformed-TLS upstream roots PEM bundle from {} (config key host_netd_upstream_roots_pem_file or {HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV})",
            path.display()
        )
    })?;
    Ok(HostNetdUpstreamRootsSelection::PemBundle(pem))
}

fn transparent_net_stream_transforms(
    tenant: &str,
    plan_secrets: &[PlanSecretBinding],
    store: &dyn SecretStore,
) -> Result<HostNetdStreamTransformsFile> {
    let mut config = HostNetdStreamTransformsFile::default();
    for secret in plan_secrets {
        if secret.allowed_hosts.is_empty() {
            continue;
        }
        let value = resolve_plan_secret_value(tenant, secret, store)?;
        if !config
            .response_leak_guard_secret_values
            .iter()
            .any(|existing| existing == &value)
        {
            config.response_leak_guard_secret_values.push(value.clone());
        }

        let Some(placeholder_name) = guest_placeholder_name_for_transparent_tls(secret) else {
            continue;
        };
        for host in &secret.allowed_hosts {
            config.secret_replacement_bindings.push(
                mvm_core::policy::secret_binding::SecretBinding::new(&placeholder_name, host)
                    .with_value(value.clone()),
            );
        }
    }
    Ok(config)
}

fn guest_placeholder_name_for_transparent_tls(secret: &PlanSecretBinding) -> Option<String> {
    match secret.guest_mount.as_ref() {
        Some(SecretGuestMount::Env { var }) => Some(var.clone()),
        Some(SecretGuestMount::File { path }) => Some(path.clone()),
        None => Some(secret.name.clone()),
    }
}

fn resolve_plan_secret_value(
    tenant: &str,
    secret: &PlanSecretBinding,
    store: &dyn SecretStore,
) -> Result<String> {
    match &secret.source {
        SecretSource::Static { value } => Ok(value.clone()),
        SecretSource::Keystore { address } => Ok(store
            .get(tenant, address)
            .with_context(|| format!("resolve transparent-net secret {address:?}"))?
            .expose_secret()
            .clone()),
        SecretSource::External { provider, path } => bail!(
            "transparent-net TLS secret transforms do not support external secret source {provider:?}:{path:?}"
        ),
    }
}

fn stage_transparent_net_tls_intermediate(
    state_dir: &Path,
    network_policy: &NetworkPolicy,
) -> Result<Option<(String, String)>> {
    let Some(rules) = network_policy.resolve_rules() else {
        clear_egress_intermediate(state_dir);
        return Ok(None);
    };

    let mut bound_hosts = Vec::new();
    for rule in rules {
        if rule.host.parse::<IpAddr>().is_ok() {
            continue;
        }
        if !bound_hosts.iter().any(|existing| existing == &rule.host) {
            bound_hosts.push(rule.host);
        }
    }

    if bound_hosts.is_empty() {
        clear_egress_intermediate(state_dir);
        return Ok(None);
    }

    let refs: Vec<&str> = bound_hosts.iter().map(String::as_str).collect();
    let delivery = build_egress_tls_delivery(&refs, &mvm_core::config::egress_ca_dir())?;
    write_egress_intermediate(
        state_dir,
        &delivery.endpoint_cert_pem,
        &delivery.endpoint_key_pem,
    )?;
    Ok(Some((
        delivery.endpoint_cert_pem,
        delivery.endpoint_key_pem,
    )))
}

fn resolve_dns_pins(
    network_policy: &NetworkPolicy,
    resolved_at: &str,
    expires_at: &str,
) -> Result<DnsPinRegistry> {
    let mut registry = DnsPinRegistry::new();
    let Some(rules) = network_policy.resolve_rules() else {
        return Ok(registry);
    };
    for rule in rules {
        let ips = resolve_rule_ips(&rule.host, rule.port)?;
        registry.add(DnsPin::at(
            rule.host,
            ips,
            resolved_at.to_string(),
            expires_at.to_string(),
        ));
    }
    Ok(registry)
}

fn resolve_rule_ips(host: &str, port: u16) -> Result<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let mut ips: Vec<IpAddr> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve network policy host {host:?}"))?
        .map(|addr| addr.ip())
        .collect();
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        bail!("network policy host {host:?} resolved to no IP addresses");
    }
    Ok(ips)
}

pub fn reap_mvm_net_authority(state_dir: &Path) {
    if let Some(pid) = read_pid(&state_dir.join(HOST_NETD_PID_FILE))
        && pid_alive_or_reap(pid)
    {
        terminate_recorded_pid(pid);
    }
    let _ = std::fs::remove_file(state_dir.join(HOST_NETD_PID_FILE));
    let _ = std::fs::remove_file(state_dir.join(HOST_NETD_SOCKET_FILE));
}

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn pid_alive_or_reap(pid: libc::pid_t) -> bool {
    if reap_exited_child(pid) {
        return false;
    }
    // SAFETY: signal 0 probes existence/permission without delivering a signal.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn kill(pid: libc::pid_t, sig: libc::c_int) {
    // SAFETY: best-effort signal to a pid this helper recorded.
    unsafe {
        libc::kill(pid, sig);
    }
}

fn terminate_recorded_pid(pid: libc::pid_t) {
    kill(pid, libc::SIGTERM);
    if wait_for_pid_exit(pid, HOST_NETD_REAP_GRACE_TIMEOUT) {
        return;
    }
    kill(pid, libc::SIGKILL);
    let _ = wait_for_pid_exit(pid, HOST_NETD_REAP_GRACE_TIMEOUT);
}

fn wait_for_pid_exit(pid: libc::pid_t, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if !pid_alive_or_reap(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn reap_exited_child(pid: libc::pid_t) -> bool {
    let mut status = 0;
    // SAFETY: waitpid with WNOHANG observes/reaps only this recorded child pid.
    let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    rc == pid
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::crypto::secret_store::{FileSecretStore, SecretStore};
    use mvm_core::plan::{SecretBinding as PlanSecretBinding, SecretGuestMount, SecretSource};
    use mvm_core::policy::network_policy::HostPort;
    use secrecy::SecretBox;

    #[test]
    fn config_json_carries_policy_pins_and_timestamp() {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("203.0.113.10", 443)]);
        let pins =
            resolve_dns_pins(&policy, "2030-01-01T00:00:00Z", "2030-01-01T01:00:00Z").unwrap();
        let cfg = host_netd_config_json(
            HostNetdConfigJsonParamsBuilder::new()
                .network_policy(&policy)
                .dns_pins(&pins)
                .now("2030-01-01T00:00:00Z")
                .stream_transforms(&HostNetdStreamTransformsFile::default())
                .tenant("local")
                .vm_name("vm-test")
                .build(),
        );

        assert_eq!(cfg["network_policy"]["type"], "allowlist");
        assert_eq!(
            cfg["dns_pins"]["pins"]["203.0.113.10"]["ips"][0],
            "203.0.113.10"
        );
        assert_eq!(cfg["now"], "2030-01-01T00:00:00Z");
        assert_eq!(cfg["audit_chain"]["tenant"], "local");
        assert_eq!(cfg["audit_chain"]["vm_name"], "vm-test");
    }

    #[test]
    fn resolve_dns_pins_pins_direct_ip_allow_list_without_dns() {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("2001:db8::10", 8443)]);
        let pins =
            resolve_dns_pins(&policy, "2030-01-01T00:00:00Z", "2030-01-01T01:00:00Z").unwrap();

        let pin = pins.lookup("2001:db8::10").unwrap();
        assert_eq!(pin.ips, vec!["2001:db8::10".parse::<IpAddr>().unwrap()]);
        assert_eq!(pin.ttl_secs(), 3600);
    }

    #[test]
    fn stage_transparent_net_tls_intermediate_writes_sidecar_for_hostname_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]);

        let staged = stage_transparent_net_tls_intermediate(dir.path(), &policy).unwrap();

        let (cert_pem, key_pem) = staged.expect("hostname allowlist should stage TLS material");
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("PRIVATE KEY"));
        let written = crate::substitution_spawn::read_egress_intermediate(dir.path())
            .unwrap()
            .expect("sidecar persisted");
        assert_eq!(written.0, cert_pem);
        assert_eq!(written.1, key_pem);
    }

    #[test]
    fn stage_transparent_net_tls_intermediate_skips_ip_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("203.0.113.10", 443)]);

        let staged = stage_transparent_net_tls_intermediate(dir.path(), &policy).unwrap();

        assert!(staged.is_none());
        assert!(
            crate::substitution_spawn::read_egress_intermediate(dir.path())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn spawn_mvm_net_authority_writes_config_and_records_pid() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let dir = std::env::temp_dir().join(format!("mvm-host-netd-spawn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("stub-host-netd.sh");
        std::fs::write(
            &stub,
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    --config) cfg=\"$2\"; shift 2 ;;\n    --listen-uds) sock=\"$2\"; shift 2 ;;\n    *) shift ;;\n  esac\ndone\ncp \"$cfg\" \"$cfg.captured\"\ntouch \"$sock\"\nsleep 30\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let saved = std::env::var_os("MVM_HOST_NETD_PATH");
        unsafe {
            std::env::set_var("MVM_HOST_NETD_PATH", &stub);
        }

        let socket = spawn_mvm_net_authority(MvmNetSpawnParams {
            vm_name: "netd-spawn-test",
            state_dir: &dir,
            tenant: "local",
            secrets: &[],
            network_policy: &NetworkPolicy::allow_list(vec![HostPort::new("203.0.113.10", 443)]),
        })
        .unwrap();

        unsafe {
            match saved {
                Some(value) => std::env::set_var("MVM_HOST_NETD_PATH", value),
                None => std::env::remove_var("MVM_HOST_NETD_PATH"),
            }
        }

        assert_eq!(socket, dir.join(HOST_NETD_SOCKET_FILE));
        assert!(dir.join(HOST_NETD_PID_FILE).is_file());
        let captured =
            std::fs::read_to_string(dir.join(format!("{HOST_NETD_CONFIG_FILE}.captured"))).unwrap();
        let cfg: serde_json::Value = serde_json::from_str(&captured).unwrap();
        assert_eq!(cfg["network_policy"]["type"], "allowlist");
        assert_eq!(
            cfg["dns_pins"]["pins"]["203.0.113.10"]["ips"][0],
            "203.0.113.10"
        );
        assert!(cfg.get("tls_intermediate").is_none());
        assert!(cfg.get("upstream_roots").is_none());
        assert_eq!(cfg["audit_chain"]["tenant"], "local");
        assert_eq!(cfg["audit_chain"]["vm_name"], "netd-spawn-test");
        assert!(
            cfg["audit_chain"]["path"]
                .as_str()
                .expect("audit_chain.path string")
                .ends_with("local.netd-spawn-test.transparent-net.jsonl")
        );
        assert!(
            cfg["audit_chain"]["signing_key_path"]
                .as_str()
                .expect("audit_chain.signing_key_path string")
                .ends_with(HOST_SIGNER_KEY_FILE)
        );

        reap_mvm_net_authority(&dir);
        assert!(!dir.join(HOST_NETD_PID_FILE).exists());
        assert!(!dir.join(HOST_NETD_SOCKET_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spawn_mvm_net_authority_writes_explicit_native_upstream_roots_for_hostname_allowlist() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "mvm-host-netd-spawn-hostname-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("stub-host-netd.sh");
        std::fs::write(
            &stub,
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    --config) cfg=\"$2\"; shift 2 ;;\n    --listen-uds) sock=\"$2\"; shift 2 ;;\n    *) shift ;;\n  esac\ndone\ncp \"$cfg\" \"$cfg.captured\"\ntouch \"$sock\"\nsleep 30\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let saved = std::env::var_os("MVM_HOST_NETD_PATH");
        unsafe {
            std::env::set_var("MVM_HOST_NETD_PATH", &stub);
        }

        let socket = spawn_mvm_net_authority(MvmNetSpawnParams {
            vm_name: "tls-netd-spawn-test",
            state_dir: &dir,
            tenant: "local",
            secrets: &[],
            network_policy: &NetworkPolicy::allow_list(vec![HostPort::new("localhost", 443)]),
        })
        .unwrap();

        unsafe {
            match saved {
                Some(value) => std::env::set_var("MVM_HOST_NETD_PATH", value),
                None => std::env::remove_var("MVM_HOST_NETD_PATH"),
            }
        }

        assert_eq!(socket, dir.join(HOST_NETD_SOCKET_FILE));
        let captured =
            std::fs::read_to_string(dir.join(format!("{HOST_NETD_CONFIG_FILE}.captured"))).unwrap();
        let cfg: serde_json::Value = serde_json::from_str(&captured).unwrap();
        assert_eq!(cfg["network_policy"]["type"], "allowlist");
        assert!(cfg["tls_intermediate"].is_object());
        assert_eq!(cfg["upstream_roots"]["type"], "native");

        reap_mvm_net_authority(&dir);
        assert!(!dir.join(HOST_NETD_PID_FILE).exists());
        assert!(!dir.join(HOST_NETD_SOCKET_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn host_netd_config_json_emits_explicit_native_upstream_roots_with_tls_intermediate() {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]);
        let dns_pins = DnsPinRegistry::default();
        let tls_intermediate = ("cert-pem".to_string(), "key-pem".to_string());
        let cfg = host_netd_config_json(
            HostNetdConfigJsonParamsBuilder::new()
                .network_policy(&policy)
                .dns_pins(&dns_pins)
                .now("2030-01-01T00:00:00Z")
                .tls_intermediate(Some(&tls_intermediate))
                .upstream_roots(Some(&HostNetdUpstreamRootsSelection::Native))
                .stream_transforms(&HostNetdStreamTransformsFile::default())
                .tenant("local")
                .vm_name("tls-netd-test")
                .build(),
        );

        assert_eq!(cfg["tls_intermediate"]["cert_pem"], "cert-pem");
        assert_eq!(cfg["tls_intermediate"]["key_pem"], "key-pem");
        assert_eq!(cfg["upstream_roots"]["type"], "native");
    }

    #[test]
    fn host_netd_config_json_emits_pem_bundle_upstream_roots_with_tls_intermediate() {
        let policy = NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]);
        let dns_pins = DnsPinRegistry::default();
        let tls_intermediate = ("cert-pem".to_string(), "key-pem".to_string());
        let upstream_roots = HostNetdUpstreamRootsSelection::PemBundle(
            "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n".to_string(),
        );
        let cfg = host_netd_config_json(
            HostNetdConfigJsonParamsBuilder::new()
                .network_policy(&policy)
                .dns_pins(&dns_pins)
                .now("2030-01-01T00:00:00Z")
                .tls_intermediate(Some(&tls_intermediate))
                .upstream_roots(Some(&upstream_roots))
                .stream_transforms(&HostNetdStreamTransformsFile::default())
                .tenant("local")
                .vm_name("tls-netd-test")
                .build(),
        );

        assert_eq!(cfg["upstream_roots"]["type"], "pem_bundle");
        assert!(
            cfg["upstream_roots"]["pem"]
                .as_str()
                .expect("pem bundle string")
                .contains("BEGIN CERTIFICATE")
        );
    }

    #[test]
    fn resolve_host_netd_upstream_roots_defaults_to_native() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let saved = std::env::var_os(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV);
        unsafe {
            std::env::remove_var(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV);
        }

        let resolved = resolve_host_netd_upstream_roots().unwrap();

        unsafe {
            match saved {
                Some(value) => std::env::set_var(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV, value),
                None => std::env::remove_var(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV),
            }
        }

        assert_eq!(resolved, HostNetdUpstreamRootsSelection::Native);
    }

    #[test]
    fn resolve_host_netd_upstream_roots_reads_pem_bundle_file_from_env() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let pem_path = dir.path().join("upstream-roots.pem");
        std::fs::write(
            &pem_path,
            "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let saved = std::env::var_os(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV);
        unsafe {
            std::env::set_var(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV, &pem_path);
        }

        let resolved = resolve_host_netd_upstream_roots().unwrap();

        unsafe {
            match saved {
                Some(value) => std::env::set_var(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV, value),
                None => std::env::remove_var(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV),
            }
        }

        assert_eq!(
            resolved,
            HostNetdUpstreamRootsSelection::PemBundle(
                "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n".to_string()
            )
        );
    }

    #[test]
    fn resolve_host_netd_upstream_roots_reads_pem_bundle_file_from_user_config() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config");
        let pem_path = dir.path().join("configured-upstream-roots.pem");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            &pem_path,
            "-----BEGIN CERTIFICATE-----\nconfigured-root\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let cfg = mvm_core::user_config::MvmConfig {
            host_netd_upstream_roots_pem_file: Some(pem_path.display().to_string()),
            ..mvm_core::user_config::MvmConfig::default()
        };
        mvm_core::user_config::save(&cfg, Some(&config_dir)).unwrap();
        let saved_config_dir = std::env::var_os("MVM_CONFIG_DIR");
        let saved_env_override = std::env::var_os(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV);
        unsafe {
            std::env::set_var("MVM_CONFIG_DIR", &config_dir);
            std::env::remove_var(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV);
        }

        let resolved = resolve_host_netd_upstream_roots().unwrap();

        unsafe {
            match saved_config_dir {
                Some(value) => std::env::set_var("MVM_CONFIG_DIR", value),
                None => std::env::remove_var("MVM_CONFIG_DIR"),
            }
            match saved_env_override {
                Some(value) => std::env::set_var(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV, value),
                None => std::env::remove_var(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV),
            }
        }

        assert_eq!(
            resolved,
            HostNetdUpstreamRootsSelection::PemBundle(
                "-----BEGIN CERTIFICATE-----\nconfigured-root\n-----END CERTIFICATE-----\n"
                    .to_string()
            )
        );
    }

    #[test]
    fn spawn_mvm_net_authority_writes_pem_bundle_upstream_roots_for_hostname_allowlist() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "mvm-host-netd-spawn-pem-roots-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("stub-host-netd.sh");
        let pem_path = dir.join("upstream-roots.pem");
        std::fs::write(
            &pem_path,
            "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        std::fs::write(
            &stub,
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do\n  case \"$1\" in\n    --config) cfg=\"$2\"; shift 2 ;;\n    --listen-uds) sock=\"$2\"; shift 2 ;;\n    *) shift ;;\n  esac\ndone\ncp \"$cfg\" \"$cfg.captured\"\ntouch \"$sock\"\nsleep 30\n",
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let saved_bin = std::env::var_os("MVM_HOST_NETD_PATH");
        let saved_roots = std::env::var_os(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV);
        unsafe {
            std::env::set_var("MVM_HOST_NETD_PATH", &stub);
            std::env::set_var(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV, &pem_path);
        }

        let socket = spawn_mvm_net_authority(MvmNetSpawnParams {
            vm_name: "tls-netd-pem-roots-test",
            state_dir: &dir,
            tenant: "local",
            secrets: &[],
            network_policy: &NetworkPolicy::allow_list(vec![HostPort::new("localhost", 443)]),
        })
        .unwrap();

        unsafe {
            match saved_bin {
                Some(value) => std::env::set_var("MVM_HOST_NETD_PATH", value),
                None => std::env::remove_var("MVM_HOST_NETD_PATH"),
            }
            match saved_roots {
                Some(value) => std::env::set_var(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV, value),
                None => std::env::remove_var(HOST_NETD_UPSTREAM_ROOTS_PEM_FILE_ENV),
            }
        }

        assert_eq!(socket, dir.join(HOST_NETD_SOCKET_FILE));
        let captured =
            std::fs::read_to_string(dir.join(format!("{HOST_NETD_CONFIG_FILE}.captured"))).unwrap();
        let cfg: serde_json::Value = serde_json::from_str(&captured).unwrap();
        assert_eq!(cfg["network_policy"]["type"], "allowlist");
        assert!(cfg["tls_intermediate"].is_object());
        assert_eq!(cfg["upstream_roots"]["type"], "pem_bundle");
        assert!(
            cfg["upstream_roots"]["pem"]
                .as_str()
                .expect("pem bundle string")
                .contains("BEGIN CERTIFICATE")
        );

        reap_mvm_net_authority(&dir);
        assert!(!dir.join(HOST_NETD_PID_FILE).exists());
        assert!(!dir.join(HOST_NETD_SOCKET_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn transparent_net_stream_transforms_derive_secret_plugins_from_plan_secret() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("sk-live-12345".to_string())),
            )
            .unwrap();
        let config = transparent_net_stream_transforms(
            "local",
            &[PlanSecretBinding {
                name: "OPENAI_API_KEY".into(),
                source: SecretSource::Keystore {
                    address: "openai".into(),
                },
                guest_mount: Some(SecretGuestMount::Env {
                    var: "OPENAI_API_KEY".into(),
                }),
                allowed_hosts: vec!["api.openai.com".into(), "*.openai.com".into()],
            }],
            &store,
        )
        .unwrap();

        assert_eq!(config.response_leak_guard_secret_values, ["sk-live-12345"]);
        assert_eq!(config.secret_replacement_bindings.len(), 2);
        assert_eq!(
            config.secret_replacement_bindings[0].env_var,
            "OPENAI_API_KEY"
        );
        assert_eq!(
            config.secret_replacement_bindings[1].target_host,
            "*.openai.com"
        );
    }

    #[test]
    fn transparent_net_stream_transforms_derive_file_mount_replacement_binding() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSecretStore::with_dir(dir.path());
        store
            .put(
                "local",
                "openai",
                &SecretBox::new(Box::new("sk-live-12345".to_string())),
            )
            .unwrap();
        let config = transparent_net_stream_transforms(
            "local",
            &[PlanSecretBinding {
                name: "/run/mvm-secrets/openai".into(),
                source: SecretSource::Keystore {
                    address: "openai".into(),
                },
                guest_mount: Some(SecretGuestMount::File {
                    path: "/run/mvm-secrets/openai".into(),
                }),
                allowed_hosts: vec!["api.openai.com".into()],
            }],
            &store,
        )
        .unwrap();

        assert_eq!(config.secret_replacement_bindings.len(), 1);
        assert_eq!(
            config.secret_replacement_bindings[0].env_var,
            "/run/mvm-secrets/openai"
        );
        assert_eq!(
            config.secret_replacement_bindings[0].placeholder(),
            "mvm-managed:/run/mvm-secrets/openai"
        );
        assert_eq!(config.response_leak_guard_secret_values, ["sk-live-12345"]);
    }

    #[test]
    fn reap_mvm_net_authority_kills_recorded_process_and_cleans_state() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(HOST_NETD_SOCKET_FILE);
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("trap '' TERM; while :; do sleep 1; done")
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;
        std::fs::write(dir.path().join(HOST_NETD_PID_FILE), pid.to_string()).unwrap();
        assert!(pid_alive_or_reap(pid), "stub authority should be running");

        reap_mvm_net_authority(dir.path());

        assert!(
            !pid_alive_or_reap(pid),
            "reap must terminate even a SIGTERM-ignoring authority"
        );
        assert!(!dir.path().join(HOST_NETD_PID_FILE).exists());
        assert!(!dir.path().join(HOST_NETD_SOCKET_FILE).exists());
        let _ = child.kill();
        let _ = child.wait();
    }
}
