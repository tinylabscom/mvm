//! Package policy is a requirement, never an operator grant.

use super::merge::{Layer, canonical_allow, deny_covers, merge_layers, split_host_port};
use super::{LayerOrigin, PolicyError, ResolvedPolicy};

fn prevented(key: &str) -> PolicyError {
    PolicyError::new(
        "application package",
        "local policy prevents this required capability; select a compatible local --policy",
    )
    .at_key(key)
}

/// Check positive package requirements against explicit local authority before
/// using the ordinary layer merger. Neither input nor its backing file changes.
///
/// # Errors
///
/// Missing local authority, denied requirements, or unsupported narrowing.
pub fn compose_package(
    package: &ResolvedPolicy,
    local: &ResolvedPolicy,
) -> Result<ResolvedPolicy, PolicyError> {
    // Resolution can discard requests denied by another package layer or
    // unsupported for signed packs. Do not silently run without requirements.
    if !package.notes.is_empty() {
        return Err(prevented("package.policy"));
    }
    check_requirements(package, local)?;
    let mut result = merge_layers(&[
        Layer {
            label: "application package".into(),
            file: None,
            origin: LayerOrigin::Pack,
            body: package.policy.clone(),
        },
        Layer {
            label: "local policy".into(),
            file: None,
            origin: LayerOrigin::User,
            body: local.policy.clone(),
        },
    ])?;
    check_requirements(package, &result)?;
    result.backend_conditioned = package.backend_conditioned || local.backend_conditioned;
    result
        .notes
        .extend(package.notes.iter().chain(&local.notes).cloned());
    Ok(result)
}

fn check_requirements(package: &ResolvedPolicy, local: &ResolvedPolicy) -> Result<(), PolicyError> {
    let request = &package.policy;
    let authority = &local.policy;
    for host in &request.network.allow {
        let canonical = canonical_allow(host).map_err(|_| prevented("network.allow"))?;
        let (host, port) = split_host_port(&canonical);
        if authority.network.block == Some(true)
            || !authority
                .network
                .allow
                .iter()
                .any(|entry| canonical_allow(entry).is_ok_and(|entry| entry == canonical))
            || authority
                .network
                .deny
                .iter()
                .any(|deny| deny_covers(deny, host, port))
        {
            return Err(prevented(&format!("network.allow.{canonical}")));
        }
    }
    for route in &request.network.routes {
        if authority.network.block == Some(true)
            || !authority.network.routes.contains(route)
            || authority
                .network
                .deny
                .iter()
                .any(|deny| deny_covers(deny, &route.host, route.port))
        {
            return Err(prevented(&format!("network.routes.{}", route.id)));
        }
    }
    for binding in &request.secrets.bind {
        if !authority.secrets.bind.contains(binding)
            || authority.secrets.deny.contains(&binding.name)
        {
            return Err(prevented(&format!("secrets.bind.{}", binding.name)));
        }
    }
    for name in &request.env.allow {
        if !authority.env.allow.contains(name) || authority.env.deny.contains(name) {
            return Err(prevented(&format!("env.allow.{name}")));
        }
    }
    if !request.env.readmit.is_empty() {
        return Err(prevented("env.readmit"));
    }
    for share in &request.shares.mount {
        if !authority.shares.mount.contains(share)
            || authority
                .shares
                .deny
                .iter()
                .any(|deny| std::path::Path::new(&share.host).starts_with(deny))
        {
            return Err(prevented(&format!("shares.mount.{}", share.guest)));
        }
    }
    for (names, allowed, key) in [
        (&request.tools.allow, &authority.tools.allow, "tools.allow"),
        (&request.tools.ask, &authority.tools.ask, "tools.ask"),
    ] {
        for name in names {
            if !allowed.contains(name)
                || authority.tools.deny.contains(name)
                || (key == "tools.allow" && authority.tools.ask.contains(name))
            {
                return Err(prevented(&format!("{key}.{name}")));
            }
        }
    }
    for (name, detail) in &request.tools.detail {
        if authority.tools.detail.get(name) != Some(detail)
            || authority.tools.deny.contains(name)
            || !(authority.tools.allow.contains(name) || authority.tools.ask.contains(name))
        {
            return Err(prevented(&format!("tools.detail.{name}")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(host: &str) -> ResolvedPolicy {
        let mut policy = ResolvedPolicy::empty();
        policy.policy.network.allow.push(host.into());
        policy
    }

    #[test]
    fn local_authority_is_required_and_denies_win() {
        let package = network("required.test:443");
        assert!(compose_package(&package, &network("other.test")).is_err());
        let mut local = package.clone();
        local.policy.network.deny.push("required.test".into());
        assert!(compose_package(&package, &local).is_err());
        local.policy.network.block = Some(true);
        assert!(compose_package(&package, &local).is_err());
    }

    #[test]
    fn discarded_package_requests_and_effective_denials_are_refused() {
        let mut package = network("required.test:443");
        let local = package.clone();
        package
            .notes
            .push("a request was discarded during resolution".into());
        assert!(compose_package(&package, &local).is_err());
        package.notes.clear();
        package.policy.network.deny.push("required.test".into());
        assert!(compose_package(&package, &local).is_err());
    }

    #[test]
    fn compatible_composition_is_deterministic_and_immutable_with_minimum_resources() {
        let mut package = network("required.test:443");
        package.policy.resources.wall_clock_secs = Some(60);
        let before = package.clone();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signed-policy.json");
        let bytes = serde_json::to_vec(&package.policy).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let mut local = network("required.test");
        local.policy.resources.wall_clock_secs = Some(20);
        let result = compose_package(&package, &local).unwrap();
        assert_eq!(result.policy.resources.wall_clock_secs, Some(20));
        assert_eq!(result, compose_package(&package, &local).unwrap());
        assert_eq!(package, before);
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn package_cannot_introduce_other_authority() {
        for body in [
            r#"{"env":{"allow":["TOKEN"]}}"#,
            r#"{"env":{"readmit":["LD_PRELOAD"]}}"#,
            r#"{"secrets":{"bind":[{"name":"TOKEN"}]}}"#,
            r#"{"shares":{"mount":[{"host":"/work","guest":"/work"}]}}"#,
            r#"{"tools":{"allow":["shell"]}}"#,
            r#"{"tools":{"ask":["shell"]}}"#,
            r#"{"tools":{"detail":{"shell":{"executable":"/bin/sh"}}}}"#,
        ] {
            let mut package = ResolvedPolicy::empty();
            package.policy = serde_json::from_str(body).unwrap();
            assert!(
                compose_package(&package, &ResolvedPolicy::empty()).is_err(),
                "{body}"
            );
        }
    }
}
