//! Endpoint routes for one launch: the project manifest's `[[network.routes]]`
//! plus the `--allow-endpoint` flags, merged into the route list the signed
//! plan carries.
//!
//! `--allow-endpoint "GET https://api.github.com/repos/org/**"` admits that
//! host as `--allow-host` would, and adds a route there whose one rule allows
//! `GET` under the glob and whose default refuses everything else. Several
//! flags for one destination become several rules of one route, tried in the
//! order given. The flag is the operator's explicit grant to intercept that
//! destination so its rules can be enforced.
//!
//! Composition only narrows. A flag naming a destination the manifest already
//! routes is refused rather than merged: adding an allow rule to a project's
//! route would widen what the project declared.

use anyhow::{Context, Result, bail};
use mvm_contract::policy::routes::{
    EgressRoute, EndpointRule, RouteOutcome, RouteSet, parse_endpoint_spec,
};

/// What a launch's routes add to its policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunRoutes {
    /// `HOST:PORT` entries to admit, one per concrete route host.
    pub allow_host: Vec<String>,
    /// The validated routes, in order.
    pub routes: Vec<EgressRoute>,
}

impl RunRoutes {
    /// `allow_host` extended with the route hosts not already in it.
    #[must_use]
    pub fn with_allow_host(&self, allow_host: &[String]) -> Vec<String> {
        let mut all = allow_host.to_vec();
        for entry in &self.allow_host {
            if !all.contains(entry) {
                all.push(entry.clone());
            }
        }
        all
    }

    /// Whether the launch carries no routes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// A route id derived from its destination: `endpoint-<host>-<port>`, with a
/// wildcard's `*` spelled `any`.
fn derived_id(host: &str, port: u16) -> String {
    format!("endpoint-{}-{port}", host.replace('*', "any"))
}

/// Parse `--allow-endpoint` specs into one route per destination.
///
/// # Errors
///
/// The first malformed spec, named.
pub fn routes_from_endpoint_flags(specs: &[String]) -> Result<Vec<EgressRoute>> {
    let mut routes: Vec<EgressRoute> = Vec::new();
    for spec in specs {
        let (method, host, port, path) = parse_endpoint_spec(spec)
            .map_err(|reason| anyhow::anyhow!("invalid --allow-endpoint {spec:?}: {reason}"))?;
        let rule = EndpointRule {
            id: None,
            method,
            path,
            outcome: RouteOutcome::Allow,
        };
        match routes.iter_mut().find(|r| r.host == host && r.port == port) {
            Some(route) => route.rules.push(rule),
            None => routes.push(EgressRoute {
                id: derived_id(&host, port),
                host,
                port,
                rules: vec![rule],
                otherwise: RouteOutcome::Deny,
                intercept: true,
            }),
        }
    }
    Ok(routes)
}

/// Merge the manifest's routes with the flags' and validate the result.
///
/// # Errors
///
/// A malformed flag, a flag naming a destination the manifest routes, or a
/// route set that does not validate.
pub fn resolve_run_routes(
    allow_endpoint: &[String],
    manifest_routes: &[EgressRoute],
) -> Result<RunRoutes> {
    let flagged = routes_from_endpoint_flags(allow_endpoint)?;
    if let Some((flag, declared)) = flagged.iter().find_map(|flag| {
        manifest_routes
            .iter()
            .find(|m| m.host == flag.host && m.port == flag.port)
            .map(|m| (flag, m))
    }) {
        bail!(
            "--allow-endpoint for {}:{} would widen the manifest's route {:?}; \
             edit that route instead",
            flag.host,
            flag.port,
            declared.id
        );
    }
    let mut routes = manifest_routes.to_vec();
    routes.extend(flagged);
    let set = RouteSet::new(routes).context("the launch's endpoint routes do not validate")?;
    let allow_host = set
        .routes()
        .iter()
        .filter(|route| !route.host.starts_with("*."))
        .map(|route| format!("{}:{}", route.host, route.port))
        .collect();
    Ok(RunRoutes {
        allow_host,
        routes: set.routes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(specs: &[&str]) -> Vec<String> {
        specs.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn flags_for_one_destination_become_rules_of_one_route() {
        let resolved = resolve_run_routes(
            &flags(&[
                "GET https://api.github.com/repos/org/**",
                "POST https://api.github.com/repos/org/*/issues",
                "https://example.com/public/**",
            ]),
            &[],
        )
        .unwrap();
        assert_eq!(resolved.routes.len(), 2);
        let github = &resolved.routes[0];
        assert_eq!(github.id, "endpoint-api.github.com-443");
        assert_eq!(github.rules.len(), 2);
        assert_eq!(github.otherwise, RouteOutcome::Deny);
        assert!(github.intercept, "the flag is the interception grant");
        assert_eq!(
            resolved.allow_host,
            ["api.github.com:443", "example.com:443"]
        );
        let set = RouteSet::new(resolved.routes).unwrap();
        let outcome = |m, p| set.decide("api.github.com", 443, m, p).unwrap().outcome;
        assert_eq!(outcome("GET", "/repos/org/x"), RouteOutcome::Allow);
        assert_eq!(outcome("POST", "/repos/org/x"), RouteOutcome::Deny);
        assert_eq!(outcome("POST", "/repos/org/x/issues"), RouteOutcome::Allow);
    }

    #[test]
    fn a_flag_cannot_widen_a_manifest_route() {
        let manifest =
            routes_from_endpoint_flags(&flags(&["GET https://api.github.com/"])).unwrap();
        let err =
            resolve_run_routes(&flags(&["POST https://api.github.com/**"]), &manifest).unwrap_err();
        assert!(format!("{err:#}").contains("widen"), "{err:#}");
        // A different destination is fine.
        let ok = resolve_run_routes(&flags(&["https://example.com/"]), &manifest).unwrap();
        assert_eq!(ok.routes.len(), 2);
    }

    #[test]
    fn a_malformed_flag_is_refused_by_name() {
        let err = resolve_run_routes(&flags(&["GET api.github.com/repos"]), &[]).unwrap_err();
        assert!(format!("{err:#}").contains("--allow-endpoint"), "{err:#}");
    }
}
