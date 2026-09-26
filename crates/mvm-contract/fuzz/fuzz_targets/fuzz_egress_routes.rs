//! Fuzz the egress route set: decoding, validation, and the decision.
//!
//! A route set arrives in a signed plan, and every request on a terminated
//! flow is decided against it with a guest-chosen method and path. For any
//! input:
//!
//! - decoding, validation and deciding never panic;
//! - a path the decision cannot canonicalise is refused, never matched;
//! - the same request decides the same way twice;
//! - an `--allow-endpoint` spec either parses to a route that validates, or is
//!   refused — never both a parse and an invalid route.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_contract::policy::routes::{
    DecidedBy, EgressRoute, EndpointRule, RouteOutcome, RouteSet, parse_endpoint_spec,
};

fuzz_target!(|data: &[u8]| {
    // Split: the first half is a route set, the rest a request.
    let mid = data.len() / 2;
    let (routes, request) = data.split_at(mid);

    if let Ok(set) = RouteSet::from_json(routes) {
        let request = String::from_utf8_lossy(request);
        let mut parts = request.splitn(3, ' ');
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("/");
        let host = parts.next().unwrap_or("api.example.com");
        for route in set.routes() {
            let first = set.decide(&route.host, route.port, method, path);
            let second = set.decide(&route.host, route.port, method, path);
            assert_eq!(first, second, "a decision is a function of its inputs");
            if let Some(decision) = first
                && decision.decided_by == DecidedBy::AmbiguousPath
            {
                assert_eq!(decision.outcome, RouteOutcome::Deny);
            }
        }
        let _ = set.decide(host, 443, method, path);
    }

    let spec = String::from_utf8_lossy(data);
    if let Ok((method, host, port, path)) = parse_endpoint_spec(&spec) {
        let route = EgressRoute {
            id: "fuzz".into(),
            host,
            port,
            rules: vec![EndpointRule {
                id: None,
                method,
                path,
                outcome: RouteOutcome::Allow,
            }],
            otherwise: RouteOutcome::Deny,
            intercept: true,
        };
        if port != 0 {
            assert!(
                RouteSet::new(vec![route]).is_ok(),
                "a parsed endpoint spec builds a valid route"
            );
        }
    }
});
