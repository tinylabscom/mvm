use mvm_contract::pack_spec::PackSpec;
use mvm_contract::pack_spec_v2::ComposablePackSpec;
use mvm_contract::pack_spec_v3::{
    ComposedGraph, ComposedGraphError, EntrypointRequest, GraphNode, SelectedEntrypoint,
    SignedPackPin,
};
use serde_json::{Value, json};

fn graph() -> Value {
    let digest = "a".repeat(64);
    json!({
        "schema": "mvm.pack-spec/v3",
        "graph": [
            {"kind": "runtime", "pin": {"name": "runtime/python", "version": "2.0.1", "manifest_sha256": digest}},
            {"kind": "tool", "pin": {"name": "tool/grep", "version": "1.0.0", "manifest_sha256": digest}},
            {"kind": "application", "pin": {"name": "agent/first", "version": "1.0.0", "manifest_sha256": digest}},
            {"kind": "application", "pin": {"name": "agent/last", "version": "1.0.0", "manifest_sha256": digest}}
        ]
    })
}

fn request(runtime: Option<Vec<&str>>, workload: Option<Vec<&str>>) -> EntrypointRequest {
    serde_json::from_value(json!({
        "schema": "mvm.entrypoint-request/v1",
        "runtime_command_override": runtime,
        "workload_command": workload,
    }))
    .unwrap()
}

fn verified_default<'a>(
    pin: &SignedPackPin,
    first: &'a [String],
    last: &'a [String],
) -> Option<&'a [String]> {
    match pin.name.as_str() {
        "agent/first" => Some(first),
        "agent/last" => Some(last),
        _ => None,
    }
}

#[test]
fn precedence_is_independent_of_graph_order_and_all_eight_combinations() {
    let graph: ComposedGraph = serde_json::from_value(graph()).unwrap();
    let first = vec!["/srv/app/first".into(), "--literal".into()];
    let last = vec!["/srv/app/last".into()];
    for runtime in [None, Some(vec!["/usr/bin/runtime"])] {
        for workload in [None, Some(vec!["/usr/bin/workload"])] {
            for declared in [false, true] {
                let selection = request(runtime.clone(), workload.clone());
                let selected = graph
                    .select_entrypoint(&selection, |pin| {
                        Ok(if declared {
                            verified_default(pin, &first, &last)
                        } else {
                            None
                        })
                    })
                    .unwrap();
                match (runtime.is_some(), workload.is_some(), declared, selected) {
                    (true, _, _, Some(SelectedEntrypoint::RuntimeOverride(argv))) => {
                        assert_eq!(argv, ["/usr/bin/runtime"]);
                    }
                    (false, true, _, Some(SelectedEntrypoint::Workload(argv))) => {
                        assert_eq!(argv, ["/usr/bin/workload"]);
                    }
                    (false, false, true, Some(SelectedEntrypoint::Application { pin, argv })) => {
                        assert_eq!(pin.name, "agent/last");
                        assert_eq!(argv, ["/srv/app/last"]);
                    }
                    (false, false, false, None) => {}
                    other => panic!("unexpected selection: {other:?}"),
                }
            }
        }
    }
}

#[test]
fn last_declaring_application_wins_over_later_undeclared_application_and_tool() {
    let mut doc = graph();
    let tool = doc["graph"][1].clone();
    doc["graph"].as_array_mut().unwrap().remove(1);
    doc["graph"].as_array_mut().unwrap().push(tool);
    let graph: ComposedGraph = serde_json::from_value(doc).unwrap();
    let selection = request(None, None);
    let first = vec!["/srv/app/first".into(), "--literal".into()];
    assert!(matches!(
        graph.select_entrypoint(&selection, |pin| {
            Ok((pin.name == "agent/first").then_some(first.as_slice()))
        }),
        Ok(Some(SelectedEntrypoint::Application { pin, argv }))
            if pin.name == "agent/first" && argv == ["/srv/app/first", "--literal"]
    ));
}

#[test]
fn no_implicit_service_or_tool_startup() {
    let no_commands: ComposedGraph = serde_json::from_value(graph()).unwrap();
    let selection = request(None, None);
    assert_eq!(
        no_commands.select_entrypoint(&selection, |_| Ok(None)),
        Ok(None)
    );
    let mut doc = graph();
    doc["graph"][2]["command"] = json!(["/srv/app/bogus"]);
    assert!(serde_json::from_value::<ComposedGraph>(doc).is_err());
    let mut doc = graph();
    doc["graph"][0]["command"] = json!(["/usr/bin/python3"]);
    assert!(serde_json::from_value::<ComposedGraph>(doc).is_err());
    let mut doc = graph();
    doc["graph"][1]["services"] = json!(["daemon"]);
    assert!(serde_json::from_value::<ComposedGraph>(doc).is_err());
    let mut doc = graph();
    doc["services"] = json!(["daemon"]);
    assert!(serde_json::from_value::<ComposedGraph>(doc).is_err());
    let mut doc = graph();
    doc["graph"].as_array_mut().unwrap().remove(3);
    let graph: ComposedGraph = serde_json::from_value(doc).unwrap();
    assert_eq!(graph.select_entrypoint(&selection, |_| Ok(None)), Ok(None));
    assert_eq!(
        graph.select_entrypoint(&request(Some(vec!["/bin/explicit"]), None), |_| {
            Err(ComposedGraphError::Pin)
        }),
        Err(ComposedGraphError::Pin),
        "an unverified application cannot be hidden by a command override"
    );
}

#[test]
fn pins_are_exact_signed_manifest_references_and_conflicting_names_are_rejected() {
    for (field, bad) in [
        ("manifest_sha256", json!("A".repeat(64))),
        ("manifest_sha256", json!("f".repeat(63))),
        ("manifest_sha256", json!(format!("{}g", "a".repeat(63)))),
        ("version", json!("latest")),
        ("version", json!("1.0.0+local")),
        ("name", json!("runtime/python@2.0.1")),
    ] {
        let mut doc = graph();
        doc["graph"][0]["pin"][field] = bad;
        assert!(
            serde_json::from_value::<ComposedGraph>(doc).is_err(),
            "{field}"
        );
    }
    for field in ["signature", "publisher", "path", "digest"] {
        let mut doc = graph();
        doc["graph"][0]["pin"][field] = json!("unauthorized");
        assert!(
            serde_json::from_value::<ComposedGraph>(doc).is_err(),
            "{field}"
        );
    }
    let mut doc = graph();
    let duplicate = doc["graph"][0].clone();
    doc["graph"].as_array_mut().unwrap().push(duplicate);
    assert!(serde_json::from_value::<ComposedGraph>(doc).is_err());
    let mut doc = graph();
    doc["graph"][0]["pin"]["version"] = json!("3.0.0");
    let duplicate = doc["graph"][0].clone();
    doc["graph"].as_array_mut().unwrap().push(duplicate);
    assert!(serde_json::from_value::<ComposedGraph>(doc).is_err());
    let mut doc = graph();
    doc["graph"][3]["pin"]["name"] = json!("agent/first");
    assert!(serde_json::from_value::<ComposedGraph>(doc).is_err());
    let mut doc = graph();
    doc["graph"][3]["pin"]["manifest_sha256"] = json!("b".repeat(64));
    doc["graph"][3]["pin"]["name"] = json!("agent/first");
    assert!(serde_json::from_value::<ComposedGraph>(doc).is_err());
}

#[test]
fn closed_versions_roles_and_unsafe_commands_fail_on_deserialize_and_direct_construction() {
    for schema in ["mvm.pack-spec/v1", "mvm.pack-spec/v2", "mvm.pack-spec/v4"] {
        let mut doc = graph();
        doc["schema"] = json!(schema);
        assert!(serde_json::from_value::<ComposedGraph>(doc).is_err());
    }
    assert!(serde_json::from_value::<ComposablePackSpec>(graph()).is_err());
    assert!(serde_json::from_value::<PackSpec>(graph()).is_err());
    for invalid_graph in [json!([]), json!([graph()["graph"][0].clone()])] {
        let mut doc = graph();
        doc["graph"] = invalid_graph;
        assert!(serde_json::from_value::<ComposedGraph>(doc).is_err());
    }
    let mut doc = graph();
    doc["graph"][0]["pin"]["unexpected"] = json!(true);
    assert!(serde_json::from_value::<ComposedGraph>(doc).is_err());
    for (index, name) in [(0, "agent/first"), (1, "runtime/python"), (2, "tool/grep")] {
        let mut doc = graph();
        doc["graph"][index]["pin"]["name"] = json!(name);
        assert!(serde_json::from_value::<ComposedGraph>(doc).is_err());
    }
    for bad in [
        json!([]),
        json!(["relative"]),
        json!(["//usr/bin/app"]),
        json!(["/srv/app/../app"]),
        json!(["/srv/app/run\nnow"]),
        json!(["/srv/app/run", "a\0b"]),
        json!(["/srv/app/run", "x".repeat(16 * 1024)]),
    ] {
        let mut req = json!({"schema": "mvm.entrypoint-request/v1"});
        req["runtime_command_override"] = bad.clone();
        assert!(serde_json::from_value::<EntrypointRequest>(req).is_err());
        let graph: ComposedGraph = serde_json::from_value(graph()).unwrap();
        let selection = request(Some(vec!["/bin/safe"]), None);
        let argv: Vec<String> = serde_json::from_value(bad).unwrap();
        assert_eq!(
            graph.select_entrypoint(&selection, |_| Ok(Some(argv.as_slice()))),
            Err(ComposedGraphError::Command),
            "invalid verified default must not be hidden by override"
        );
    }
    let mut graph: ComposedGraph = serde_json::from_value(graph()).unwrap();
    if let GraphNode::Application { pin } = &mut graph.graph[2] {
        pin.manifest_sha256 = "0".into();
    }
    assert_eq!(graph.validate(), Err(ComposedGraphError::Pin));
    assert!(graph.canonical_json().is_err());
    let mut req = request(None, None);
    req.workload_command = Some(vec!["relative".into()]);
    assert!(req.validate().is_err());
    assert!(graph.select_entrypoint(&req, |_| Ok(None)).is_err());
    let mut req = request(Some(vec!["/bin/safe"]), None);
    req.workload_command = Some(vec!["relative".into()]);
    assert!(req.validate().is_err(), "lower-priority invalid command");
    assert_eq!(
        serde_json::from_value::<EntrypointRequest>(json!({
            "schema": "mvm.entrypoint-request/v1",
            "runtime_command_override": ["/usr/bin/sh", "-c", "echo allowed"]
        }))
        .unwrap()
        .validate(),
        Ok(()),
        "explicit shell use is governed by downstream admission, not this contract"
    );
    assert!(
        serde_json::from_str::<EntrypointRequest>(
            r#"{"schema":"mvm.entrypoint-request/v1","schema":"mvm.entrypoint-request/v1"}"#
        )
        .is_err()
    );
}

#[test]
fn canonical_roundtrip_preserves_order_and_no_command_does_not_materialize() {
    let graph: ComposedGraph = serde_json::from_value(graph()).unwrap();
    let bytes = graph.canonical_json().unwrap();
    let roundtrip: ComposedGraph = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(roundtrip, graph);
    assert_eq!(roundtrip.graph, graph.graph);
    let request = request(None, None);
    let bytes = request.canonical_json().unwrap();
    assert_eq!(
        serde_json::from_slice::<EntrypointRequest>(&bytes).unwrap(),
        request
    );
    assert!(
        serde_json::from_slice::<EntrypointRequest>(br#"{"schema":"mvm.entrypoint-request/v2"}"#)
            .is_err()
    );
    assert!(
        serde_json::from_slice::<EntrypointRequest>(
            br#"{"schema":"mvm.entrypoint-request/v1","services":[]}"#
        )
        .is_err()
    );
    let toml = r#"
schema = "mvm.pack-spec/v3"

[[graph]]
kind = "application"
[graph.pin]
name = "agent/example"
version = "1.0.0"
manifest_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;
    let from_toml: ComposedGraph = toml::from_str(toml).unwrap();
    assert_eq!(
        from_toml.graph[0].pin().name,
        "agent/example",
        "TOML and JSON share the same closed model"
    );
    assert_eq!(
        toml::from_str::<EntrypointRequest>(
            "schema = \"mvm.entrypoint-request/v1\"\nworkload_command = [\"/srv/app/run\"]"
        )
        .unwrap()
        .workload_command,
        Some(vec!["/srv/app/run".into()])
    );
}
