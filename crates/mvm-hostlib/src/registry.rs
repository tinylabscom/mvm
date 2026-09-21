//! The machine-readable host-ABI contract: one registry row per dotted
//! method.
//!
//! This registry is the single source of truth the SDK stub generators read.
//! `emit_host_abi_schema` renders every row's request and reply types into
//! one JSON Schema document; `emit_host_abi_methods` renders the method
//! table (dotted name, schema key, classification, summary). The language
//! bindings consume the generated stubs, so no binding hand-maintains a
//! method list, and a method added here reaches both SDKs on the next
//! `cargo xtask gen-stubs`.
//!
//! The registry must name exactly the methods the library answers at
//! runtime; the unit tests below hold the two lists to each other.

use mvm_agentd::vsock::{FsStat, ProcInfo};
use mvm_core::client::dto::{MachineFilter, MachineState};
use serde::Serialize;

use crate::dispatch::{
    BACKEND_CAPABILITIES, Empty as DispatchEmpty, LogsReply, LogsRequest, MACHINE_INSPECT,
    MACHINE_LIST, MACHINE_LOGS, MachineRef,
};
use crate::guest::{
    AcceptedReply, DataReply, FS_LIST, FS_MKDIR, FS_READ, FS_REMOVE, FS_RENAME, FS_STAT, FS_WRITE,
    ListReply, MachineRequest, MkdirRequest, PROC_KILL, PROC_LIST, PROC_SIGNAL, PROC_START,
    PROC_STDIN, PROC_WAIT, PathRequest, ProcessRequest, ReadRequest, RemoveRequest, RemovedReply,
    RenameRequest, SignalRequest, StartRequest, StartedReply, StatRequest, StdinRequest, WaitReply,
    WaitRequest, WriteRequest, WrittenReply,
};

/// How a method is classified for admission policy. `DevOnly` methods are
/// the guest-agent verbs a sealed image refuses; the classification travels
/// with the generated table so a binding can say why a refusal happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// Safe to offer on a production-admitted machine.
    ProdSafe,
    /// Development-only guest-agent verb.
    DevOnly,
}

/// A type's JSON Schema root plus the `$ref` definitions it names. Kept
/// split so the emitter can merge every row's definitions into one document
/// and rewrite nothing.
#[derive(Debug)]
pub struct SchemaAndDefs {
    /// The schema root: inline for primitive shapes, `$ref` for named ones.
    pub root: serde_json::Value,
    /// `(name, schema)` pairs this root references.
    pub defs: Vec<(String, serde_json::Value)>,
}

/// The schema of `T`, split into root and definitions.
fn schema_of<T: schemars::JsonSchema>() -> SchemaAndDefs {
    let schema = schemars::schema_for!(T);
    let defs = schema
        .definitions
        .iter()
        .map(|(name, def)| {
            (
                name.clone(),
                serde_json::to_value(def).expect("a schema definition always serializes"),
            )
        })
        .collect();
    let mut root = serde_json::to_value(&schema).expect("a generated schema always serializes");
    if let Some(obj) = root.as_object_mut() {
        // Definitions merge into the document's own map; keeping a copy on
        // every root would fight the merge.
        obj.remove("definitions");
        obj.remove("$schema");
    }
    SchemaAndDefs { root, defs }
}

/// The schema of a homogeneous array of `T`.
fn array_of<T: schemars::JsonSchema>() -> SchemaAndDefs {
    let item = schema_of::<T>();
    SchemaAndDefs {
        root: serde_json::json!({ "type": "array", "items": item.root }),
        defs: item.defs,
    }
}

/// One dotted method, its wire types, and its classification.
#[derive(Debug)]
pub struct MethodDef {
    /// The dotted name a call carries (`machine.list`).
    pub name: &'static str,
    /// The identifier-safe key the generated stubs use (`machine_list`).
    pub key: &'static str,
    /// One-line description, rendered as the generated constant's doc.
    pub summary: &'static str,
    /// Admission classification.
    pub classification: Classification,
    /// The request schema.
    pub request: fn() -> SchemaAndDefs,
    /// The reply schema.
    pub reply: fn() -> SchemaAndDefs,
}

/// The report behind `backend.capabilities` is owned by the capability
/// negotiation module; it is deliberately not re-modeled here, so the ABI
/// schema stays small and the two cannot drift. A binding reads the reply
/// as untyped JSON.
fn any_json() -> SchemaAndDefs {
    // An untyped object rather than the boolean `true` schema: the pinned
    // datamodel-codegen version cannot parse a boolean subschema, and an
    // unbounded object is the honest shape for an opaque report.
    SchemaAndDefs {
        root: serde_json::json!({
            "type": "object",
            "description": "Opaque report; the shape is owned by the capability negotiation module.",
        }),
        defs: Vec::new(),
    }
}

/// Every method the ABI answers, in dotted-name order within each family.
pub const REGISTRY: &[MethodDef] = &[
    MethodDef {
        name: BACKEND_CAPABILITIES,
        key: "backend_capabilities",
        summary: "Reports what the backend can do.",
        classification: Classification::ProdSafe,
        request: schema_of::<DispatchEmpty>,
        reply: any_json,
    },
    MethodDef {
        name: MACHINE_INSPECT,
        key: "machine_inspect",
        summary: "Inspects one machine.",
        classification: Classification::ProdSafe,
        request: schema_of::<MachineRef>,
        reply: schema_of::<MachineState>,
    },
    MethodDef {
        name: MACHINE_LIST,
        key: "machine_list",
        summary: "Lists machines, optionally filtered.",
        classification: Classification::ProdSafe,
        request: schema_of::<MachineFilter>,
        reply: array_of::<MachineState>,
    },
    MethodDef {
        name: MACHINE_LOGS,
        key: "machine_logs",
        summary: "Returns captured console output, base64-encoded.",
        classification: Classification::ProdSafe,
        request: schema_of::<LogsRequest>,
        reply: schema_of::<LogsReply>,
    },
    MethodDef {
        name: FS_LIST,
        key: "guest_fs_list",
        summary: "Lists a directory in the guest.",
        classification: Classification::DevOnly,
        request: schema_of::<PathRequest>,
        reply: schema_of::<ListReply>,
    },
    MethodDef {
        name: FS_MKDIR,
        key: "guest_fs_mkdir",
        summary: "Creates a directory in the guest.",
        classification: Classification::DevOnly,
        request: schema_of::<MkdirRequest>,
        reply: schema_of::<crate::guest::Empty>,
    },
    MethodDef {
        name: FS_READ,
        key: "guest_fs_read",
        summary: "Reads a file from the guest, base64-encoded.",
        classification: Classification::DevOnly,
        request: schema_of::<ReadRequest>,
        reply: schema_of::<DataReply>,
    },
    MethodDef {
        name: FS_REMOVE,
        key: "guest_fs_remove",
        summary: "Removes a path in the guest.",
        classification: Classification::DevOnly,
        request: schema_of::<RemoveRequest>,
        reply: schema_of::<RemovedReply>,
    },
    MethodDef {
        name: FS_RENAME,
        key: "guest_fs_rename",
        summary: "Moves a path in the guest.",
        classification: Classification::DevOnly,
        request: schema_of::<RenameRequest>,
        reply: schema_of::<crate::guest::Empty>,
    },
    MethodDef {
        name: FS_STAT,
        key: "guest_fs_stat",
        summary: "Stats a path in the guest.",
        classification: Classification::DevOnly,
        request: schema_of::<StatRequest>,
        reply: schema_of::<FsStat>,
    },
    MethodDef {
        name: FS_WRITE,
        key: "guest_fs_write",
        summary: "Writes a file in the guest, base64-encoded.",
        classification: Classification::DevOnly,
        request: schema_of::<WriteRequest>,
        reply: schema_of::<WrittenReply>,
    },
    MethodDef {
        name: PROC_KILL,
        key: "guest_proc_kill",
        summary: "Kills a tracked guest process.",
        classification: Classification::DevOnly,
        request: schema_of::<ProcessRequest>,
        reply: schema_of::<crate::guest::Empty>,
    },
    MethodDef {
        name: PROC_LIST,
        key: "guest_proc_list",
        summary: "Lists tracked guest processes.",
        classification: Classification::DevOnly,
        request: schema_of::<MachineRequest>,
        reply: array_of::<ProcInfo>,
    },
    MethodDef {
        name: PROC_SIGNAL,
        key: "guest_proc_signal",
        summary: "Signals a tracked guest process.",
        classification: Classification::DevOnly,
        request: schema_of::<SignalRequest>,
        reply: schema_of::<crate::guest::Empty>,
    },
    MethodDef {
        name: PROC_START,
        key: "guest_proc_start",
        summary: "Starts a process in the guest.",
        classification: Classification::DevOnly,
        request: schema_of::<StartRequest>,
        reply: schema_of::<StartedReply>,
    },
    MethodDef {
        name: PROC_STDIN,
        key: "guest_proc_stdin",
        summary: "Writes a tracked process's stdin, base64-encoded.",
        classification: Classification::DevOnly,
        request: schema_of::<StdinRequest>,
        reply: schema_of::<AcceptedReply>,
    },
    MethodDef {
        name: PROC_WAIT,
        key: "guest_proc_wait",
        summary: "Waits for a guest process to end, returning its output.",
        classification: Classification::DevOnly,
        request: schema_of::<WaitRequest>,
        reply: schema_of::<WaitReply>,
    },
];

/// `machine_list` -> `MachineList`: the title the generated wrapper class
/// carries.
fn title_of(key: &str) -> String {
    key.split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// Assemble the whole ABI into one JSON Schema document: a root object keyed
/// by method key, each property referencing that method's named request and
/// reply definitions, with every referenced type merged at the top level.
///
/// Request and reply schemas are registered under per-method names
/// (`MachineListRequest`, `MachineListReply`) rather than embedded inline,
/// because the pinned generators name an inline nested schema after the
/// property (`Request`, `Request1`), which is neither stable nor meaningful
/// across regenerations.
///
/// Fails when two types share a definition name with different shapes —
/// that is a naming collision the emitters must surface, not silently pick
/// one side of.
pub fn schema_document() -> anyhow::Result<serde_json::Value> {
    let mut properties = serde_json::Map::new();
    let mut definitions = serde_json::Map::new();
    let mut required = Vec::new();

    let mut insert_def = |name: String,
                          schema: serde_json::Value,
                          definitions: &mut serde_json::Map<String, serde_json::Value>|
     -> anyhow::Result<()> {
        match definitions.get(&name) {
            Some(existing) if *existing == schema => Ok(()),
            Some(_) => anyhow::bail!("two ABI types collide on the schema name `{name}`"),
            None => {
                definitions.insert(name, schema);
                Ok(())
            }
        }
    };

    for method in REGISTRY {
        let title = title_of(method.key);
        let request = (method.request)();
        let reply = (method.reply)();
        for (name, schema) in request.defs.into_iter().chain(reply.defs) {
            insert_def(name, schema, &mut definitions)?;
        }
        insert_def(format!("{title}Request"), request.root, &mut definitions)?;
        insert_def(format!("{title}Reply"), reply.root, &mut definitions)?;
        let mut wrapper = serde_json::Map::new();
        wrapper.insert("title".into(), title.into());
        wrapper.insert("type".into(), "object".into());
        wrapper.insert("additionalProperties".into(), false.into());
        wrapper.insert("required".into(), serde_json::json!(["request", "reply"]));
        wrapper.insert(
            "properties".into(),
            serde_json::json!({
                "request": { "$ref": format!("#/definitions/{}Request", title_of(method.key)) },
                "reply": { "$ref": format!("#/definitions/{}Reply", title_of(method.key)) },
            }),
        );
        properties.insert(method.key.to_string(), wrapper.into());
        required.push(method.key);
    }

    let mut doc = serde_json::Map::new();
    doc.insert(
        "$schema".into(),
        "http://json-schema.org/draft-07/schema#".into(),
    );
    doc.insert("title".into(), "HostAbi".into());
    doc.insert("type".into(), "object".into());
    doc.insert("additionalProperties".into(), false.into());
    doc.insert("required".into(), required.into());
    doc.insert("properties".into(), properties.into());
    doc.insert("definitions".into(), definitions.into());
    Ok(doc.into())
}

/// The method-table manifest the per-language constant renderers consume.
pub fn method_manifest() -> serde_json::Value {
    serde_json::json!({
        "version": 0,
        "abi_major": crate::MVM_HOSTLIB_ABI_MAJOR,
        "abi_minor": crate::MVM_HOSTLIB_ABI_MINOR,
        "methods": REGISTRY.iter().map(|m| serde_json::json!({
            "name": m.name,
            "key": m.key,
            "classification": m.classification,
            "summary": m.summary,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry and the runtime dispatch tables must name exactly the
    /// same methods; a method added to one and not the other is a binding
    /// that advertises what the library refuses, or the reverse.
    #[test]
    fn registry_names_match_the_runtime_method_tables() {
        let mut registry: Vec<&str> = REGISTRY.iter().map(|m| m.name).collect();
        registry.sort_unstable();
        let mut runtime: Vec<&str> = crate::dispatch::METHODS
            .iter()
            .chain(crate::guest::METHODS.iter())
            .copied()
            .collect();
        runtime.sort_unstable();
        assert_eq!(registry, runtime);
    }

    #[test]
    fn keys_are_unique_and_dotted_names_are_unique() {
        let mut keys: Vec<&str> = REGISTRY.iter().map(|m| m.key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), REGISTRY.len(), "duplicate schema key");
        let mut names: Vec<&str> = REGISTRY.iter().map(|m| m.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), REGISTRY.len(), "duplicate method name");
    }

    #[test]
    fn keys_are_identifier_safe() {
        for method in REGISTRY {
            assert!(
                method
                    .key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{} is not identifier-safe",
                method.key
            );
            assert!(method.key.starts_with(|c: char| c.is_ascii_lowercase()));
        }
    }

    #[test]
    fn schema_document_covers_every_method_and_merges_definitions() {
        let doc = schema_document().expect("the ABI schema assembles");
        let obj = doc.as_object().expect("an object document");
        let properties = obj["properties"].as_object().expect("properties");
        let definitions = obj["definitions"].as_object().expect("definitions");
        for method in REGISTRY {
            let title = title_of(method.key);
            for side in ["Request", "Reply"] {
                let name = format!("{title}{side}");
                let refr = properties[method.key]["properties"][side.to_lowercase()]["$ref"]
                    .as_str()
                    .expect("a named reference");
                assert_eq!(refr, format!("#/definitions/{name}"), "{}", method.name);
                assert!(definitions.contains_key(&name), "{name} is defined");
            }
        }
    }

    #[test]
    fn title_of_camel_cases_keys() {
        assert_eq!(title_of("machine_list"), "MachineList");
        assert_eq!(title_of("guest_proc_start"), "GuestProcStart");
    }

    #[test]
    fn the_manifest_carries_the_abi_version_and_every_method() {
        let manifest = method_manifest();
        assert_eq!(manifest["abi_major"], crate::MVM_HOSTLIB_ABI_MAJOR);
        assert_eq!(manifest["abi_minor"], crate::MVM_HOSTLIB_ABI_MINOR);
        assert_eq!(
            manifest["methods"].as_array().expect("methods").len(),
            REGISTRY.len()
        );
    }
}
