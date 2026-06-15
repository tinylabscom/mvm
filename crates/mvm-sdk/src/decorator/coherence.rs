//! One IR, two front-ends: the Python and TypeScript decorators are
//! mirror authoring surfaces over the *same* `Workload` IR. A given
//! app, declared identically in both languages, must lower to the
//! same canonical IR everywhere a host consumes it — otherwise the
//! two SDKs have silently drifted and a workload behaves differently
//! depending on which language declared it.
//!
//! Exactly one field is bound to the authoring language by
//! construction and is *expected* to differ: the entrypoint
//! `language` (the per-SDK shim selector — `"python"` vs `"node"`).
//! Everything else — id, image, `app.source` (the project root `.`,
//! identical regardless of which language declared it), resources,
//! network, env (literals and secret bindings), hooks, dependencies —
//! is the declared contract and must be byte-identical after
//! canonicalization.
//!
//! Scope note: the plan framed this as "four surfaces" (decorator,
//! runtime-record, `mvm.toml`, flake). Only the decorator is a
//! Workload authoring surface in both languages. `mvm.toml` is the
//! build-sizing manifest (its own boundary: no role / network / deps —
//! it points at a flake), the flake is the rendered derivation the one
//! engine *emits* (`compile::flake::build_flake_nix`, IR → Nix, not
//! Nix → IR), and runtime-record observes argv and so lowers to a
//! `Command` entrypoint that cannot equal the decorator's `Function`
//! shape. The honest, enforceable coherence is the Python⇔TypeScript
//! mirror, which is the "one IR" guarantee that actually exists.

use std::path::PathBuf;

use crate::decorator::{parse_python, parse_typescript};
use crate::ir::{Entrypoint, Source, Workload, canonicalize};

/// Marker the language-bound entrypoint field is normalized to so the
/// rest of the IR can be compared for equality.
const NORMALIZED: &str = "<normalized>";

/// The same hello-app, declared in Python.
const APP_PY: &str = r#"
import mvm

@mvm.app(
    name="hello-app",
    image=mvm.python_image(python="3.12"),
    resources=mvm.resources(cpu=2, memory_mb=512, rootfs_size_mb=1024),
    network=mvm.network(
        mode="bridge",
        ports=[{"guest": 8080, "host": 8080, "proto": "tcp"}],
    ),
    env={
        "MODEL_PATH": "/data/model.pt",
        "API_KEY": mvm.secret("api-key", type="bearer", hosts=["api.openai.com"]),
    },
)
def greet(name: str) -> str:
    return f"hello {name}"
"#;

/// The same hello-app, declared in TypeScript.
const APP_TS: &str = r#"
import * as mvm from "mvm-sdk";

export const greet = mvm.app({
  name: "hello-app",
  image: mvm.python_image({ python: "3.12" }),
  resources: mvm.resources({ cpu: 2, memory_mb: 512, rootfs_size_mb: 1024 }),
  network: mvm.network({
    mode: "bridge",
    ports: [{ guest: 8080, host: 8080, proto: "tcp" }],
  }),
  env: {
    "MODEL_PATH": "/data/model.pt",
    "API_KEY": mvm.secret("api-key", { type: "bearer", hosts: ["api.openai.com"] }),
  },
})((name: string): string => `hello ${name}`);
"#;

fn lower_py() -> Workload {
    parse_python(APP_PY.as_bytes(), &PathBuf::from("app.py"))
        .expect("python decorator parses")
        .0
}

fn lower_ts() -> Workload {
    parse_typescript(APP_TS.as_bytes(), &PathBuf::from("app.ts"))
        .expect("typescript decorator parses")
        .0
}

/// Erase the one intrinsically language-bound field (the entrypoint
/// shim `language`) so the remaining IR is the declared contract both
/// surfaces must agree on. `app.source` is deliberately *not* erased:
/// it is the project root (`.`) in either language, so it belongs to
/// the contract and a divergence there is a real bug this test should
/// catch.
fn erase_shim_language(mut w: Workload) -> Workload {
    for app in &mut w.apps {
        for ep in &mut app.entrypoints {
            if let Entrypoint::Function { language, .. } = ep {
                *language = NORMALIZED.to_string();
            }
        }
    }
    w
}

#[test]
fn python_and_typescript_lower_to_one_canonical_workload() {
    let py = lower_py();
    let ts = lower_ts();

    // Non-vacuous: the raw IRs genuinely differ — if they didn't, the
    // normalized equality below would prove nothing. They differ in
    // exactly one place: the entrypoint shim `language`.
    assert_ne!(
        canonicalize(&py).unwrap(),
        canonicalize(&ts).unwrap(),
        "raw Python and TypeScript IRs must differ in the shim language"
    );

    let py_norm = canonicalize(&erase_shim_language(py)).unwrap();
    let ts_norm = canonicalize(&erase_shim_language(ts)).unwrap();
    assert_eq!(
        py_norm, ts_norm,
        "the same app declared in Python and TypeScript must lower to one canonical Workload"
    );
}

#[test]
fn the_sole_divergence_is_the_entrypoint_shim_language() {
    // Pin the claim that the entrypoint shim `language` is the *only*
    // field that differs: the languages are `python` vs `node`, while
    // the sources are identical (both the project root `.`). A future
    // field that lowered differently per language (a real drift bug)
    // would survive normalization and fail
    // `python_and_typescript_lower_to_one_canonical_workload`.
    let py = lower_py();
    let ts = lower_ts();

    let py_lang = match &py.apps[0].entrypoints[0] {
        Entrypoint::Function { language, .. } => language.clone(),
        other => panic!("expected Function entrypoint, got {other:?}"),
    };
    let ts_lang = match &ts.apps[0].entrypoints[0] {
        Entrypoint::Function { language, .. } => language.clone(),
        other => panic!("expected Function entrypoint, got {other:?}"),
    };
    assert_eq!(py_lang, "python");
    assert_eq!(ts_lang, "node");

    match (&py.apps[0].source, &ts.apps[0].source) {
        (Source::LocalPath { path: p, .. }, Source::LocalPath { path: t, .. }) => {
            assert_eq!(p, t, "source path is the project root in either language");
        }
        other => panic!("expected LocalPath sources, got {other:?}"),
    }
}
