# Audit — user-identifier → path-traversal guards (template / tag / catalog names)

**Date:** 2026-06-16
**Trigger:** A public OSS sibling (Rust Firecracker fork/snapshot sandbox; referred to
obliquely per repo naming policy) shipped two advisories in the same class: a
user-supplied identifier (`--tag` / `snapshot_tag`) was joined into a filesystem path
without rejecting `..` or absolute paths (Rust's `Path::join(x)` silently discards the
base when `x` is absolute), and the second was an **asymmetry** — one handler validated
the identifier, a sibling handler building a path from the same value did not. This audit
asks whether the equivalent identifier classes in mvm are guarded.

## Verdict

**mvm is not exposed to the write-side traversal CVE on any primary flow.** One
read-side asymmetry exists (`export_oci`, low severity, local-CLI/read-only). The
structural weakness worth fixing is that the template path is guarded *per caller*
rather than at a chokepoint — the same shape that produced the sibling's advisory #2.

## Validators (all strict allowlists — reject `.`, `/`, and therefore `..`/absolute)

- `mvm_core::naming::validate_template_name` — `[a-z0-9-_]`, 1–63, no leading `-`/`_`.
- `mvm_core::naming::validate_id` — `[a-z0-9-]`, 1–63, no leading/trailing `-`.
- `mvm_core::naming::validate_vm_name`, `mvm_backend::audit_substrate::validate_vm_name`.
- `mvm_core::dev_network::validate_network_name`.
- `mvm_guest::volume::validate_volume_name`.
- `mvm::vm::overlay::validate_path_component`; `mvm_build::pipeline::build_cache::is_safe_component`.
- `mvm_core::plan::bundle` rejects absolute / `..` / `\` on bundle member paths.

A `.` is outside every charset, so a single allowlist call blocks both traversal shapes.

## Per identifier class

### Template names — GUARDED on primary flows, but caller-dependent (no chokepoint)
The path helpers in `mvm-core/src/domain/template.rs` (`template_dir`,
`template_spec_path`, `template_revision_dir`, …) interpolate the raw id with
`format!("{base}/{id}")` and do **no** validation. `template_load`
(`mvm/src/vm/template/lifecycle.rs:65`) and `template_load_dispatched` (`:495`, legacy-name
arm) likewise pass the id straight to `template_spec_path`. Safety therefore rests
entirely on callers, and the callers are inconsistent:

- `vm/up.rs` `--manifest`: **safe**, but structurally, not by charset. `resolved_template_arg`
  comes from `shared::resolve_manifest_arg` (`shared/resolve.rs:58`); its `looks_like_path`
  gate (`:92`) diverts anything containing `/` or starting with `.` to
  `canonicalize` + content-hash, so the `ManifestArgRef::Name(arg)` branch (`:98`) cannot
  carry a `/` or leading-`.` segment. It is *not* run through `validate_template_name`,
  so a benign-but-odd name (`a..b`, uppercase) reaches `template_load` — no escape from
  `templates_base_dir`, so not a vuln, but fragile.
- `ops/mcp.rs:630` `template_load(&params.env)`: **safe**. `validate_env` (`:797`, called at
  `:600` before the load) is an allowlist-membership check against `template_list()`, so a
  traversal string matches no registered template and is rejected. Note this is
  agent-controlled input, so the guard matters.
- `manifest/export_oci.rs:131` `resolve_to_slot_hash`: **UNGUARDED.** After the
  slot-hash check (`:109`) and the manifest-path resolution (`:123`), it falls through to
  `template_load_dispatched(template)` on the raw arg with no `looks_like_path` gate and
  no `validate_template_name`. `template = "../../../etc/foo"` reaches
  `template_spec_path("../../../etc/foo")` →
  read of `<templates_base>/../../../etc/foo/template.json`. This is a read-side path
  traversal / file-existence oracle (the file must parse as `TemplateSpec` JSON to fully
  succeed; the read attempt + error message still leaks existence). **Severity: low** —
  local CLI verb, read-only, runs as the invoking user on their own machine — but it is
  exactly the sibling's advisory-#2 asymmetry: a sibling handler that forgot the guard its
  peers apply.

### Snapshot / pool / VM names — GUARDED
`instance_snapshot.rs` validates the VM name (`validate_vm_name`) before
`pause_and_seal` / path use; pool/instance dirs key off validated names. No raw
free-text tag reaches a snapshot path the way the sibling's `--tag` did.

### Network names — GUARDED
`validate_network_name` (`dev_network.rs:59`) is called on the creation path before any
path/interface use.

### Catalog / image-entry names — N/A
The bundled catalog is compile-time static, not a user free-text key that selects a path.
OCI references go through `mvm-oci`'s allow-listed, fuzzed unpacker
(`unpack::unpack_layer`) and content-addressed digests, not name→path joins.

### Volume names — GUARDED
`validate_volume_name` (`mvm-guest/src/volume.rs:41`); the in-guest mount path also rejects
traversal via `VolumePath`.

## Recommended fix (defense-in-depth at the chokepoint)

The sibling's own remedy was to add the guard at the **dereference site**
(`read_snapshot_volumes`), not only at the request handler — so a future forgetful caller
fails closed. Mirror that here:

- [ ] Validate inside `template_load` and `template_load_dispatched` (legacy-name arm):
      reject the id with `validate_template_name` before `template_spec_path`. This closes
      `export_oci` and every future caller at once, regardless of caller discipline.
      Slot-hash inputs already route through `is_slot_hash_dirname`, so the guard applies
      only to the free-text name arm.
- [ ] (Optional, stronger) Introduce a `TemplateId` newtype constructible only via
      `validate_template_name`, and have the path helpers take `&TemplateId` instead of
      `&str` — makes the unvalidated path unrepresentable rather than merely guarded.
- [ ] Add a regression test: `template_load("../../etc/x")` and the `export_oci` resolver
      both reject a traversal arg (the red test, then the guard).

Until then the only live gap is the low-severity local read in `export_oci`; the primary
boot/exec/MCP flows are safe.
