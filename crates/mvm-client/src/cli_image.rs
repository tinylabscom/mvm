//! Public workspace compatibility facade for existing CLI image orchestration.
//!
//! This is not the embedder prepared-launch API. Explicit preparation and
//! presentation remain separate from [`crate::prepared_image`], whose fixed
//! cache, development qualification and persistent-only admission are checked
//! by MVM. These compatibility operations retain the CLI's explicit
//! acquisition, production verification, index adoption and destructive cache
//! removal effects; callers must not substitute them for prepared launch.
//! Hiding this module from the main documentation index is not access control.
//! Cache schemas, materializer injection and verifier injection remain private
//! to the canonical image owner, and returned reports cannot authorize boot.

pub use crate::image_cache::{
    AcquisitionHooks, ImageSource, OciProvenance, OciPullRecord, OciRegistryAuthDecision,
    RemovedImage, ResolvedOciRunImage, acquire, ensure_prod_digest_pin,
    ensure_prod_registry_allowed, human_bytes, inspect_digest_reference, inspect_json, list_json,
    pull, recent_image_references, registry_auth_for, registry_auth_from_lookup, remove_image,
    render_inspect, render_list, require_prod_digest_pin, resolve_prepared, validate_preparation,
};
