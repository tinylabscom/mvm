/**
 * `addon_use` — hand-written, deliberately.
 *
 * Every other Tier A/B constructor is generated from the Rust registry
 * (`crates/mvm-sdk/src/ctor_registry.rs`). This one is not, because
 * expressing it declaratively would need four capabilities that no other
 * constructor uses: a cross-parameter XOR constraint, a *branching*
 * target (a different `AddonRef` variant depending on which argument was
 * passed), a derived string field, and default-if-absent. Building a
 * mini-language for one function is the over-abstraction the project
 * guidelines warn about.
 *
 * The WS-1 reasoning still applies, though: a copy is dangerous when
 * nothing checks it. This pair is pinned against its Python twin by the
 * s27 golden IR document, so a divergence fails a gate rather than
 * shipping.
 *
 * Note the shape difference from Rust, which is not an oversight. Rust
 * exposes `addon_use_registry` / `addon_use_local` as two functions, so
 * the invalid "both or neither" combination cannot be written at all —
 * the same reason a port is a `u16` there and a range check here.
 */

import type { AddonRef, AddonUse } from "./ir/workload.js";

/**
 * The placeholder `sha256` an unlocked addon use carries until
 * `mvm addon lock` resolves it.
 *
 * Deliberately not exported: Python spells it `_UNRESOLVED_SHA256`, i.e.
 * private, and exporting it here would widen the TypeScript public API
 * past its twin. The surface-divergence gate caught exactly that.
 */
const UNRESOLVED_SHA256 = "0".repeat(64);

/** Options for {@link addon_use}. */
export interface AddonUseOptions {
  /** Registry version. Pass exactly one of `version` or `path`. */
  version?: string;
  /** Local path, for development. Pass exactly one of `version` or `path`. */
  path?: string;
  /** Prefix every env var the addon exports with `<ALIAS_UPPER>_`. */
  alias?: string;
  /** Resolved artifact hash; defaults to the unlocked placeholder. */
  sha256?: string;
  /** Param values passed to the addon. */
  params?: Record<string, unknown>;
  /** Composition tier; only `separate` is accepted today. */
  tier?: string;
}

/**
 * Declare a use of a published addon.
 *
 * Pass `version` for a registry-resolved addon, or `path` for a
 * local-path addon during development — exactly one of the two.
 */
export function addon_use(name: string, options: AddonUseOptions = {}): AddonUse {
  const { version, path, alias, sha256, params, tier = "separate" } = options;

  // Message kept byte-identical to the Python twin; the golden document
  // compares them verbatim.
  if ((version === undefined) === (path === undefined)) {
    throw new Error(
      "mv.addon_use(): pass exactly one of `version=` (registry) or `path=` (local-path)",
    );
  }

  const ref: AddonRef =
    version !== undefined
      ? ({ kind: "registry", url: `addons.mvm.io/${name}`, version } as AddonRef)
      : ({ kind: "local", path } as AddonRef);

  return {
    name,
    alias,
    tier,
    ref,
    sha256: sha256 ?? UNRESOLVED_SHA256,
    params,
  } as AddonUse;
}
