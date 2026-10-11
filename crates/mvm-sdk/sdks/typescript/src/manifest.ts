/**
 * Built-manifest inspection through the host library.
 * Discovery, verification, and validation stay in the client facade.
 */
import { call } from "./_hostlib.js";
import {
  MANIFEST_EXPORT_OCI, MANIFEST_INFO, MANIFEST_LIST, MANIFEST_PRUNE,
  MANIFEST_REMOVE, MANIFEST_VERIFY,
} from "./hostabi/methods.js";

/** List built manifests, optionally restricted to orphans and matching tags. */
export function list(
  opts: { orphans?: boolean; tags?: string[] } = {},
): Record<string, unknown>[] {
  return call(MANIFEST_LIST, {
    orphans: opts.orphans ?? false,
    tags: opts.tags ?? [],
  });
}

/** Inspect a manifest without interpreting its persisted data or snapshot. */
export function info(path: string | null = null): Record<string, unknown> {
  return call(MANIFEST_INFO, { path });
}

/** Remove a local slot without prompting; source deletion is explicit. */
export function remove(
  path: string | null = null,
  opts: { force?: boolean; manifestFile?: boolean } = {},
): Record<string, unknown> {
  return call(MANIFEST_REMOVE, {
    path, force: opts.force ?? false, manifest_file: opts.manifestFile ?? false,
  });
}

/** Preview orphan removal by default; orphans must be selected explicitly. */
export function prune(
  opts: { orphans?: boolean; dryRun?: boolean } = {},
): Record<string, unknown> {
  return call(MANIFEST_PRUNE, { orphans: opts.orphans ?? false, dry_run: opts.dryRun ?? true });
}

/** Copy a registered template's existing OCI archive to a host path. */
export function exportOci(template: string, out: string): Record<string, unknown> {
  return call(MANIFEST_EXPORT_OCI, { template, out });
}

/** Verify a built manifest using the client facade's verification policy. */
export function verify(
  path: string | null = null,
  opts: { revision?: string | null; checkSignature?: boolean } = {},
): Record<string, unknown> {
  return call(MANIFEST_VERIFY, {
    path,
    revision: opts.revision ?? null,
    check_signature: opts.checkSignature ?? false,
  });
}
