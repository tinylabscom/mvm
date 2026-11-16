/**
 * Built-manifest inspection and removal through the host library.
 * Discovery, verification, and validation stay in the client facade.
 */
import { call } from "./_hostlib.js";
import {
  MANIFEST_INFO,
  MANIFEST_LIST,
  MANIFEST_PRUNE,
  MANIFEST_REMOVE,
  MANIFEST_VERIFY,
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

/** Delete a built slot from the registry; the source manifest file is never deleted. */
export function remove(
  path: string | null = null,
  opts: { force?: boolean } = {},
): Record<string, unknown> {
  return call(MANIFEST_REMOVE, { path, force: opts.force ?? false });
}

/** Remove built slots whose source manifest is gone; `dryRun` only reports them. */
export function prune(opts: { dryRun?: boolean } = {}): Record<string, unknown>[] {
  return call(MANIFEST_PRUNE, { orphans: true, dry_run: opts.dryRun ?? false });
}
