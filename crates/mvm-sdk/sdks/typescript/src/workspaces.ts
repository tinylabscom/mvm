/** Review may recover interrupted work. No caller-assembled apply plans are accepted. */
import { call } from "./_hostlib.js";
import { WORKSPACE_APPLY, WORKSPACE_REDO, WORKSPACE_REVIEW, WORKSPACE_UNDO } from "./hostabi/methods.js";

export interface ReviewOptions {
  volume?: string;
  exclude?: string[];
  /** Additional protection; mandatory defaults cannot be disabled. */
  protectedPaths?: string[];
}
function workspace(vm: string, opts: ReviewOptions) {
  return { vm, volume: opts.volume ?? null, exclude: opts.exclude ?? [], protected_paths: opts.protectedPaths ?? [] };
}
export function review(vm: string, opts: ReviewOptions = {}): Record<string, unknown> {
  return call(WORKSPACE_REVIEW, workspace(vm, opts));
}
export function apply(
  vm: string, expectedFingerprint: string, opts: ReviewOptions & { approved?: boolean } = {},
): Record<string, unknown> {
  return call(WORKSPACE_APPLY, { workspace: workspace(vm, opts), expected_fingerprint: expectedFingerprint, approved: opts.approved ?? false });
}
export function undo(vm: string, opts: { volume?: string; approved?: boolean } = {}): Record<string, unknown> {
  return call(WORKSPACE_UNDO, { workspace: workspace(vm, opts), approved: opts.approved ?? false });
}
export function redo(vm: string, opts: { volume?: string; approved?: boolean } = {}): Record<string, unknown> {
  return call(WORKSPACE_REDO, { workspace: workspace(vm, opts), approved: opts.approved ?? false });
}
