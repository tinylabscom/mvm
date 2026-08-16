/**
 * Numeric environment-variable readers.
 *
 * The *names* live in the generated `vars.ts`; this is how a value is read
 * off one. The behaviour deliberately mirrors the Python SDK's `env_float` /
 * `env_int`: absent, empty, or unparseable all fall back to the default,
 * silently. Two SDKs that read the same variable and disagree about what a
 * malformed value means is the kind of divergence the shared registry exists
 * to prevent, so this matches Python rather than improving on it.
 */

function raw(name: string): string | undefined {
  if (typeof process === "undefined") return undefined;
  const value = process.env[name];
  return value === undefined || value === "" ? undefined : value;
}

/** Read `name` as a float, falling back to `fallback`. */
export function envFloat(name: string, fallback: number): number {
  const value = raw(name);
  if (value === undefined) return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

/** Read `name` as an integer, falling back to `fallback`. */
export function envInt(name: string, fallback: number): number {
  const value = raw(name);
  if (value === undefined) return fallback;
  // `Number` accepts "1.5" where Python's `int()` raises; truncating keeps a
  // fractional byte count from silently becoming a non-integer `maxBuffer`.
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : fallback;
}
