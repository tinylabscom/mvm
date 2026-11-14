/** Refuse an env value written as a bare string. The value is not echoed:
 *  a bare string is often a secret pasted in. */
export function refuseBareEnvValue(key: string): TypeError {
  return new TypeError(
    `env ${JSON.stringify(key)} is a bare string; an env value must say what it is. ` +
      'Write mvm.literal("...") for a literal value, or ' +
      'mvm.secret("name", { type, hosts }) for a secret.',
  );
}

/** Throw on the first bare-string value; the type system already forbids
 *  one, so this catches plain-JavaScript callers. */
export function checkEnv<T>(env: Record<string, T> | undefined): Record<string, T> {
  for (const [key, value] of Object.entries(env ?? {})) {
    if (typeof value === "string") throw refuseBareEnvValue(key);
  }
  return env ?? {};
}
