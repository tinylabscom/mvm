/**
 * The per-platform npm packages that carry `libmvm_hostlib`.
 *
 * `@runmvm/mvm` itself is platform-neutral. Each supported host gets its own
 * package holding only that host's library, declared by the main package as
 * an optional dependency with `os`, `cpu`, and (on Linux) `libc` fields, so
 * npm installs exactly the one that matches and skips the rest. The loader
 * asks this module which package that is; the publish workflow asks it which
 * packages to assemble. One table serves both, so a platform cannot be
 * published that the loader never looks for, or the reverse.
 */

/** The C library a Linux host runs. Irrelevant, and absent, on macOS. */
export type Libc = "glibc" | "musl";

/** One host the SDK ships a library for. */
export interface PlatformPackage {
  /** Suffix of the package name: `<os>-<cpu>` plus `-gnu`/`-musl` on Linux. */
  readonly key: string;
  /** `process.platform` value, and the package's `os` field. */
  readonly os: "darwin" | "linux";
  /** `process.arch` value, and the package's `cpu` field. */
  readonly cpu: "arm64" | "x64";
  /** The package's `libc` field; only Linux distinguishes. */
  readonly libc?: Libc;
}

/** The main package; every platform package is named after it. */
export const MAIN_PACKAGE_NAME = "@runmvm/mvm";

/**
 * Every host a published release carries a library for. Intel macOS is not
 * here because no release builds for it.
 */
export const PLATFORM_PACKAGES: readonly PlatformPackage[] = [
  { key: "darwin-arm64", os: "darwin", cpu: "arm64" },
  { key: "linux-x64-gnu", os: "linux", cpu: "x64", libc: "glibc" },
  { key: "linux-arm64-gnu", os: "linux", cpu: "arm64", libc: "glibc" },
  { key: "linux-x64-musl", os: "linux", cpu: "x64", libc: "musl" },
  { key: "linux-arm64-musl", os: "linux", cpu: "arm64", libc: "musl" },
];

/** The npm name of the package for `pkg`. */
export function platformPackageName(pkg: PlatformPackage): string {
  return `${MAIN_PACKAGE_NAME}-${pkg.key}`;
}

/**
 * The C library this process runs on, or `undefined` off Linux.
 *
 * Node records the glibc version it is running against in its diagnostic
 * report header; a musl build of Node has no such field. That is the same
 * signal npm uses to evaluate a package's `libc` field, so the loader and
 * the installer cannot disagree about which package applies.
 */
export function detectLibc(platform: string = process.platform): Libc | undefined {
  if (platform !== "linux") return undefined;
  const report = process.report?.getReport() as
    | { header?: { glibcVersionRuntime?: string } }
    | undefined;
  return report?.header?.glibcVersionRuntime ? "glibc" : "musl";
}

/** The package for this host, or `undefined` when none is published. */
export function platformPackageFor(
  platform: string,
  arch: string,
  libc: Libc | undefined,
): PlatformPackage | undefined {
  return PLATFORM_PACKAGES.find(
    (pkg) =>
      pkg.os === platform && pkg.cpu === arch && (pkg.libc === undefined || pkg.libc === libc),
  );
}
