# mvm pack authoring for Kotlin (JVM)

A thin, dependency-free Kotlin builder for `mvm.pack-spec/v1`, the
language-neutral pack input the Rust, Python and TypeScript SDKs also emit. It
assembles and validates authored data and returns its canonical JSON. It does
not resolve packages, lock, compile, build, or sign: those run once, in the
shared Rust path, from these bytes. There is no JNI and no native library.

```kotlin
import com.runmvm.packs.*

val spec = pack("acme/csv-analysis", "0.1.0")
    .target(PackTarget.AARCH64_LINUX)
    .source("app")
    .`package`("python3", version = "3.13.1")
    .`package`("pkg-config", scope = PackageScope.BUILD)
    .dependencies(PythonTool.UV, "pyproject.toml", "uv.lock")
    .copy("main.py", "/app/main.py")
    .entrypoint("python3", "/app/main.py")
    .resources(cpuCores = 1, memoryMib = 256)

java.io.File("pack.json").writeBytes(spec.toJson())
```

`package` is a Kotlin keyword, so the method is spelled with backticks; it is
the same `.package` the other SDKs expose.

- `.package(name, version = null, scope = RUNTIME)` requests a generic package.
  Nothing about a package implies a language runtime.
- `.dependencies(tool, manifest, lockfile)` references a Python manifest and
  its hash-locked lockfile inside the source tree.
- `.copy(source, destination)` copies a source-relative file or tree to a
  guest-absolute path. Calls append in order.
- `.entrypoint(...)` is literal argv; nothing is split or evaluated.
- `.resources(cpuCores, memoryMib)` is advisory; memory is binary MiB.

## Failures

`build()` and `toJson()` throw `PackSpecException`. Its `code` is the stable
string every SDK reports for the same mistake: `missing` (with `field`),
`identity`, `package`, `path`, `entrypoint`, or `resources`.

## Tests

```sh
crates/mvm-sdk/sdks/kotlin/scripts/install-kotlinc.sh   # prints the bin dir to add to PATH
just sdk::test-kotlin
```

The suite checks the builder against the canonical goldens in
`crates/mvm-contract/tests/fixtures/pack-spec-v1/canonical/`, byte for byte and
by SHA-256, so a pass means this SDK and the Rust contract agree on the
`spec_sha256` a lock records.
