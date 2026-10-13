package com.runmvm.packs

/**
 * Start a pack named `namespace/name` at a SemVer 2.0 [version].
 *
 * ```kotlin
 * val spec = pack("acme/hello", "1.0.0")
 *     .target(PackTarget.AARCH64_LINUX)
 *     .source(".")
 *     .`package`("busybox")
 *     .copy("hello.txt", "/app/hello.txt")
 *     .entrypoint("cat", "/app/hello.txt")
 *     .resources(cpuCores = 1, memoryMib = 128)
 *     .build()
 * ```
 *
 * The builder only assembles and validates authored data. Locking, compiling
 * and signing happen in the shared Rust path, from the bytes [Pack.toJson]
 * returns, exactly as for the Rust, Python and TypeScript SDKs.
 */
fun pack(name: String, version: String): Pack = Pack(PackIdentity(name, version))

/** Fluent PackSpec builder. Adding calls append in call order; setting calls replace. */
class Pack internal constructor(private val identity: PackIdentity) {
    private var target: PackTarget? = null
    private var source: String? = null
    private val packages = mutableListOf<PackageRequest>()
    private val dependencies = mutableListOf<DependencyFiles>()
    private val copy = mutableListOf<CopyOperation>()
    private var entrypoint: List<String>? = null
    private var resources: PackResources? = null

    /** The guest target. Required; never inferred from the author's host. */
    fun target(target: PackTarget): Pack = apply { this.target = target }

    /** The local source tree, relative to the spec's directory (`.` for itself). */
    fun source(path: String): Pack = apply { source = path }

    /**
     * Request a generic package. Nothing about a package implies a language
     * runtime; [version] requests an exact spelling.
     */
    fun `package`(
        name: String,
        version: String? = null,
        scope: PackageScope = PackageScope.RUNTIME,
    ): Pack = apply { packages += PackageRequest(name, version, scope) }

    /** A Python manifest and the lockfile [tool] produced from it. */
    fun dependencies(tool: PythonTool, manifest: String, lockfile: String): Pack =
        apply { dependencies += DependencyFiles.Python(tool, manifest, lockfile) }

    /** Copy a source-relative file or tree to a guest-absolute destination. */
    fun copy(source: String, destination: String): Pack =
        apply { copy += CopyOperation(source, destination) }

    /** Literal argv; no shell splitting or evaluation. */
    fun entrypoint(vararg argv: String): Pack = apply { entrypoint = argv.toList() }

    fun entrypoint(argv: List<String>): Pack = apply { entrypoint = argv.toList() }

    /** Advisory CPU cores and binary MiB of memory. */
    fun resources(cpuCores: Int, memoryMib: Long): Pack =
        apply { resources = PackResources(cpuCores, memoryMib) }

    /** Assemble and validate; throws [PackSpecException] with a shared code. */
    fun build(): PackSpec {
        val spec =
            PackSpec(
                identity = identity,
                target = target ?: missing("target"),
                sourcePath = source ?: missing("source"),
                packages = packages.toList(),
                dependencies = dependencies.toList(),
                copy = copy.toList(),
                entrypoint = entrypoint ?: missing("entrypoint"),
                resources = resources ?: missing("resources"),
            )
        spec.validate()
        return spec
    }

    /** [build], then the canonical JSON every SDK emits for it. */
    fun toJson(): ByteArray = build().canonicalJson()

    private fun missing(field: String): Nothing =
        throw PackSpecException("missing", field, "pack is missing required field `$field`")
}
