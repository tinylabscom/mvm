package com.runmvm.packs

import java.security.MessageDigest

/** The only authored schema this SDK writes. */
const val PACK_SPEC_SCHEMA: String = "mvm.pack-spec/v1"

/** Explicit guest target, never inferred from the author's host. */
enum class PackTarget(val wire: String) {
    AARCH64_LINUX("aarch64-linux"),
    X86_64_LINUX("x86_64-linux"),
}

/** Whether a generic package is needed only while building or in the guest. */
enum class PackageScope(val wire: String) {
    BUILD("build"),
    RUNTIME("runtime"),
}

/** The Python tool that produced a lockfile from its manifest. */
enum class PythonTool(val wire: String) {
    UV("uv"),
    PIP_TOOLS("pip_tools"),
}

data class PackIdentity(val name: String, val version: String)

/** A generic package request; an absent version leaves selection to resolution. */
data class PackageRequest(val name: String, val version: String?, val scope: PackageScope)

/** Language dependency files, relative to the source tree. */
sealed class DependencyFiles {
    data class Python(val tool: PythonTool, val manifest: String, val lockfile: String) :
        DependencyFiles()
}

data class CopyOperation(val source: String, val destination: String)

/** Advisory requests: CPU cores and binary MiB (1 MiB = 1_048_576 bytes). */
data class PackResources(val cpuCores: Int, val memoryMib: Long)

/**
 * Structured authoring failure. [code] is the same stable string every
 * language SDK reports for the same mistake; [field] names a missing field.
 */
class PackSpecException(val code: String, val field: String? = null, message: String) :
    IllegalArgumentException(message)

/**
 * The closed `mvm.pack-spec/v1` document. Mirrors the Rust contract
 * (`mvm_contract::pack_spec::PackSpec`) field for field; [validate] applies the
 * same rules, and [canonicalJson] emits the same bytes.
 */
data class PackSpec(
    val identity: PackIdentity,
    val target: PackTarget,
    val sourcePath: String,
    val packages: List<PackageRequest>,
    val dependencies: List<DependencyFiles>,
    val copy: List<CopyOperation>,
    val entrypoint: List<String>,
    val resources: PackResources,
) {
    /** Throws [PackSpecException] with the shared failure code. */
    fun validate() {
        if (!packName(identity.name) || !releaseVersion(identity.version)) {
            fail("identity", "invalid pack identity: expected namespace/name and SemVer 2.0 version")
        }
        relativePath(sourcePath, allowRoot = true)
        for (p in packages) {
            if (!token(p.name) || (p.version != null && !token(p.version))) {
                fail("package", "invalid package name or version token")
            }
        }
        for (d in dependencies) {
            when (d) {
                is DependencyFiles.Python -> {
                    relativePath(d.manifest, allowRoot = false)
                    relativePath(d.lockfile, allowRoot = false)
                }
            }
        }
        for (c in copy) {
            relativePath(c.source, allowRoot = true)
            if (utf8Len(c.destination) > 4096 || !c.destination.startsWith("/")) badPath()
            relativePath(c.destination.substring(1), allowRoot = false)
        }
        val first = entrypoint.firstOrNull()
        if (first == null || first.isBlank() || entrypoint.any { it.contains('\u0000') }) {
            fail("entrypoint", "entrypoint must have a nonempty executable and no NUL bytes")
        }
        if (resources.cpuCores !in 1..65535 || resources.memoryMib !in 1L..4294967295L) {
            fail("resources", "CPU cores and memory MiB must be positive")
        }
    }

    /** Compact UTF-8 JSON with sorted keys and no trailing newline. */
    fun canonicalJson(): ByteArray {
        validate()
        return Json.render(toJson()).toByteArray(Charsets.UTF_8)
    }

    /** Lowercase hex SHA-256 of [canonicalJson]; equals a lock's `spec_sha256`. */
    fun sha256(): String =
        MessageDigest.getInstance("SHA-256").digest(canonicalJson()).joinToString("") {
            "%02x".format(it)
        }

    private fun toJson(): Map<String, Any> =
        mapOf(
            "schema" to PACK_SPEC_SCHEMA,
            "identity" to mapOf("name" to identity.name, "version" to identity.version),
            "target" to target.wire,
            "source" to mapOf("kind" to "local", "path" to sourcePath),
            "packages" to
                packages.map { p ->
                    buildMap<String, Any> {
                        put("name", p.name)
                        p.version?.let { put("version", it) }
                        put("scope", p.scope.wire)
                    }
                },
            "dependencies" to
                dependencies.map { d ->
                    when (d) {
                        is DependencyFiles.Python ->
                            mapOf(
                                "kind" to "python",
                                "tool" to d.tool.wire,
                                "manifest" to d.manifest,
                                "lockfile" to d.lockfile,
                            )
                    }
                },
            "copy" to copy.map { mapOf("source" to it.source, "destination" to it.destination) },
            "entrypoint" to entrypoint,
            "resources" to
                mapOf("cpu_cores" to resources.cpuCores, "memory_mb" to resources.memoryMib),
        )
}

private fun fail(code: String, message: String): Nothing = throw PackSpecException(code, null, message)

private fun badPath(): Nothing =
    fail("path", "unsafe path: expected normalized portable path without traversal")

private fun utf8Len(value: String): Int = value.toByteArray(Charsets.UTF_8).size

private fun relativePath(value: String, allowRoot: Boolean) {
    if (allowRoot && value == ".") return
    if (value.isEmpty() ||
        utf8Len(value) > 4096 ||
        value.any { it.isISOControl() || it == '\\' || it == ':' } ||
        value.split('/').any { it.isEmpty() || it == "." || it == ".." }
    ) {
        badPath()
    }
}

private fun isAsciiAlnum(c: Char): Boolean = c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9'

internal fun token(value: String): Boolean =
    value.isNotEmpty() &&
        value.length <= 128 &&
        isAsciiAlnum(value[0]) &&
        value.all { isAsciiAlnum(it) || it in "-_.+" }

private fun packName(value: String): Boolean {
    val slash = value.indexOf('/')
    if (slash < 0) return false
    return packComponent(value.substring(0, slash)) && packComponent(value.substring(slash + 1))
}

private fun packComponent(value: String): Boolean =
    value.length in 1..64 &&
        isAsciiAlnum(value.first()) &&
        isAsciiAlnum(value.last()) &&
        value.all { it in 'a'..'z' || it in '0'..'9' || it in "._-" }

private fun decimalIdentifier(value: String): Boolean =
    value.isNotEmpty() && (value.length == 1 || !value.startsWith("0")) && value.all { it in '0'..'9' }

private fun versionIdentifier(value: String): Boolean =
    value.isNotEmpty() && value.all { isAsciiAlnum(it) || it == '-' }

internal fun releaseVersion(value: String): Boolean {
    if (value.length > 128 || value.any { it.code > 0x7f }) return false
    val plus = value.indexOf('+')
    val version = if (plus < 0) value else value.substring(0, plus)
    val build = if (plus < 0) null else value.substring(plus + 1)
    if (build != null && !build.split('.').all(::versionIdentifier)) return false
    val dash = version.indexOf('-')
    val core = if (dash < 0) version else version.substring(0, dash)
    val prerelease = if (dash < 0) null else version.substring(dash + 1)
    if (prerelease != null &&
        !prerelease.split('.').all { id ->
            versionIdentifier(id) && (!id.all { it in '0'..'9' } || decimalIdentifier(id))
        }
    ) {
        return false
    }
    val parts = core.split('.')
    return parts.size == 3 && parts.all(::decimalIdentifier)
}

/** The canonical writer: sorted object keys, compact, serde_json string escapes. */
internal object Json {
    fun render(value: Any?): String = StringBuilder().also { write(it, value) }.toString()

    private fun write(out: StringBuilder, value: Any?) {
        when (value) {
            is String -> string(out, value)
            is Int, is Long -> out.append(value.toString())
            is Map<*, *> -> {
                out.append('{')
                value.entries
                    .map { (it.key as String) to it.value }
                    .sortedWith { a, b -> compareUtf8(a.first, b.first) }
                    .forEachIndexed { i, (k, v) ->
                        if (i > 0) out.append(',')
                        string(out, k)
                        out.append(':')
                        write(out, v)
                    }
                out.append('}')
            }
            is List<*> -> {
                out.append('[')
                value.forEachIndexed { i, v ->
                    if (i > 0) out.append(',')
                    write(out, v)
                }
                out.append(']')
            }
            else -> throw PackSpecException("serialization", null, "could not serialize PackSpec")
        }
    }

    private fun compareUtf8(a: String, b: String): Int {
        val x = a.toByteArray(Charsets.UTF_8)
        val y = b.toByteArray(Charsets.UTF_8)
        for (i in 0 until minOf(x.size, y.size)) {
            val d = (x[i].toInt() and 0xff) - (y[i].toInt() and 0xff)
            if (d != 0) return d
        }
        return x.size - y.size
    }

    private fun string(out: StringBuilder, value: String) {
        out.append('"')
        for (c in value) {
            when (c) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\b' -> out.append("\\b")
                '\u000C' -> out.append("\\f")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                else ->
                    if (c.code < 0x20) {
                        out.append("\\u00").append("%02x".format(c.code))
                    } else {
                        out.append(c)
                    }
            }
        }
        out.append('"')
    }
}
