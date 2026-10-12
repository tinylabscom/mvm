package com.runmvm.packs

import java.io.File
import kotlin.system.exitProcess

/**
 * Dependency-free suite: it needs only the Kotlin compiler and a JDK. The
 * canonical goldens are the ones the Rust contract test pins, so a pass here
 * means this SDK and the Rust one emit identical bytes and spec digests.
 */
private lateinit var goldens: File
private var failures = 0

private fun check(name: String, body: () -> Unit) {
    try {
        body()
        println("PASS $name")
    } catch (e: Throwable) {
        failures++
        println("FAIL $name: $e")
    }
}

private fun expect(condition: Boolean, message: () -> String) {
    if (!condition) throw AssertionError(message())
}

private fun golden(name: String) = File(goldens, "$name.json").readBytes()

private fun goldenDigest(name: String) = File(goldens, "$name.sha256").readText().trim()

private fun assertGolden(name: String, pack: Pack) {
    val bytes = pack.toJson()
    expect(bytes.contentEquals(golden(name))) {
        "$name differs:\n  got  ${String(bytes)}\n  want ${String(golden(name))}"
    }
    expect(pack.build().sha256() == goldenDigest(name)) { "$name digest differs" }
}

private fun minimal(): Pack =
    pack("acme/hello", "1.0.0")
        .target(PackTarget.AARCH64_LINUX)
        .source(".")
        .`package`("busybox")
        .copy("hello.txt", "/app/hello.txt")
        .entrypoint("cat", "/app/hello.txt")
        .resources(cpuCores = 1, memoryMib = 128)

private fun code(pack: Pack): PackSpecException =
    try {
        pack.build()
        throw AssertionError("expected a refusal")
    } catch (e: PackSpecException) {
        e
    }

fun main(args: Array<String>) {
    goldens = File(args.getOrElse(0) { "../../../mvm-contract/tests/fixtures/pack-spec-v1/canonical" })
    require(goldens.isDirectory) { "golden directory not found: $goldens" }

    check("minimal emits the shared golden") { assertGolden("minimal", minimal()) }

    check("python emits the shared golden") {
        assertGolden(
            "python",
            pack("acme/csv-analysis", "0.1.0")
                .target(PackTarget.AARCH64_LINUX)
                .source("app")
                .`package`("python3", version = "3.13.1")
                .`package`("pkg-config", scope = PackageScope.BUILD)
                .dependencies(PythonTool.UV, "pyproject.toml", "uv.lock")
                .dependencies(PythonTool.PIP_TOOLS, "tools/requirements.in", "tools/requirements.txt")
                .copy("main.py", "/app/main.py")
                .copy("data", "/app/data")
                .entrypoint("python3", "/app/main.py", "one argument", "")
                .resources(cpuCores = 1, memoryMib = 256),
        )
    }

    check("claude-style emits the shared golden") {
        assertGolden(
            "claude-style",
            pack("acme/claude-style", "1.2.3-rc.1+build.7")
                .target(PackTarget.X86_64_LINUX)
                .source("app")
                .copy("bin/claude", "/app/bin/claude")
                .entrypoint("/app/bin/claude", "--version")
                .resources(cpuCores = 2, memoryMib = 1024),
        )
    }

    check("missing fields are named") {
        val cases =
            listOf(
                pack("acme/x", "1.0.0").source(".").entrypoint("x").resources(1, 1) to "target",
                pack("acme/x", "1.0.0").target(PackTarget.AARCH64_LINUX).entrypoint("x").resources(1, 1) to "source",
                pack("acme/x", "1.0.0").target(PackTarget.AARCH64_LINUX).source(".").resources(1, 1) to "entrypoint",
                pack("acme/x", "1.0.0").target(PackTarget.AARCH64_LINUX).source(".").entrypoint("x") to "resources",
            )
        for ((builder, field) in cases) {
            val e = code(builder)
            expect(e.code == "missing" && e.field == field) { "$field: got ${e.code}/${e.field}" }
        }
    }

    // The same table the Rust suite checks: one mistake, one stable code.
    check("invalid input reports the shared failure codes") {
        val base = { name: String, version: String ->
            pack(name, version).target(PackTarget.AARCH64_LINUX).source(".").entrypoint("x").resources(1, 1)
        }
        val cases =
            listOf(
                base("no-namespace", "1.0.0") to "identity",
                base("acme/x", "1.0") to "identity",
                minimal().`package`("has space") to "package",
                minimal().`package`("ok", version = ">=1") to "package",
                minimal().copy("../escape", "/app/x") to "path",
                minimal().entrypoint(emptyList()) to "entrypoint",
                minimal().resources(0, 128) to "resources",
            )
        for ((builder, expected) in cases) {
            val e = code(builder)
            expect(e.code == expected) { "expected $expected, got ${e.code}: ${e.message}" }
        }
    }

    check("identity and path rules match the contract") {
        for (ok in listOf("0.1.0", "1.2.3-rc.1", "1.2.3+build.7", "1.0.0-0a.1+007")) {
            expect(releaseVersion(ok)) { ok }
        }
        for (bad in listOf("01.0.0", "1.0.0-01", "1.0", "1.0.0-", "1.0.0+", "1.0.0-a..b", "1.0.0\n")) {
            expect(!releaseVersion(bad)) { bad }
        }
        for (bad in listOf("Acme/x", "acme/x/", "/x", "acme/-x", "acme/x-")) {
            expect(code(base(bad)).code == "identity") { bad }
        }
        for (bad in listOf("/abs", "a//b", "./a", "a/./b", "C:x", "a\\b", "a\u0001b")) {
            expect(code(minimal().copy(bad, "/app/x")).code == "path") { bad }
        }
        expect(code(minimal().copy("x", "/")).code == "path") { "root destination" }
        expect(code(minimal().copy("x", "relative")).code == "path") { "relative destination" }
    }

    check("additions keep call order") {
        val spec = minimal().`package`("zlib", scope = PackageScope.BUILD).`package`("aaa").build()
        expect(spec.packages.map { it.name } == listOf("busybox", "zlib", "aaa")) { "${spec.packages}" }
    }

    check("strings escape exactly like serde_json") {
        expect(Json.render(listOf("a\"b\\c\n\t\u0001/é")) == "[\"a\\\"b\\\\c\\n\\t\\u0001/é\"]") {
            Json.render(listOf("a\"b\\c\n\t\u0001/é"))
        }
    }

    if (failures > 0) {
        println("$failures check(s) failed")
        exitProcess(1)
    }
    println("all checks passed")
}

private fun base(name: String): Pack =
    pack(name, "1.0.0").target(PackTarget.AARCH64_LINUX).source(".").entrypoint("x").resources(1, 1)
