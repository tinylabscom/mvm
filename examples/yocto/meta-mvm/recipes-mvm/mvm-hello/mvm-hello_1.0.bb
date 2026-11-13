SUMMARY = "Minimal one-shot workload for an MVM health boot"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "file://hello.S"
S = "${WORKDIR}"
COMPATIBLE_MACHINE = "qemuarm64"

# The standalone PIE has no interpreter or shared libraries. A GNU hash makes
# RPM infer an rtld dependency despite that, so use the older hash table and
# exempt only this package from Yocto's GNU-hash linker-flags check.
INSANE_SKIP:${PN} += "ldflags"

do_compile() {
    ${CC} ${CFLAGS} -nostdlib -static-pie -Wl,-e,_start -Wl,--build-id=none \
        ${LDFLAGS} -Wl,--hash-style=sysv "${WORKDIR}/hello.S" -o "${B}/mvm-hello"
}

do_install() {
    install -d "${D}/srv/app"
    install -m 0755 "${B}/mvm-hello" "${D}/srv/app/hello"
}

FILES:${PN} += "/srv/app/hello"
