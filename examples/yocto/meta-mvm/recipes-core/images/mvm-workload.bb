SUMMARY = "Representative MVM workload root filesystem"
LICENSE = "MIT"

inherit image

# The Poky defaults include debug-tweaks and the first-boot postinst runner.
# Neither belongs in a one-shot, already-configured workload rootfs.
EXTRA_IMAGE_FEATURES = ""
ROOTFS_BOOTSTRAP_INSTALL = ""
IMAGE_INSTALL = "mvm-hello"
IMAGE_FSTYPES = "tar.gz"
IMAGE_FEATURES = ""
IMAGE_LINGUAS = ""
NO_RECOMMENDATIONS = "1"
