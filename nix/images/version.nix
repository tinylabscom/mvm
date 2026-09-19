# The mvmctl version every image that carries a `VERSION` file is built for:
# the runtime overlay, the SDK sidecar, and the universal initramfs.
#
# Each of those host-side resolvers compares `VERSION` with the running
# mvmctl's semver and refuses an artifact that disagrees, so this string must
# equal `[workspace.package].version` in the root Cargo.toml. `just release`
# rewrites it with the workspace version, and `xtask
# check-runtime-overlay-version` fails when the two differ or when an image
# flake binds its version to anything other than this file.
"0.18.0-rc.2"
