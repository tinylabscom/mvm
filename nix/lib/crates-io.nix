# Where crate tarballs come from, in one place.
#
# The crates.io API host answers a plain curl User-Agent with 403. Nix's
# fetchurl sends exactly that, so any `crates.io/api/v1/crates/...` fetch fails
# — and because fetchurl names a derivation after the URL's last segment, every
# one of them is called `download`, so the build reports
# `error: Cannot build '/nix/store/...-download.drv'` and names neither the
# crate nor the host it could not reach.
#
# static.crates.io is the CDN cargo itself fetches from. It serves byte-identical
# `.crate` files — swapping hosts changes no hash — and applies no such rule.
#
# Scope: the crate fetches this repo writes. A pinned nixpkgs pulls ~116 more
# through its own fetchCrate, still on the API host, and those keep working
# because cache.nixos.org substitutes them rather than reaching the network.
# The ones written here have no such cache entry, so they are the ones that go
# out over curl and the only ones that 403.
rec {
  api = "https://crates.io/api/v1/crates";
  cdn = "https://static.crates.io/crates";

  # Move an API-host crate URL onto the CDN. A URL that is already on the CDN
  # passes through unchanged, so this is safe to apply more than once.
  toCdn = builtins.replaceStrings [ api ] [ cdn ];

  # A crate fetch that names itself. Takes the same `sha256` the API-host URL
  # took: the bytes are the same, so an existing hash carries over untouched.
  fetchCrate =
    fetchurl:
    {
      crate,
      version,
      sha256,
    }:
    fetchurl {
      name = "${crate}-${version}.crate";
      url = "${cdn}/${crate}/${version}/download";
      inherit sha256;
    };
}
