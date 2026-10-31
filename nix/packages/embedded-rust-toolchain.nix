# Use one upstream release for cargo, rustc and the musl standard library.
# The locked rust-overlay supplies the component hashes for every host and target.
{ rust-bin, target }:
let
  version = "1.97.1";
in
rust-bin.stable.${version}.minimal.override {
  targets = [ target ];
}
