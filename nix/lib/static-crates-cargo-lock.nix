{ lockFile }:

{
  inherit lockFile;

  extraRegistries = {
    "https://github.com/rust-lang/crates.io-index" = "https://static.crates.io/crates";
  };
}
