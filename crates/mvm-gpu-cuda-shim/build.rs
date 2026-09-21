fn main() {
    // The guest loader resolves libraries by soname, so the cdylib must
    // advertise the name the workload links against. macOS ld calls the same
    // concept -install_name and the guest is always Linux; only guest-target
    // builds need either.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-link-arg=-Wl,-soname,libcuda.so.1");
    }
}
