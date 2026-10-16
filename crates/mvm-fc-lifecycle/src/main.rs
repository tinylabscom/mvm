fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args != ["serve", "--experimental"] {
        eprintln!("disabled by default; usage: mvm-fc-lifecycle serve --experimental");
        std::process::exit(2);
    }
    if mvm_fc_lifecycle::serve_experimental().is_err() {
        // Do not format errors from untrusted requests or disclose registry contents.
        eprintln!("experimental lifecycle service refused startup or stopped");
        std::process::exit(1);
    }
}
