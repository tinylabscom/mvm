/// E2E test suite — spawns the real `mvmctl` binary and inspects exit codes
/// and output.  All tests work without a Lima VM present; they validate
/// argument parsing, help output, and commands that run cleanly on any host.
mod e2e {
    mod audit_emissions;
    mod cleanup_orphans;
    mod harness;
    mod help;
    mod status;
    mod uninstall;
}
