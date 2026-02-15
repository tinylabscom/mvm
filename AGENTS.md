# Agent Working Agreement

- Always write and fix tests before considering a feature complete. Ensure new functionality has coverage and existing tests are green.
- Never leave clippy warnings. Run `cargo clippy -D warnings` and fix all findings before calling a feature done.
- Never leave the workspace in a non-compiling state. Run `cargo check` (or full `cargo test`/`cargo build`) and fix any errors before you finish.
