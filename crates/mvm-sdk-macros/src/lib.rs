//! Proc macros for the mvm Rust SDK.
//!
//! Placeholder scaffold. The macro surface will
//! be `#[mvm::function]`, `#[mvm::image]`, `#[mvm::secret]`,
//! `#[mvm::volume]`, `#[mvm::addon]` once the runtime/declarative
//! split for `mvm-sdk` is wired.
//!
//! Today the crate only exists so downstream `Cargo.toml`s can wire
//! `mvm-sdk-macros = { workspace = true }` ahead of the body landing,
//! and so `cargo test --workspace` exercises the proc-macro build
//! plumbing.
