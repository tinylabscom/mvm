//! The privilege-drop helper, built as a binary of this package.
//!
//! `mvm-setpriv` is a binary of its own crate, and a test here can only name
//! binaries of this package. This is the same entry point the shipped helper's
//! `main` calls, so a test that starts a process through it starts it the way a
//! guest init does.

fn main() {
    mvm_setpriv::run()
}
