use core_foundation::base::TCFType;
use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};
use zeroize::Zeroizing;

use super::{IdentityError, Result, SERVICE, Store};

pub(super) struct NativeStore;

unsafe extern "C" {
    fn SecKeychainGetStatus(keychain: *mut std::ffi::c_void, status: *mut u32) -> i32;
}

fn keychain() -> Result<SecKeychain> {
    let keychain = SecKeychain::default_for_domain(SecPreferencesDomain::User)
        .map_err(|_| IdentityError::Unavailable)?;
    let mut status = 0u32;
    // SAFETY: the retained SecKeychain is live for the call, and status points
    // to initialized writable storage. This only queries status, never unlocks.
    let result =
        unsafe { SecKeychainGetStatus(keychain.as_concrete_TypeRef().cast(), &mut status) };
    // kSecUnlockStateStatus is bit zero. A subsequent relock can still block a
    // native call; the worker deadline controls result delivery, not the syscall.
    if result != 0 || status & 1 == 0 {
        return Err(IdentityError::Unavailable);
    }
    Ok(keychain)
}

impl Store for NativeStore {
    fn read(&self, account: &str) -> Result<Zeroizing<Vec<u8>>> {
        read_at(SERVICE, account)
    }
    fn create(&self, account: &str, seed: &[u8]) -> Result<()> {
        create_at(SERVICE, account, seed)
    }
}

pub(super) fn read_at(service: &str, account: &str) -> Result<Zeroizing<Vec<u8>>> {
    let (password, _) = keychain()?
        .find_generic_password(service, account)
        .map_err(|error| match error.code() {
            -25300 => IdentityError::Missing,
            _ => IdentityError::Unavailable,
        })?;
    Ok(Zeroizing::new(password.as_ref().to_vec()))
}

pub(super) fn create_at(service: &str, account: &str, seed: &[u8]) -> Result<()> {
    // Unlike set_generic_password, add refuses an existing item atomically.
    keychain()?
        .add_generic_password(service, account, seed)
        .map_err(|error| match error.code() {
            -25299 => IdentityError::Conflict,
            _ => IdentityError::Unavailable,
        })
}

#[cfg(test)]
pub(super) fn delete_test_entry(service: &str, account: &str) -> Result<()> {
    if !service.starts_with("com.tinylabs.mvm.test.entrypoint-caller.v1.")
        || !account.starts_with("test:installation:")
    {
        return Err(IdentityError::Conflict);
    }
    match keychain()?.find_generic_password(service, account) {
        Ok((_, item)) => item.delete(),
        Err(error) if error.code() == -25300 => return Ok(()),
        Err(_) => return Err(IdentityError::Unavailable),
    }
    // The native wrapper discards deletion status; verify the exact item.
    match read_at(service, account) {
        Err(IdentityError::Missing) => Ok(()),
        _ => Err(IdentityError::Unavailable),
    }
}
