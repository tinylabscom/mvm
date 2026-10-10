use std::collections::HashMap;

use secret_service::{EncryptionType, blocking::SecretService};
use zeroize::Zeroizing;

use super::{IdentityError, Result, SERVICE, Store};

pub(super) struct NativeStore;

fn attributes(account: &str) -> HashMap<&str, &str> {
    HashMap::from([("service", SERVICE), ("account", account)])
}

fn connect<'a>() -> Result<SecretService<'a>> {
    // No plaintext transport, session-only keyring or automatic unlock.
    // Native calls may block; the owning worker bounds result delivery.
    SecretService::connect(EncryptionType::Dh).map_err(|_| IdentityError::Unavailable)
}

impl Store for NativeStore {
    fn read(&self, account: &str) -> Result<Zeroizing<Vec<u8>>> {
        let service = connect()?;
        let collection = service
            .get_default_collection()
            .map_err(|_| IdentityError::Unavailable)?;
        if collection.collection_path.as_str() == "/org/freedesktop/secrets/collection/session"
            || collection
                .is_locked()
                .map_err(|_| IdentityError::Unavailable)?
        {
            return Err(IdentityError::Unavailable);
        }
        let items = collection
            .search_items(attributes(account))
            .map_err(|_| IdentityError::Unavailable)?;
        let item = match items.as_slice() {
            [] => return Err(IdentityError::Missing),
            [item] => item,
            _ => return Err(IdentityError::Conflict),
        };
        if item.is_locked().map_err(|_| IdentityError::Unavailable)? {
            return Err(IdentityError::Unavailable);
        }
        item.get_secret()
            .map(Zeroizing::new)
            .map_err(|_| IdentityError::Unavailable)
    }

    fn create(&self, account: &str, seed: &[u8]) -> Result<()> {
        let service = connect()?;
        let collection = service
            .get_default_collection()
            .map_err(|_| IdentityError::Unavailable)?;
        if collection.collection_path.as_str() == "/org/freedesktop/secrets/collection/session"
            || collection
                .is_locked()
                .map_err(|_| IdentityError::Unavailable)?
        {
            return Err(IdentityError::Unavailable);
        }
        if !collection
            .search_items(attributes(account))
            .map_err(|_| IdentityError::Unavailable)?
            .is_empty()
        {
            return Err(IdentityError::Conflict);
        }
        // Secret Service has no atomic create-if-absent primitive. Never replace:
        // concurrent creates become ambiguous and mandatory readback refuses.
        collection
            .create_item(
                SERVICE,
                attributes(account),
                seed,
                false,
                "application/octet-stream",
            )
            .map_err(|_| IdentityError::Unavailable)?;
        Ok(())
    }
}
