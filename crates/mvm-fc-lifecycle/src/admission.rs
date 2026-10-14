use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use crate::{Error, Result};

const MAX_NON_ROOT: usize = 16;

/// One active connection per UID; root has a separate reserved slot.
#[derive(Default)]
pub(crate) struct Admission {
    active: BTreeSet<u32>,
}

pub(crate) struct Permit {
    admission: Arc<Mutex<Admission>>,
    uid: u32,
}

impl Admission {
    pub fn acquire(admission: &Arc<Mutex<Self>>, uid: u32) -> Result<Permit> {
        let mut state = admission.lock().map_err(|_| Error::Refused)?;
        let non_root = state.active.iter().filter(|uid| **uid != 0).count();
        if state.active.contains(&uid) || uid != 0 && non_root >= MAX_NON_ROOT {
            return Err(Error::Limit);
        }
        state.active.insert(uid);
        Ok(Permit {
            admission: admission.clone(),
            uid,
        })
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if let Ok(mut state) = self.admission.lock() {
            state.active.remove(&self.uid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_uid_cannot_monopolize_slots_and_root_is_reserved() {
        let admission = Arc::new(Mutex::new(Admission::default()));
        let owner = Admission::acquire(&admission, 1000).unwrap();
        assert!(Admission::acquire(&admission, 1000).is_err());
        let others: Vec<_> = (1..MAX_NON_ROOT)
            .map(|uid| Admission::acquire(&admission, u32::try_from(uid).unwrap()).unwrap())
            .collect();
        assert!(Admission::acquire(&admission, 2000).is_err());
        let root = Admission::acquire(&admission, 0).unwrap();
        assert!(Admission::acquire(&admission, 0).is_err());
        drop(owner);
        Admission::acquire(&admission, 2000).unwrap();
        drop(root);
        Admission::acquire(&admission, 0).unwrap();
        drop(others);
    }
}
