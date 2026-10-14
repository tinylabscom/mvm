use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::protocol::{Operation, RegistrationId, Request, Response, Status};
use crate::{Error, Result};

pub(crate) const MAX_RECORDS: usize = 1024;
pub(crate) const MAX_PATH: usize = 1024;

/// Constructed only by the transport from kernel peer credentials.
pub(crate) struct Peer {
    pub uid: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Object {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub mode: u32,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Evidence {
    pub pid: i32,
    pub start_ticks: u64,
    pub owner_uid: u32,
    pub state_dir: String,
    pub api_socket: String,
    pub directory: Object,
    pub socket: Object,
    pub executable: Object,
    pub boot_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub version: u32,
    pub id: RegistrationId,
    pub evidence: Evidence,
}

/// Each handle is opened once and retained until the registration is discarded.
/// Implementations must inspect and signal that handle, never reopen by PID.
pub(crate) trait Processes {
    type Handle;
    fn capture(&self, registration: &Operation) -> Result<(Self::Handle, Evidence)>;
    /// Lost filesystem pins cannot exclude inode reuse. Restoration requires
    /// stronger evidence than a root record; production deliberately refuses.
    fn reopen(&self, _evidence: &Evidence) -> Result<Self::Handle> {
        Err(Error::Refused)
    }
    fn validate(&self, handle: &Self::Handle, evidence: &Evidence) -> Result<Status>;
    fn stop(&self, handle: &Self::Handle, evidence: &Evidence) -> Result<Status>;
}

pub(crate) trait Storage {
    fn load(&self) -> Result<Vec<Record>>;
    /// Must not overwrite an existing record, and must durably persist before return.
    fn insert(&self, record: &Record) -> Result<()>;
    fn random_id(&self) -> Result<RegistrationId>;
}

struct Entry<H> {
    record: Record,
    handle: Arc<H>,
}

pub(crate) struct Action<H> {
    record: Record,
    handle: Arc<H>,
    stop: bool,
}

impl<H> Action<H> {
    pub fn run(&self, processes: &impl Processes<Handle = H>) -> Result<Response> {
        let status = if self.stop {
            processes.stop(&self.handle, &self.record.evidence)?
        } else {
            processes.validate(&self.handle, &self.record.evidence)?
        };
        Ok(Response::Status { status })
    }
}

pub(crate) struct Service<P: Processes, S> {
    processes: P,
    storage: S,
    entries: BTreeMap<RegistrationId, Entry<P::Handle>>,
}

impl<P: Processes, S: Storage> Service<P, S> {
    pub fn admits_uid(&self, uid: u32) -> bool {
        uid == 0
            || self
                .entries
                .values()
                .any(|entry| entry.record.evidence.owner_uid == uid)
    }

    pub fn recover(processes: P, storage: S) -> Result<Self> {
        let records = storage.load()?;
        if records.len() > MAX_RECORDS {
            return Err(Error::Limit);
        }
        let mut entries = BTreeMap::new();
        for record in records {
            if record.version != 1 || entries.contains_key(&record.id) {
                return Err(Error::Refused);
            }
            // A damaged or stale registry refuses startup, not just one operation.
            let handle = processes.reopen(&record.evidence)?;
            processes.validate(&handle, &record.evidence)?;
            entries.insert(
                record.id.clone(),
                Entry {
                    record,
                    handle: Arc::new(handle),
                },
            );
        }
        Ok(Self {
            processes,
            storage,
            entries,
        })
    }

    pub fn execute(&mut self, peer: Peer, request: Request) -> Result<Response> {
        if request.version != 1 {
            return Err(Error::Protocol);
        }
        match request.operation {
            operation @ Operation::Register { .. } => {
                if peer.uid != 0 {
                    return Err(Error::Refused);
                }
                if self.entries.len() >= MAX_RECORDS {
                    return Err(Error::Limit);
                }
                let (handle, evidence) = self.processes.capture(&operation)?;
                self.processes.validate(&handle, &evidence)?;
                let id = self.storage.random_id()?;
                if self.entries.contains_key(&id) {
                    return Err(Error::Refused);
                }
                let record = Record {
                    version: 1,
                    id: id.clone(),
                    evidence,
                };
                self.storage.insert(&record)?;
                self.entries.insert(
                    id.clone(),
                    Entry {
                        record,
                        handle: Arc::new(handle),
                    },
                );
                Ok(Response::Registered { id })
            }
            Operation::Stop { id } => {
                let entry = self.authorize(peer, &id)?;
                let status = self.processes.stop(&entry.handle, &entry.record.evidence)?;
                Ok(Response::Status { status })
            }
            Operation::Query { id } => {
                let entry = self.authorize(peer, &id)?;
                let status = self
                    .processes
                    .validate(&entry.handle, &entry.record.evidence)?;
                Ok(Response::Status { status })
            }
        }
    }

    fn authorize(&self, peer: Peer, id: &RegistrationId) -> Result<&Entry<P::Handle>> {
        let entry = self.entries.get(id).ok_or(Error::Refused)?;
        if peer.uid != 0 && peer.uid != entry.record.evidence.owner_uid {
            return Err(Error::Refused);
        }
        Ok(entry)
    }

    /// Capture only authorized immutable handles under the registry lock.
    /// Potentially slow process/filesystem checks execute after releasing it.
    pub fn action(&self, peer: Peer, request: Request) -> Result<Action<P::Handle>> {
        if request.version != 1 {
            return Err(Error::Protocol);
        }
        let (id, stop) = match request.operation {
            Operation::Stop { id } => (id, true),
            Operation::Query { id } => (id, false),
            Operation::Register { .. } => return Err(Error::Refused),
        };
        let entry = self.authorize(peer, &id)?;
        Ok(Action {
            record: entry.record.clone(),
            handle: entry.handle.clone(),
            stop,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    struct Process {
        changed: Rc<Cell<bool>>,
        signals: Rc<Cell<usize>>,
        captures: Cell<usize>,
        unsupported: bool,
    }
    impl Processes for Process {
        type Handle = Rc<Cell<usize>>;
        fn capture(&self, _: &Operation) -> Result<(Self::Handle, Evidence)> {
            self.captures.set(self.captures.get() + 1);
            if self.unsupported {
                return Err(Error::Unsupported);
            }
            Ok((self.signals.clone(), evidence()))
        }
        fn reopen(&self, _: &Evidence) -> Result<Self::Handle> {
            if self.unsupported {
                return Err(Error::Unsupported);
            }
            Ok(self.signals.clone())
        }
        fn validate(&self, handle: &Self::Handle, _: &Evidence) -> Result<Status> {
            assert!(Rc::ptr_eq(handle, &self.signals));
            if self.changed.get() {
                Err(Error::Refused)
            } else {
                Ok(Status::Running)
            }
        }
        fn stop(&self, handle: &Self::Handle, evidence: &Evidence) -> Result<Status> {
            self.validate(handle, evidence)?;
            handle.set(handle.get() + 1);
            Ok(Status::StopRequested)
        }
    }
    #[derive(Default)]
    struct Memory {
        records: RefCell<Vec<Record>>,
        fail: Cell<bool>,
        inserts: Cell<usize>,
        random_calls: Cell<usize>,
    }
    impl Storage for Memory {
        fn load(&self) -> Result<Vec<Record>> {
            Ok(self.records.borrow().clone())
        }
        fn insert(&self, record: &Record) -> Result<()> {
            self.inserts.set(self.inserts.get() + 1);
            if self.fail.get() {
                return Err(Error::Refused);
            }
            self.records.borrow_mut().push(record.clone());
            Ok(())
        }
        fn random_id(&self) -> Result<RegistrationId> {
            self.random_calls.set(self.random_calls.get() + 1);
            Ok(id())
        }
    }
    fn id() -> RegistrationId {
        RegistrationId::from_bytes([7; 32])
    }
    fn evidence() -> Evidence {
        let object = Object {
            dev: 1,
            ino: 2,
            uid: 1000,
            mode: 0o40700,
        };
        Evidence {
            pid: 42,
            start_ticks: 123,
            owner_uid: 1000,
            state_dir: "/state".into(),
            api_socket: "/state/api.sock".into(),
            directory: object,
            socket: Object {
                dev: 1,
                ino: 3,
                uid: 0,
                mode: 0o140600,
            },
            executable: Object {
                dev: 1,
                ino: 4,
                uid: 0,
                mode: 0o100755,
            },
            boot_id: "12345678-1234-1234-1234-123456789abc".into(),
        }
    }
    fn service() -> Service<Process, Memory> {
        Service::recover(
            Process {
                changed: Rc::new(Cell::new(false)),
                signals: Rc::new(Cell::new(0)),
                captures: Cell::new(0),
                unsupported: false,
            },
            Memory::default(),
        )
        .unwrap()
    }
    fn register(service: &mut Service<Process, Memory>, uid: u32) -> Result<Response> {
        service.execute(
            Peer { uid },
            Request {
                version: 1,
                operation: Operation::Register {
                    pid: 42,
                    owner_uid: 1000,
                    state_dir: "/state".into(),
                    api_socket: "/state/api.sock".into(),
                },
            },
        )
    }
    fn stop(service: &mut Service<Process, Memory>, uid: u32) -> Result<Response> {
        service.execute(
            Peer { uid },
            Request {
                version: 1,
                operation: Operation::Stop { id: id() },
            },
        )
    }
    #[test]
    fn only_root_registers_and_only_owner_or_root_stops() {
        let mut service = service();
        assert!(register(&mut service, 1000).is_err());
        assert_eq!(service.processes.captures.get(), 0);
        assert_eq!(service.storage.inserts.get(), 0);
        assert_eq!(service.storage.random_calls.get(), 0);
        assert!(service.storage.records.borrow().is_empty());
        assert!(service.admits_uid(0));
        assert!(!service.admits_uid(1000));
        // Identical payload has a root positive control, not invalid evidence.
        register(&mut service, 0).unwrap();
        assert_eq!(service.processes.captures.get(), 1);
        assert_eq!(service.storage.inserts.get(), 1);
        assert!(service.admits_uid(1000));
        assert!(!service.admits_uid(1001));
        assert!(stop(&mut service, 1001).is_err());
        for uid in [1000, 0, 1001] {
            let query = service.execute(
                Peer { uid },
                Request {
                    version: 1,
                    operation: Operation::Query { id: id() },
                },
            );
            assert_eq!(query.is_ok(), uid != 1001);
        }
        assert_eq!(service.processes.signals.get(), 0);
        stop(&mut service, 1000).unwrap();
        stop(&mut service, 0).unwrap();
        assert_eq!(service.processes.signals.get(), 2);
    }
    #[test]
    fn retained_handle_refuses_changed_identity() {
        let mut service = service();
        register(&mut service, 0).unwrap();
        service.processes.changed.set(true);
        assert!(stop(&mut service, 1000).is_err());
        assert_eq!(service.processes.signals.get(), 0);
    }
    #[test]
    fn failed_durable_insert_never_authorizes() {
        let mut service = service();
        service.storage.fail.set(true);
        assert!(register(&mut service, 0).is_err());
        assert!(stop(&mut service, 1000).is_err());
    }
    #[test]
    fn unsupported_pidfds_never_fall_back_and_restart_revalidates() {
        let mut service = service();
        service.processes.unsupported = true;
        assert!(matches!(register(&mut service, 0), Err(Error::Unsupported)));
        assert_eq!(service.processes.signals.get(), 0);
        service.processes.unsupported = false;
        register(&mut service, 0).unwrap();
        service.processes.changed.set(true);
        assert!(Service::recover(service.processes, service.storage).is_err());
    }
    #[test]
    fn strict_protocol_roundtrip_and_negative_shapes() {
        let text = format!(
            r#"{{"version":1,"operation":{{"op":"stop","id":"{}"}}}}"#,
            id().as_str()
        );
        let request: Request = serde_json::from_str(&text).unwrap();
        let encoded = serde_json::to_string(&request).unwrap();
        assert_eq!(
            serde_json::from_str::<Request>(&encoded).unwrap().version,
            1
        );
        for text in [
            r#"{"version":1,"uid":0,"operation":{"op":"query","id":"bad"}}"#,
            r#"{"version":1,"operation":{"op":"stop","id":"bad","pid":42}}"#,
            r#"{"version":1,"operation":{"op":"register","pid":42,"owner_uid":0,"state_dir":"/x","api_socket":"/x/s","signal":9}}"#,
        ] {
            assert!(serde_json::from_str::<Request>(text).is_err());
        }
        let base = serde_json::to_value(&request).unwrap();
        for field in ["pid", "signal", "scope", "path", "owner_uid", "uid"] {
            let mut value = base.clone();
            value["operation"][field] = serde_json::json!(0);
            assert!(serde_json::from_value::<Request>(value).is_err());
        }
        let mut value = base;
        value["uid"] = serde_json::json!(0);
        assert!(serde_json::from_value::<Request>(value).is_err());
    }
    #[test]
    fn unknown_ids_versions_and_capacity_do_not_create_authority() {
        let mut service = service();
        assert!(stop(&mut service, 0).is_err());
        assert!(
            service
                .execute(
                    Peer { uid: 0 },
                    Request {
                        version: 2,
                        operation: Operation::Query { id: id() },
                    }
                )
                .is_err()
        );
        register(&mut service, 0).unwrap();
        // Populate the real fixed cap without weakening production limits.
        for index in 0..MAX_RECORDS {
            let mut bytes = [0; 32];
            bytes[..std::mem::size_of::<usize>()].copy_from_slice(&index.to_be_bytes());
            let mut record = service.entries.get(&id()).unwrap().record.clone();
            record.id = RegistrationId::from_bytes(bytes);
            service.entries.insert(
                record.id.clone(),
                Entry {
                    record,
                    handle: service.entries.get(&id()).unwrap().handle.clone(),
                },
            );
        }
        assert!(matches!(register(&mut service, 0), Err(Error::Limit)));
        assert_eq!(service.processes.signals.get(), 0);
    }
    #[test]
    fn detached_actions_retain_original_handles_and_authorize_before_checks() {
        let mut service = service();
        register(&mut service, 0).unwrap();
        let request = || Request {
            version: 1,
            operation: Operation::Stop { id: id() },
        };
        assert!(service.action(Peer { uid: 1001 }, request()).is_err());
        let action = service.action(Peer { uid: 1000 }, request()).unwrap();
        service.entries.clear();
        action.run(&service.processes).unwrap();
        assert_eq!(service.processes.signals.get(), 1);
        service.processes.changed.set(true);
        assert!(action.run(&service.processes).is_err());
        assert_eq!(service.processes.signals.get(), 1);
    }
    #[cfg(unix)]
    #[test]
    fn filesystem_backend_refuses_mutation_before_signaling() {
        use crate::identity::same_pin;
        use std::fs::{self, File};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        struct Files {
            path: std::path::PathBuf,
            signals: Cell<usize>,
        }
        fn identity(metadata: std::fs::Metadata) -> Object {
            Object {
                dev: metadata.dev(),
                ino: metadata.ino(),
                uid: metadata.uid(),
                mode: metadata.mode(),
            }
        }
        impl Processes for Files {
            type Handle = File;
            fn capture(&self, operation: &Operation) -> Result<(File, Evidence)> {
                let Operation::Register { owner_uid, .. } = operation else {
                    return Err(Error::Protocol);
                };
                let handle = File::open(&self.path)?;
                let directory = identity(handle.metadata()?);
                if directory.uid != *owner_uid {
                    return Err(Error::Refused);
                }
                let mut evidence = evidence();
                evidence.directory = directory;
                evidence.owner_uid = *owner_uid;
                Ok((handle, evidence))
            }
            fn validate(&self, handle: &File, evidence: &Evidence) -> Result<Status> {
                same_pin(
                    &evidence.directory,
                    &identity(handle.metadata()?),
                    &identity(fs::symlink_metadata(&self.path)?),
                )?;
                Ok(Status::Running)
            }
            fn stop(&self, handle: &File, evidence: &Evidence) -> Result<Status> {
                self.validate(handle, evidence)?;
                self.signals.set(self.signals.get() + 1);
                Ok(Status::StopRequested)
            }
        }
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("state");
        fs::create_dir(&path).unwrap();
        let original = fs::metadata(&path).unwrap();
        let uid = original.uid();
        let mut service = Service::recover(
            Files {
                path: path.clone(),
                signals: Cell::new(0),
            },
            Memory::default(),
        )
        .unwrap();
        let register = |owner_uid| Request {
            version: 1,
            operation: Operation::Register {
                pid: 42,
                owner_uid,
                state_dir: path.to_str().unwrap().into(),
                api_socket: path.join("api.sock").to_str().unwrap().into(),
            },
        };
        assert!(service.execute(Peer { uid: 0 }, register(uid + 1)).is_err());
        service.execute(Peer { uid: 0 }, register(uid)).unwrap();
        let stop = || Request {
            version: 1,
            operation: Operation::Stop { id: id() },
        };
        let action = service.action(Peer { uid }, stop()).unwrap();
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode((original.mode() ^ 0o100) & 0o777),
        )
        .unwrap();
        assert!(action.run(&service.processes).is_err());
        assert_eq!(service.processes.signals.get(), 0);
        fs::set_permissions(&path, fs::Permissions::from_mode(original.mode() & 0o777)).unwrap();
        action.run(&service.processes).unwrap();
        fs::rename(&path, temporary.path().join("original")).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(action.run(&service.processes).is_err());
        assert_eq!(service.processes.signals.get(), 1);
        fs::remove_dir(&path).unwrap();
        std::os::unix::fs::symlink(temporary.path().join("original"), &path).unwrap();
        assert!(action.run(&service.processes).is_err());
        assert_eq!(service.processes.signals.get(), 1);
        // Even intact root evidence cannot restore the lost original pin.
        assert!(Service::recover(service.processes, service.storage).is_err());
    }
}
