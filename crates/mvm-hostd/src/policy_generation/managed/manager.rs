//! Read-only observations of the existing unit over the manager's native socket.

use zbus::{OwnedObjectPath, OwnedVariant};

use super::{ManagedIdentity, ManagedRefusal, PeerProcess, UnitObservation, native_bus};

const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER: &str = "org.freedesktop.systemd1.Manager";
const UNIT: &str = "org.freedesktop.systemd1.Unit";
const SERVICE: &str = "org.freedesktop.systemd1.Service";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";

fn unknown(identity: &ManagedIdentity, detail: String) -> ManagedRefusal {
    ManagedRefusal::Unknown {
        unit: identity.unit().to_string(),
        detail,
    }
}

fn verify_manager_peer(
    identity: &ManagedIdentity,
    peer: PeerProcess,
) -> Result<(), ManagedRefusal> {
    if peer.uid != identity.uid() || peer.pid <= 1 {
        return Err(ManagedRefusal::ManagerUnavailable {
            unit: identity.unit().to_string(),
            reason: "the native socket has no matching user-manager peer",
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) async fn connect(
    identity: &ManagedIdentity,
    deadline: tokio::time::Instant,
) -> Result<native_bus::NativeConnection, ManagedRefusal> {
    require_budget(identity, deadline)?;
    let unavailable = || ManagedRefusal::ManagerUnavailable {
        unit: identity.unit().to_string(),
        reason: "its fixed native socket is unavailable",
    };
    let socket = format!("/run/user/{}/systemd/private", identity.uid());
    let stream =
        super::connect_without_waiting(std::path::Path::new(&socket)).map_err(|_| unavailable())?;
    let peer = super::peer_credentials(&stream).map_err(|_| unavailable())?;
    verify_manager_peer(identity, peer)?;
    stream.set_nonblocking(true).map_err(|_| unavailable())?;
    let stream = tokio::net::UnixStream::from_std(stream).map_err(|_| unavailable())?;
    native_bus::connect(stream, deadline)
        .await
        .map_err(|error| {
            unknown(
                identity,
                format!("authenticating the native manager: {error:#}"),
            )
        })
}

/// Read only the named, already-loaded unit. In particular, `GetUnit` does
/// not load a dormant unit just to discover its state.
pub(super) async fn observe(
    bus: &native_bus::NativeConnection,
    identity: &ManagedIdentity,
    deadline: tokio::time::Instant,
) -> Result<UnitObservation, ManagedRefusal> {
    require_budget(identity, deadline)?;
    let observation = tokio::time::timeout_at(deadline, observe_on(bus, identity))
        .await
        .map_err(|_| {
            unknown(
                identity,
                "native manager observation deadline expired".into(),
            )
        })??;
    require_budget(identity, deadline)?;
    Ok(observation)
}

fn require_budget(
    identity: &ManagedIdentity,
    deadline: tokio::time::Instant,
) -> Result<(), ManagedRefusal> {
    if tokio::time::Instant::now() >= deadline {
        Err(unknown(
            identity,
            "native manager observation deadline expired".into(),
        ))
    } else {
        Ok(())
    }
}

async fn observe_on(
    bus: &native_bus::NativeConnection,
    identity: &ManagedIdentity,
) -> Result<UnitObservation, ManagedRefusal> {
    let reply = bus
        .connection
        .call_method(
            None::<&str>,
            MANAGER_PATH,
            Some(MANAGER),
            "GetUnit",
            &(identity.unit(),),
        )
        .await
        .map_err(|error| {
            let detail = match &error {
                zbus::Error::MethodError(name, _, _)
                    if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit" =>
                {
                    // An unloaded unit can still have an installed unit file.
                    // Do not turn absence from the manager into "not provisioned".
                    "the unit is not loaded; it was not loaded or started to inspect it".to_string()
                }
                _ => format!("reading the native manager's unit: {error}"),
            };
            unknown(identity, detail)
        })?;
    let path: OwnedObjectPath = reply.body().deserialize().map_err(|error| {
        unknown(
            identity,
            format!("decoding the manager's unit path: {error}"),
        )
    })?;
    if !path
        .as_str()
        .strip_prefix("/org/freedesktop/systemd1/unit/")
        .is_some_and(|name| !name.is_empty() && !name.contains('/'))
    {
        return Err(unknown(
            identity,
            "the manager returned an invalid unit path".into(),
        ));
    }
    let id: String = property(bus, &path, UNIT, "Id", identity).await?;
    if id != identity.unit() {
        return Err(ManagedRefusal::IdentityMismatch {
            unit: identity.unit().to_string(),
            detail: format!("the manager returned a different unit: {id:?}"),
        });
    }
    let load_state: String = property(bus, &path, UNIT, "LoadState", identity).await?;
    if load_state != "loaded" {
        return Err(ManagedRefusal::NotProvisioned {
            unit: identity.unit().to_string(),
            load_state,
        });
    }
    let active_state: String = property(bus, &path, UNIT, "ActiveState", identity).await?;
    if active_state != "active" {
        return Err(ManagedRefusal::NotRunning {
            unit: identity.unit().to_string(),
            active_state,
        });
    }
    let main_pid: u32 = property(bus, &path, SERVICE, "MainPID", identity).await?;
    let invocation: Vec<u8> = property(bus, &path, UNIT, "InvocationID", identity).await?;
    if main_pid <= 1 || invocation.len() != 16 || invocation.iter().all(|byte| *byte == 0) {
        return Err(unknown(
            identity,
            "the manager reports it active without a main process and invocation".into(),
        ));
    }
    Ok(UnitObservation {
        main_pid,
        invocation: hex::encode(invocation),
    })
}

async fn property<T: TryFrom<OwnedVariant>>(
    bus: &native_bus::NativeConnection,
    path: &OwnedObjectPath,
    interface: &str,
    name: &str,
    identity: &ManagedIdentity,
) -> Result<T, ManagedRefusal> {
    let reply = bus
        .connection
        .call_method(
            None::<&str>,
            path.as_str(),
            Some(PROPERTIES),
            "Get",
            &(interface, name),
        )
        .await
        .map_err(|error| {
            unknown(
                identity,
                format!("reading manager property {name}: {error}"),
            )
        })?;
    let value: OwnedVariant = reply.body().deserialize().map_err(|error| {
        unknown(
            identity,
            format!("decoding manager property {name}: {error}"),
        )
    })?;
    T::try_from(value).map_err(|_| {
        unknown(
            identity,
            format!("manager property {name} has the wrong type"),
        )
    })
}

#[cfg(test)]
#[path = "manager_tests.rs"]
mod tests;
