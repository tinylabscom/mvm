//! Supervisor-owned capture routing across a resident (not forked) handoff.
//!
//! The device model sends only authenticated child context. Preparation and
//! retirement run here, never while holding the device bus. The old producer
//! must be detached before `finish`; a failed retirement never authorizes ACK.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use anyhow::{Context, Result};
use mvm_vmm::hvf_handoff::{
    CAPTURE_HANDOFF_TIMEOUT, CaptureControl, CaptureControlSender, CapturePreparation,
};

use crate::stream::protected::{CaptureAuthority, CaptureOwner, CaptureParams};

pub struct CaptureRoute {
    control: CaptureControlSender,
}

impl CaptureRoute {
    pub fn start(
        owner: CaptureOwner,
        pid_file: PathBuf,
        stop: &'static AtomicBool,
    ) -> Result<Self> {
        let (control, requests) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("mvm-capture-handoff".into())
            .spawn(move || {
                let mut owner = Some(owner);
                let mut claimed = false;
                let mut _bounds = None;
                while let Ok(request) = requests.recv() {
                    match request {
                        CaptureControl::Prepare(request) => {
                            let result = if claimed {
                                Err(anyhow::anyhow!("capture owner already transferred"))
                            } else {
                                claimed = true;
                                transfer(&mut owner, &request, &pid_file)
                            };
                            match result {
                                Ok(bounds) => {
                                    _bounds = bounds;
                                    if request.sealed.try_send(true).is_err() {
                                        stop.store(true, Ordering::Release);
                                        break;
                                    }
                                }
                                Err(_) => {
                                    stop.store(true, Ordering::Release);
                                    let _ = request.sealed.try_send(false);
                                    break;
                                }
                            }
                        }
                        CaptureControl::Finish(reply) => {
                            let complete = owner.take().is_some_and(CaptureOwner::finish);
                            let _ = reply.try_send(complete);
                            return;
                        }
                    }
                }
                if let Some(owner) = owner {
                    let _ = owner.finish();
                }
            })
            .context("start capture ownership controller")?;
        Ok(Self { control })
    }

    pub fn control(&self) -> CaptureControlSender {
        self.control.clone()
    }

    /// Called only after the VM has dropped the UART producer.
    pub fn finish(self) -> bool {
        let (reply, result) = mpsc::sync_channel(1);
        if self
            .control
            .try_send(CaptureControl::Finish(reply))
            .is_err()
        {
            return false;
        }
        result
            .recv_timeout(CAPTURE_HANDOFF_TIMEOUT)
            .unwrap_or(false)
    }
}

fn transfer(
    owner: &mut Option<CaptureOwner>,
    request: &CapturePreparation,
    pid_file: &std::path::Path,
) -> Result<Option<super::wall_clock::WallClockGuard>> {
    let json = request
        .child
        .admitted_plan
        .as_deref()
        .context("protected child has no admitted plan")?;
    // The enclosing handoff signature binds both these exact bytes and the
    // concrete child instance. A workload name is deliberately not an instance.
    let plan = mvm_core::plan::plan_from_admitted_json(json)?;
    let (child, producer) = CaptureOwner::start(CaptureParams {
        vm: &request.child.child_vm_name,
        authority: CaptureAuthority::Admitted(&plan),
        redaction: &plan.redaction,
    })?;
    if request.prepared.try_send(Ok(Box::new(producer))).is_err() {
        let _ = child.finish();
        anyhow::bail!("capture preparation canceled");
    }
    if request.detached.recv_timeout(CAPTURE_HANDOFF_TIMEOUT) != Ok(true) {
        let _ = child.finish();
        anyhow::bail!("parent UART did not detach");
    }
    let parent = owner
        .replace(child)
        .context("parent capture owner missing")?;
    if !parent.finish() {
        anyhow::bail!("parent capture finalization incomplete");
    }
    super::claimed_child::arm_for_claimed_child(&request.child, pid_file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::config;
    use mvm_core::plan::test_support::PlanFixture;
    use mvm_core::stream_client::protected::ProtectedRun;
    use mvm_core::transcript::{self, MANIFEST_FILENAME, TranscriptManifest};
    use mvm_core::util::test_env::TestEnv;
    use mvm_vmm::hvf_handoff::{AcceptedHandoff, HandoffFence};
    use mvm_vmm::vmm::device::{ConsoleHandoff, MmioDevice, Pl011};
    use std::sync::Arc;

    fn manifest(vm: &str) -> (ProtectedRun, PathBuf, TranscriptManifest) {
        let root = config::vm_stream_transcript_dir(vm);
        let run = ProtectedRun::read(&root).unwrap().unwrap();
        let dir = run.directory(&root).unwrap().join("00000000000000000000");
        let manifest =
            serde_json::from_slice(&std::fs::read(dir.join(MANIFEST_FILENAME)).unwrap()).unwrap();
        (run, dir, manifest)
    }

    #[test]
    fn owner_route_seals_parent_and_installs_fresh_child_key_run_and_binding() {
        check_owner_transition(false);
    }

    #[test]
    fn operational_live_only_parent_transfers_to_admitted_child_without_downgrade() {
        check_owner_transition(true);
    }

    fn check_owner_transition(operational: bool) {
        let mut env = TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        crate::audit::host_keypair::load_or_init_at(&config::mvm_keys_dir()).unwrap();
        let parent_plan = PlanFixture::new().tenant("parent-tenant").build();
        let child_plan = PlanFixture::new().tenant("child-tenant").build();
        let (owner, producer) = CaptureOwner::start(CaptureParams {
            vm: "route-parent",
            authority: if operational {
                CaptureAuthority::OperationalLiveOnly
            } else {
                CaptureAuthority::Admitted(&parent_plan)
            },
            redaction: &parent_plan.redaction,
        })
        .unwrap();
        let stop = Box::leak(Box::new(AtomicBool::new(false)));
        let route = CaptureRoute::start(
            owner,
            config::vm_state_dir("route-parent").join("supervisor.pid"),
            stop,
        )
        .unwrap();
        let mut uart = Pl011::new(0);
        uart.stream_to(Box::new(producer));
        for byte in b"parent-partial" {
            uart.write(0, u64::from(*byte), 1);
        }
        let (prepared, producer) = mpsc::sync_channel(1);
        let (detached, retired) = mpsc::sync_channel(1);
        let (sealed, ready) = mpsc::sync_channel(1);
        route
            .control
            .try_send(CaptureControl::Prepare(CapturePreparation {
                child: AcceptedHandoff {
                    child_vm_name: "route-child".into(),
                    admitted_plan: Some(serde_json::to_string(&child_plan).unwrap()),
                },
                prepared,
                detached: retired,
                sealed,
            }))
            .ok()
            .unwrap();
        let sink = producer
            .recv_timeout(CAPTURE_HANDOFF_TIMEOUT)
            .unwrap()
            .unwrap();
        assert!(
            ready.try_recv().is_err(),
            "owner cannot seal with its producer attached"
        );
        let fence = Arc::new(HandoffFence::new(2));
        fence.begin().unwrap();
        fence.acknowledge(0);
        fence.acknowledge(1);
        let (commands, receiver) = mpsc::sync_channel(1);
        uart.handoffs_from(receiver);
        commands
            .try_send(ConsoleHandoff {
                fence,
                sink,
                detached,
            })
            .ok()
            .unwrap();
        uart.poll_handoff();
        assert!(ready.recv_timeout(CAPTURE_HANDOFF_TIMEOUT).unwrap());
        let parent = if operational {
            let root = config::vm_stream_transcript_dir("route-parent");
            let run = ProtectedRun::read(&root).unwrap().unwrap();
            assert!(!run.persists);
            assert!(!run.directory(&root).unwrap().exists());
            None
        } else {
            let parent = manifest("route-parent");
            assert!(
                parent.2.sealed_unix_secs.is_some(),
                "seal is a pre-ACK condition"
            );
            Some(parent)
        };
        for byte in b"child-marker\n" {
            uart.write(0, u64::from(*byte), 1);
        }
        drop(uart);
        assert!(route.finish());
        assert!(!stop.load(Ordering::Relaxed));
        let (child_run, child_dir, child) = manifest("route-child");
        assert!(
            child_run.persists,
            "child admitted retention is not downgraded"
        );
        assert_eq!(child.binding.vm_name, "route-child");
        assert_eq!(child.binding.tenant_id, "child-tenant");
        let kek = transcript::load_or_init_kek(&config::mvm_keys_dir()).unwrap();
        let mut exports = Vec::new();
        if let Some((parent_run, parent_dir, parent)) = parent {
            assert_ne!(parent_run.run, child_run.run);
            assert_ne!(parent.wrapped_data_key_b64, child.wrapped_data_key_b64);
            assert_eq!(parent.binding.vm_name, "route-parent");
            exports.push((parent_dir, parent, b"parent-partial".as_slice()));
        }
        exports.push((child_dir, child, b"child-marker\n".as_slice()));
        for (dir, manifest, marker) in exports {
            let key = transcript::unwrap_data_key(&kek, &manifest.wrapped_data_key_b64).unwrap();
            let chunks = transcript::export_chunks(&manifest, &dir, &key).unwrap();
            assert_eq!(chunks.len(), 1);
            let record: mvm_contract::stream::StreamRecord =
                serde_json::from_slice(&chunks[0].plaintext).unwrap();
            assert_eq!(record.payload, marker);
        }
        assert!(!config::vm_console_log("route-parent").exists());
        assert!(!config::vm_console_log("route-child").exists());
    }
}
