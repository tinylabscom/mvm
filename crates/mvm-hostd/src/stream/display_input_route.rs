//! The road from the display input gate to the guest's display bridge.
//!
//! The gate decides whether a frame may move and records it; the route carries
//! what the gate returned to the guest agent, one RPC per frame, in the order
//! the gate accepted them. Nothing here decides anything a second time: the
//! only constructor takes a session the gate already opened.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use mvm_agentd::vsock::{DisplayDeliveryRefusal, DisplayInputResult};
use mvm_contract::stream::DisplayInputFrame;

use crate::stream::display_input_gate::{DisplayInputRefusal, DisplayInputSession};

/// How many times a frame is offered to a guest whose bridge is between reads.
///
/// The bridge reopens its end of the FIFO after every delivery, so a frame can
/// land in the gap and be told nobody is reading. The gap is a few
/// microseconds; a bridge that is really absent stays absent across all of
/// these.
const NO_BRIDGE_ATTEMPTS: u32 = 5;
const NO_BRIDGE_BACKOFF: Duration = Duration::from_millis(50);

/// Where an admitted frame goes. A trait so the route's ordering and retry are
/// testable without a guest.
pub trait DisplayInputTransport: Send {
    /// Offer one frame and report what the guest answered.
    fn deliver(&mut self, frame: &DisplayInputFrame) -> Result<DisplayInputResult>;
}

/// The production transport: the running VM's guest agent over vsock.
pub struct VsockDisplayInput {
    vm: String,
}

impl VsockDisplayInput {
    #[must_use]
    pub fn new(vm: impl Into<String>) -> Self {
        Self { vm: vm.into() }
    }
}

impl DisplayInputTransport for VsockDisplayInput {
    fn deliver(&mut self, frame: &DisplayInputFrame) -> Result<DisplayInputResult> {
        let transport = mvm_runtime::vsock_transport::for_vm(&self.vm)
            .with_context(|| format!("pick a transport for the guest agent on {:?}", self.vm))?;
        let mut stream = transport
            .connect(mvm_agentd::vsock::GUEST_AGENT_PORT)
            .with_context(|| format!("connect to the guest agent on {:?}", self.vm))?;
        Ok(mvm_agentd::vsock::send_display_input(
            &mut stream,
            frame.clone(),
        )?)
    }
}

/// Why a frame did not reach the guest's display.
#[derive(Debug, thiserror::Error)]
pub enum DisplayInputRouteError {
    /// The gate refused the frame; it was recorded and never sent.
    #[error("display input refused: {0}")]
    Refused(#[from] DisplayInputRefusal),
    /// The gate admitted the frame and the guest could not deliver it.
    #[error("display input was admitted but not delivered: {0:#}")]
    Undelivered(anyhow::Error),
}

/// One gate session bound to one transport.
pub struct DisplayInputRoute {
    session: DisplayInputSession,
    transport: Box<dyn DisplayInputTransport>,
}

impl DisplayInputRoute {
    #[must_use]
    pub fn new(session: DisplayInputSession, transport: Box<dyn DisplayInputTransport>) -> Self {
        Self { session, transport }
    }

    /// Offer one frame: through the gate, then to the guest.
    ///
    /// # Errors
    /// The gate's refusal, or a delivery failure after admission.
    pub fn write(&mut self, frame: DisplayInputFrame) -> Result<(), DisplayInputRouteError> {
        let admitted = self.session.write(frame)?;
        self.deliver(&admitted)
            .map_err(DisplayInputRouteError::Undelivered)
    }

    /// Keep the lease alive while the human is idle.
    ///
    /// # Errors
    /// The lease lapsed or the session already refused.
    pub fn refresh(&mut self) -> Result<(), DisplayInputRefusal> {
        self.session.refresh()
    }

    /// Whether a credential entry is open.
    #[must_use]
    pub fn credential_entry_open(&self) -> bool {
        self.session.credential_entry_open()
    }

    /// End the session: close any open credential entry and release the lease.
    pub fn close(self) {
        self.session.close();
    }

    fn deliver(&mut self, frame: &DisplayInputFrame) -> Result<()> {
        let mut attempt = 1;
        loop {
            match self.transport.deliver(frame)? {
                DisplayInputResult::Accepted => return Ok(()),
                DisplayInputResult::Refused {
                    kind: DisplayDeliveryRefusal::NoBridge,
                    message,
                } => {
                    if attempt >= NO_BRIDGE_ATTEMPTS {
                        bail!("the guest has no display bridge reading input: {message}");
                    }
                    attempt += 1;
                    std::thread::sleep(NO_BRIDGE_BACKOFF);
                }
                DisplayInputResult::Refused { kind, message } => {
                    bail!("the guest refused the display input frame ({kind:?}): {message}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use mvm_contract::grants::{DisplayInputGrant, DisplayTier, Grants};
    use mvm_contract::stream::{DisplayInputEvent, PointerButton};
    use mvm_core::plan::test_support::PlanFixture;

    use super::*;
    use crate::stream::display_input_gate::open_for_test;

    /// Answers from a script, and records every frame it was offered.
    struct Scripted {
        answers: Vec<DisplayInputResult>,
        offered: Arc<Mutex<Vec<u64>>>,
    }

    impl DisplayInputTransport for Scripted {
        fn deliver(&mut self, frame: &DisplayInputFrame) -> Result<DisplayInputResult> {
            self.offered.lock().unwrap().push(frame.seq);
            Ok(if self.answers.is_empty() {
                DisplayInputResult::Accepted
            } else {
                self.answers.remove(0)
            })
        }
    }

    fn route(
        answers: Vec<DisplayInputResult>,
        vm: &str,
    ) -> (DisplayInputRoute, Arc<Mutex<Vec<u64>>>) {
        let plan = PlanFixture::new()
            .grants(Some(Grants {
                display_input: Some(DisplayInputGrant::default()),
                ..Grants::default()
            }))
            .build();
        let session = open_for_test(&plan, vm, DisplayTier::Accessible).expect("granted session");
        let offered = Arc::new(Mutex::new(Vec::new()));
        (
            DisplayInputRoute::new(
                session,
                Box::new(Scripted {
                    answers,
                    offered: Arc::clone(&offered),
                }),
            ),
            offered,
        )
    }

    fn click(seq: u64) -> DisplayInputFrame {
        DisplayInputFrame {
            seq,
            events: vec![DisplayInputEvent::PointerButton {
                x: 1,
                y: 1,
                button: PointerButton::Left,
                pressed: true,
            }],
        }
    }

    fn no_bridge() -> DisplayInputResult {
        DisplayInputResult::Refused {
            kind: DisplayDeliveryRefusal::NoBridge,
            message: "between reads".into(),
        }
    }

    #[test]
    fn a_bridge_between_reads_gets_the_same_frame_again() {
        let (mut route, offered) = route(vec![no_bridge(), no_bridge()], "route-retry");
        route.write(click(0)).unwrap();
        assert_eq!(*offered.lock().unwrap(), vec![0, 0, 0]);
    }

    #[test]
    fn an_absent_bridge_is_reported_after_a_bounded_number_of_offers() {
        let answers = (0..NO_BRIDGE_ATTEMPTS).map(|_| no_bridge()).collect();
        let (mut route, offered) = route(answers, "route-absent");
        assert!(matches!(
            route.write(click(0)),
            Err(DisplayInputRouteError::Undelivered(_))
        ));
        assert_eq!(offered.lock().unwrap().len(), NO_BRIDGE_ATTEMPTS as usize);
    }

    #[test]
    fn a_frame_the_gate_refuses_never_reaches_the_transport() {
        let (mut route, offered) = route(Vec::new(), "route-refused");
        route.write(click(5)).unwrap();
        assert!(matches!(
            route.write(click(5)),
            Err(DisplayInputRouteError::Refused(
                DisplayInputRefusal::OutOfOrder { .. }
            ))
        ));
        assert_eq!(*offered.lock().unwrap(), vec![5]);
    }
}
