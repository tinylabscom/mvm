//! Exercise the handshake frames that carry the control advertisement.
//!
//! `SessionHelloAck` and `SessionHelloConfirm` are parsed before any signature
//! is checked, and the ack now carries a guest-chosen capability set and
//! version string. The property is "never panic": whatever parses must stay
//! bounded and must re-serialize to something that parses back to the same
//! value, and the advertisement validator must not panic on it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mvm_contract::policy::control_negotiation::{ControlOffer, ControlRange};
use mvm_contract::policy::security::{SessionHello, SessionHelloAck, SessionHelloConfirm};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<SessionHello>(data);

    if let Ok(confirm) = serde_json::from_slice::<SessionHelloConfirm>(data)
        && let Some(range) = confirm.control
    {
        let _ = range.validate();
        let again = serde_json::to_vec(&range).expect("a parsed range serializes");
        assert_eq!(
            serde_json::from_slice::<ControlRange>(&again).expect("round trip"),
            range
        );
    }

    if let Ok(ack) = serde_json::from_slice::<SessionHelloAck>(data)
        && let Some(offer) = ack.control
    {
        // The set is a closed enum, so it can never exceed the variant count
        // whatever the input repeats.
        assert!(offer.capabilities.len() <= 15);
        let _ = offer.validate();
        let again = serde_json::to_vec(&offer).expect("a parsed offer serializes");
        assert_eq!(
            serde_json::from_slice::<ControlOffer>(&again).expect("round trip"),
            offer
        );
    }
});
