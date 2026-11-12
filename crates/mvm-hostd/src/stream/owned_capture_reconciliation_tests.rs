//! Count reconciliation fixtures, not owner-authenticated receipts or runtime finalization.

use super::*;

fn modeled_receipt(producer: &ModelProducer, frame: &Fragment, copy: RecordedCopy) -> ModelReceipt {
    let dropped = matches!(copy, RecordedCopy::NotRecorded);
    ModelReceipt {
        connection: producer.connection.id,
        challenge: producer.connection.challenge,
        sequence: frame.sequence,
        broker_sequence: (!dropped).then_some(frame.sequence),
        dropped_bytes: dropped.then(|| u32::try_from(frame.body.len()).unwrap()),
        copy,
    }
}

fn acknowledge(producer: &mut ModelProducer, copy: RecordedCopy) {
    let frame = producer.take_next().unwrap().unwrap();
    let reply = modeled_receipt(producer, &frame, copy);
    producer.confirm(reply).unwrap();
    assert!(producer.partition_valid());
}

fn masked() -> RecordedCopy {
    RecordedCopy::Masked {
        rules_fired: vec!["fixture"],
    }
}

fn withheld() -> RecordedCopy {
    RecordedCopy::Withheld {
        reason: "fixture detector unavailable".into(),
    }
}

fn mixed_final() -> (ModelProducer, ModelFinal) {
    let permit = ModelPermit::new(binding());
    let mut producer = ModelProducer::new(permit.spend(&binding(), 10).unwrap(), 64, 1024);
    for (body, copy) in [
        (b"a".as_slice(), RecordedCopy::Identical),
        (b"bb".as_slice(), masked()),
        (b"ccc".as_slice(), masked()),
        (b"dddd".as_slice(), withheld()),
        (b"e".as_slice(), RecordedCopy::NotRecorded),
    ] {
        producer.offer(StreamKind::Stdout, body).unwrap();
        acknowledge(&mut producer, copy);
    }
    producer.freeze().unwrap();
    let reply = producer.finish().unwrap();
    (producer, reply)
}

#[test]
fn frozen_cut_conserves_original_fragments_and_bytes_without_double_counting_subcategories() {
    let mut producer = producer();
    producer.offer(StreamKind::Stdout, b"abc").unwrap();
    producer.offer(StreamKind::Stderr, b"de").unwrap();
    assert_eq!(producer.offer(StreamKind::Stdout, b"drop"), Ok(None));
    acknowledge(&mut producer, RecordedCopy::Identical);
    acknowledge(&mut producer, masked());
    producer.offer(StreamKind::Stderr, b"w").unwrap();
    acknowledge(&mut producer, withheld());
    producer.offer(StreamKind::Stdout, b"e").unwrap();
    acknowledge(&mut producer, RecordedCopy::NotRecorded);
    producer.freeze().unwrap();
    let offered = producer.offered;
    let reply = producer.finish().unwrap();
    producer.confirm_final(&reply).unwrap();
    assert_eq!(
        offered,
        Count {
            frames: 5,
            bytes: 11
        }
    );
    assert_eq!(
        producer.local_dropped,
        Count {
            frames: 1,
            bytes: 4
        }
    );
    assert_eq!(
        producer.owner_dropped,
        Count {
            frames: 1,
            bytes: 1
        }
    );
    assert_eq!(
        producer.accepted,
        Count {
            frames: 3,
            bytes: 6
        }
    );
    assert_eq!(
        producer.dispositions,
        [
            Count {
                frames: 1,
                bytes: 3
            },
            Count {
                frames: 1,
                bytes: 2
            },
            Count {
                frames: 1,
                bytes: 1
            },
        ]
    );
    assert_eq!(producer.unconfirmed, Count::default());
    assert_eq!(producer.accounted(), Ok(offered));
    assert_eq!(Count::sum(producer.dispositions), Ok(producer.accepted));
    assert_eq!(reply.through, 4);
    assert_eq!((reply.masked, reply.withheld), (1, 1));
    assert_eq!(producer.phase, ProducerPhase::Closed);
    assert!(
        !producer.complete(),
        "confirmed close with losses is not complete acceptance"
    );
}

#[test]
fn actual_withheld_marker_length_is_not_the_original_payload_count() {
    use super::super::tests::{FailingRedactor, fixture_with};
    use crate::stream::redact::StreamRedaction;

    let fx = fixture_with(
        "qualification-withheld-count",
        StreamRedaction::from_seam(Box::new(FailingRedactor)),
    );
    let mut reader = lock_broker(&fx.broker).subscribe();
    let mut sink = EntrypointSink::recorded(&fx.broker);
    let mut producer = producer();
    producer.offer(StreamKind::Stderr, b"x").unwrap();
    let (shown, receipt) = record(&mut producer, &mut sink, &mut reader);
    assert_eq!(shown.body, b"x");
    assert!(matches!(shown.recorded, RecordedCopy::Withheld { .. }));
    producer.confirm(receipt).unwrap();
    producer.freeze().unwrap();
    let reply = producer.finish().unwrap();
    producer.confirm_final(&reply).unwrap();
    assert_eq!(
        producer.accepted,
        Count {
            frames: 1,
            bytes: 1
        }
    );
    assert_eq!(producer.dispositions[2], producer.accepted);
    assert_eq!(reply.withheld, 1);
    drop(sink);
    let stored = sealed_fixture_payload(fx);
    assert_ne!(stored.len(), 1, "the marker has a different stored length");
    assert!(producer.partition_valid());
}

#[test]
fn final_must_match_every_retained_count_call_sequence_and_challenge() {
    let changes: [fn(&mut ModelFinal); 10] = [
        |reply| reply.binding.call += 1,
        |reply| reply.challenge[0] ^= 1,
        |reply| reply.through += 1,
        |reply| reply.accepted.frames += 1,
        |reply| reply.accepted.bytes += 1,
        |reply| reply.owner_dropped.frames += 1,
        |reply| reply.owner_dropped.bytes += 1,
        |reply| reply.masked += 1,
        |reply| reply.withheld += 1,
        |reply| std::mem::swap(&mut reply.masked, &mut reply.withheld),
    ];
    for change in changes {
        let (mut producer, reply) = mixed_final();
        let known = (
            producer.accepted,
            producer.owner_dropped,
            producer.dispositions,
        );
        let mut conflicting = reply.clone();
        change(&mut conflicting);
        assert_eq!(producer.confirm_final(&conflicting), Err(Refusal::Receipt));
        assert_eq!(producer.confirm_final(&reply), Err(Refusal::Receipt));
        assert_eq!(
            (
                producer.accepted,
                producer.owner_dropped,
                producer.dispositions
            ),
            known
        );
        assert_eq!(producer.unconfirmed, Count::default());
        assert!(producer.partition_valid());
        assert!(!producer.complete());
    }
}

#[test]
fn valid_final_reconciles_masked_withheld_and_inferred_identical_subcategories() {
    let (mut producer, reply) = mixed_final();
    assert_eq!(
        reply.accepted,
        Count {
            frames: 4,
            bytes: 10
        }
    );
    assert_eq!(
        reply.owner_dropped,
        Count {
            frames: 1,
            bytes: 1
        }
    );
    assert_eq!((reply.masked, reply.withheld), (2, 1));
    producer.confirm_final(&reply).unwrap();
    assert_eq!(
        producer.dispositions[0],
        Count {
            frames: 1,
            bytes: 1
        }
    );
    assert_eq!(producer.phase, ProducerPhase::Closed);
    assert!(producer.partition_valid());
}

#[test]
fn lost_final_keeps_known_dispositions_and_only_final_close_is_unconfirmed() {
    let (mut producer, _lost_final) = mixed_final();
    let known = (
        producer.accepted,
        producer.owner_dropped,
        producer.dispositions,
    );
    producer.abort();
    assert_eq!(
        (
            producer.accepted,
            producer.owner_dropped,
            producer.dispositions
        ),
        known
    );
    assert_eq!(producer.unconfirmed, Count::default());
    assert_eq!(producer.accounted(), Ok(producer.offered));
    assert_eq!(producer.phase, ProducerPhase::Aborted);
    assert!(!producer.complete());
}

#[test]
fn terminal_deadline_keeps_known_acceptance_separate_from_inflight_and_unsent_loss() {
    let mut producer = producer();
    producer.offer(StreamKind::Stdout, b"abc").unwrap();
    acknowledge(&mut producer, RecordedCopy::Identical);
    producer.offer(StreamKind::Stderr, b"de").unwrap();
    producer.take_next().unwrap().unwrap();
    producer.offer(StreamKind::Stdout, b"f").unwrap();
    producer.freeze().unwrap();
    let offered = producer.offered;
    producer.abort();
    assert_eq!(
        producer.accepted,
        Count {
            frames: 1,
            bytes: 3
        }
    );
    assert_eq!(
        producer.unconfirmed,
        Count {
            frames: 1,
            bytes: 2
        }
    );
    assert_eq!(
        producer.local_dropped,
        Count {
            frames: 1,
            bytes: 1
        }
    );
    assert_eq!(producer.accounted(), Ok(offered));
    assert!(producer.partition_valid());
    assert!(!producer.complete());
}

#[test]
fn wrong_challenge_or_drop_byte_count_cannot_resolve_an_inflight_fragment() {
    for wrong_challenge in [true, false] {
        let mut producer = producer();
        producer.offer(StreamKind::Stdout, b"abc").unwrap();
        let frame = producer.take_next().unwrap().unwrap();
        let mut reply = modeled_receipt(&producer, &frame, RecordedCopy::NotRecorded);
        if wrong_challenge {
            reply.challenge[0] ^= 1;
        } else {
            reply.dropped_bytes = Some(4);
        }
        assert_eq!(producer.confirm(reply), Err(Refusal::Receipt));
        assert_eq!(producer.owner_dropped, Count::default());
        assert_eq!(
            producer.unconfirmed,
            Count {
                frames: 1,
                bytes: 3
            }
        );
        assert!(producer.partition_valid());
    }
}

#[test]
fn checked_partition_overflow_or_conflicting_totals_never_confirm_completion() {
    for count in [
        Count {
            frames: u64::MAX,
            bytes: 0,
        },
        Count {
            frames: 0,
            bytes: u64::MAX,
        },
    ] {
        assert_eq!(
            count.plus(Count {
                frames: 1,
                bytes: 1
            }),
            Err(Refusal::Overflow)
        );
        let mut producer = producer();
        producer.offered = count;
        assert_eq!(
            producer.offer(StreamKind::Stdout, b"x"),
            Err(Refusal::Overflow)
        );
        assert!(producer.accounting_invalid);
        assert_eq!(producer.phase, ProducerPhase::Aborted);
        assert!(!producer.complete());
    }
    let (mut producer, reply) = mixed_final();
    producer.offered.bytes += 1;
    assert_eq!(producer.confirm_final(&reply), Err(Refusal::Receipt));
    assert!(!producer.complete());
}
