use mvm_core::protocol::telemetry::*;
use mvm_core::trace_context::{SpanId, TraceContext, TraceId};

fn record(body: RecordBody) -> TelemetryRecord {
    TelemetryRecord::builder()
        .epoch(ProducerEpoch::new([1; 16]).unwrap())
        .producer(7)
        .sequence(1)
        .monotonic_ns(42)
        .source(SourceKind::GuestAgent)
        .body(body)
        .build()
        .unwrap()
}

fn context() -> TraceReference {
    TraceReference::new(TraceContext::new(TraceId([2; 16]), SpanId([3; 8]))).unwrap()
}

#[test]
fn every_record_family_roundtrips_without_fabricating_a_span() {
    let bodies = [
        RecordBody::SpanOpen {
            context: context(),
            parent: Some(context()),
            name: "work".try_into().unwrap(),
            attributes: BoundedList::default(),
            links: BoundedList::new(vec![context()]).unwrap(),
        },
        RecordBody::SpanUpdate {
            context: context(),
            attributes: BoundedList::default(),
        },
        RecordBody::SpanClose {
            context: context(),
            outcome: SpanOutcome::Error,
        },
        RecordBody::Event {
            context: None,
            level: Level::Info,
            name: "ready".try_into().unwrap(),
            attributes: BoundedList::new(vec![
                Attribute {
                    key: "bool".try_into().unwrap(),
                    value: AttributeValue::Bool(true),
                },
                Attribute {
                    key: "signed".try_into().unwrap(),
                    value: AttributeValue::Signed(-2),
                },
                Attribute {
                    key: "unsigned".try_into().unwrap(),
                    value: AttributeValue::Unsigned(42),
                },
                Attribute {
                    key: "float".try_into().unwrap(),
                    value: AttributeValue::float(1.5).unwrap(),
                },
                Attribute {
                    key: "text".try_into().unwrap(),
                    value: AttributeValue::Text("field".try_into().unwrap()),
                },
            ])
            .unwrap(),
        },
        RecordBody::Log {
            context: Some(context()),
            level: Level::Warn,
            message: "diagnostic".try_into().unwrap(),
            attributes: BoundedList::default(),
        },
        RecordBody::Stdio {
            stream: StdioStream::Stderr,
            bytes: BoundedList::new(vec![0, 255, 10]).unwrap(),
        },
        RecordBody::Coverage {
            state: CoverageState::Started,
            code: "agent".try_into().unwrap(),
        },
        RecordBody::Loss {
            stage: GuestLossStage::Capture,
            reason: LossReason::Capacity,
            records: 10,
            bytes: 200,
            tail: TailState::Known,
        },
    ];
    let fixtures = [
        include_str!("fixtures/telemetry-v1/span-open.json"),
        include_str!("fixtures/telemetry-v1/span-update.json"),
        include_str!("fixtures/telemetry-v1/span-close.json"),
        include_str!("fixtures/telemetry-v1/event.json"),
        include_str!("fixtures/telemetry-v1/log.json"),
        include_str!("fixtures/telemetry-v1/stdio.json"),
        include_str!("fixtures/telemetry-v1/coverage.json"),
        include_str!("fixtures/telemetry-v1/loss.json"),
    ];
    for (body, fixture) in bodies.into_iter().zip(fixtures) {
        let expected = record(body);
        let encoded = expected.encode().unwrap();
        assert_eq!(encoded, fixture.trim_end().as_bytes());
        assert_eq!(TelemetryRecord::decode(&encoded).unwrap(), expected);
    }
}

#[test]
fn version_unknown_fields_and_guest_authored_host_identity_are_rejected() {
    let original = serde_json::to_value(record(RecordBody::Coverage {
        state: CoverageState::Started,
        code: "agent".try_into().unwrap(),
    }))
    .unwrap();
    for field in [
        "vm_id",
        "tenant_id",
        "boot_id",
        "generation",
        "host_timestamp",
    ] {
        let mut forged = original.clone();
        forged[field] = "secret-sentinel".into();
        let error = TelemetryRecord::decode(&serde_json::to_vec(&forged).unwrap()).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("secret-sentinel"));
    }
    let mut future = original;
    future["format"] = "mvm.telemetry.v99".into();
    assert!(TelemetryRecord::decode(&serde_json::to_vec(&future).unwrap()).is_err());
}

#[test]
fn bounded_values_refuse_excess_and_invalid_ids() {
    assert!(Text::<8>::new("123456789").is_err());
    assert!(Text::<8>::new("éééé").is_ok());
    assert!(BoundedList::<u8, 2>::new(vec![1, 2, 3]).is_err());
    assert!(serde_json::from_str::<BoundedList<u8, 2>>("[1,2,3]").is_err());
    assert!(serde_json::from_str::<Text<2>>(r#""long""#).is_err());
    assert!(ProducerEpoch::new([0; 16]).is_err());
    assert!(TraceReference::new(TraceContext::new(TraceId([0; 16]), SpanId([1; 8]))).is_err());
    assert!(TelemetryRecord::builder().build().is_err());
    assert!(TelemetryRecord::decode(&vec![b' '; MAX_RECORD_BYTES + 1]).is_err());
}

#[test]
fn primitive_attributes_keep_their_types_and_reject_nonfinite_numbers() {
    let values = [
        AttributeValue::Bool(true),
        AttributeValue::Signed(-2),
        AttributeValue::Unsigned(u64::MAX),
        AttributeValue::Text("value".try_into().unwrap()),
        AttributeValue::float(1.5).unwrap(),
    ];
    for value in values {
        let encoded = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            serde_json::from_slice::<AttributeValue>(&encoded).unwrap(),
            value
        );
    }
    assert!(AttributeValue::float(f64::NAN).is_err());
    assert!(AttributeValue::float(f64::INFINITY).is_err());
}

#[test]
fn wire_encoding_is_pinned_and_metadata_accessors_agree() {
    let record = record(RecordBody::Coverage {
        state: CoverageState::Started,
        code: "agent".try_into().unwrap(),
    });
    let encoded = String::from_utf8(record.encode().unwrap()).unwrap();
    assert_eq!(
        encoded,
        include_str!("fixtures/telemetry-v1/coverage.json").trim_end()
    );
    assert_eq!(record.epoch(), ProducerEpoch::new([1; 16]).unwrap());
    assert_eq!(record.producer(), 7);
    assert_eq!(record.sequence(), 1);
    assert_eq!(record.monotonic_ns(), 42);
    assert_eq!(record.source(), SourceKind::GuestAgent);
    assert!(matches!(record.body(), RecordBody::Coverage { .. }));
    assert_eq!(context().context().trace_id, TraceId([2; 16]));
}

#[test]
fn nested_unknown_data_and_total_encoded_bytes_have_independent_caps() {
    let deep = format!(
        "{}0{}",
        "[".repeat(MAX_RECORD_DEPTH + 1),
        "]".repeat(MAX_RECORD_DEPTH + 1)
    );
    assert_eq!(
        TelemetryRecord::decode(deep.as_bytes()),
        Err(RecordError::Capacity)
    );
    for malformed in ["}", "{", "\"\\", "{\"x\":1} trailing"] {
        assert!(TelemetryRecord::decode(malformed.as_bytes()).is_err());
    }
    // Quoted braces/escaped quotes are content, not JSON nesting.
    let message = "[[[[[[[[[[[[[\\\"{{{{{{{{{{{{";
    let rec = record(RecordBody::Log {
        context: None,
        level: Level::Info,
        message: message.try_into().unwrap(),
        attributes: BoundedList::default(),
    });
    assert_eq!(
        TelemetryRecord::decode(&rec.encode().unwrap()).unwrap(),
        rec
    );
    let attributes = (0..MAX_ATTRIBUTES)
        .map(|_| Attribute {
            key: "key".try_into().unwrap(),
            value: AttributeValue::Text(Text::new(&"\0".repeat(2048)).unwrap()),
        })
        .collect();
    let too_big = record(RecordBody::Event {
        context: None,
        level: Level::Info,
        name: "large".try_into().unwrap(),
        attributes: BoundedList::new(attributes).unwrap(),
    });
    assert_eq!(too_big.encode(), Err(RecordError::Capacity));
}

#[test]
fn invalid_nested_fields_ids_and_forged_loss_stages_are_rejected() {
    let original = serde_json::to_value(record(RecordBody::SpanOpen {
        context: context(),
        parent: None,
        name: "work".try_into().unwrap(),
        attributes: BoundedList::default(),
        links: BoundedList::default(),
    }))
    .unwrap();
    for (path, invalid) in [
        (
            "/body/context",
            serde_json::json!("00-00000000000000000000000000000000-0101010101010101-01"),
        ),
        (
            "/body/context",
            serde_json::json!("00-02020202020202020202020202020202-0303030303030303-zz"),
        ),
        ("/producer", serde_json::json!(0)),
        ("/sequence", serde_json::json!(0)),
        (
            "/epoch",
            serde_json::json!([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ),
        ("/body/kind", serde_json::json!("host_system_event")),
    ] {
        let mut value = original.clone();
        *value.pointer_mut(path).unwrap() = invalid;
        assert!(
            TelemetryRecord::decode(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{path}"
        );
    }
    let mut value = original;
    value["body"]["unknown"] = true.into();
    assert!(TelemetryRecord::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut loss = serde_json::to_value(record(RecordBody::Loss {
        stage: GuestLossStage::Capture,
        reason: LossReason::Capacity,
        records: 1,
        bytes: 1,
        tail: TailState::Unknown,
    }))
    .unwrap();
    loss["body"]["stage"] = "host_retention".into();
    assert!(TelemetryRecord::decode(&serde_json::to_vec(&loss).unwrap()).is_err());
}

#[test]
fn debug_output_does_not_quote_text_or_stdio() {
    let rec = record(RecordBody::Log {
        context: None,
        level: Level::Info,
        message: "secret-sentinel".try_into().unwrap(),
        attributes: BoundedList::default(),
    });
    assert!(!format!("{rec:?}").contains("secret-sentinel"));
    assert_eq!(
        BoundedList::<u8, 4>::new(vec![1, 2]).unwrap().as_slice(),
        &[1, 2]
    );
}
