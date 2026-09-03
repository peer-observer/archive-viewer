//! Generic JSON rendering of a single event, via protobuf reflection.
//!
//! Hand-writing a renderer for the ~60 message types in the schema would be a
//! lot of code that goes stale the moment upstream adds a message. Instead the
//! event's retained bytes are decoded against the embedded descriptor set, so
//! field names come from the schema itself and new message types appear without
//! any change here.
//!
//! Bytes fields render as hex rather than protobuf-JSON's base64: these are
//! txids, block hashes and raw transactions, and base64 is unreadable for those.

use crate::analysis::Analysis;
use crate::proto::FILE_DESCRIPTOR_SET;
use crate::view::{number, signed_number};
use prost_reflect::{DescriptorPool, DynamicMessage, Kind, MapKey, MessageDescriptor, Value as Pb};
use serde_json::{json, Map, Value};

/// Fully-qualified name of the archived top-level message.
const EVENT_MESSAGE: &str = "event.Event";

/// The schema, decoded once and reused.
pub struct Schema {
    event: MessageDescriptor,
}

impl Schema {
    pub fn new() -> Result<Self, String> {
        let pool = DescriptorPool::decode(FILE_DESCRIPTOR_SET)
            .map_err(|e| format!("could not read the embedded descriptor set: {e}"))?;
        let event = pool
            .get_message_by_name(EVENT_MESSAGE)
            .ok_or_else(|| format!("{EVENT_MESSAGE} is missing from the descriptor set"))?;
        Ok(Schema { event })
    }

    /// Decode one event's bytes into a JSON tree.
    pub fn event_to_json(&self, bytes: &[u8]) -> Result<Value, String> {
        let message = DynamicMessage::decode(self.event.clone(), bytes)
            .map_err(|e| format!("could not decode the event: {e}"))?;
        Ok(message_to_json(&message))
    }
}

/// Render a retained event by its index in the store.
pub fn event_json(analysis: &Analysis, schema: &Schema, index: u32) -> Result<Value, String> {
    let bytes = analysis
        .store
        .bytes(index)
        .ok_or_else(|| format!("event {index} was not retained"))?;
    schema.event_to_json(bytes)
}

fn message_to_json(message: &DynamicMessage) -> Value {
    let mut object = Map::new();
    // `fields()` yields only the fields actually present, which is what we want:
    // an inspector should show what the event carries, not the whole schema.
    for (field, value) in message.fields() {
        object.insert(
            field.name().to_string(),
            value_to_json(value, &field.kind()),
        );
    }
    Value::Object(object)
}

fn value_to_json(value: &Pb, kind: &Kind) -> Value {
    match value {
        Pb::Bool(v) => json!(v),
        Pb::I32(v) => json!(v),
        Pb::I64(v) => signed_number(*v),
        Pb::U32(v) => json!(v),
        Pb::U64(v) => number(*v),
        Pb::F32(v) => json!(v),
        Pb::F64(v) => json!(v),
        Pb::String(v) => json!(v),
        Pb::Bytes(v) => json!(hex(v)),
        Pb::EnumNumber(n) => match kind {
            Kind::Enum(descriptor) => match descriptor.get_value(*n) {
                Some(variant) => json!(variant.name()),
                // A value this build's schema does not know, from a newer archive.
                None => json!(format!("({n})")),
            },
            _ => json!(n),
        },
        Pb::Message(message) => message_to_json(message),
        Pb::List(items) => {
            Value::Array(items.iter().map(|item| value_to_json(item, kind)).collect())
        }
        Pb::Map(entries) => {
            // The map's value kind lives on the synthetic entry message's field 2.
            let value_kind = match kind {
                Kind::Message(entry) => entry.map_entry_value_field().kind(),
                other => other.clone(),
            };
            let mut object = Map::new();
            for (key, item) in entries {
                object.insert(map_key_to_string(key), value_to_json(item, &value_kind));
            }
            Value::Object(object)
        }
    }
}

fn map_key_to_string(key: &MapKey) -> String {
    match key {
        MapKey::Bool(v) => v.to_string(),
        MapKey::I32(v) => v.to_string(),
        MapKey::I64(v) => v.to_string(),
        MapKey::U32(v) => v.to_string(),
        MapKey::U64(v) => v.to_string(),
        MapKey::String(v) => v.clone(),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{
        bitcoin_primitives::ConnType,
        ebpf_extractor::{
            self,
            message::{message_event::Msg, MessageEvent, Metadata, Unknown},
        },
        event::{event::PeerObserverEvent, Event},
    };
    use prost::Message;

    fn schema() -> Schema {
        Schema::new().expect("descriptor set loads")
    }

    fn encoded_event(msg: Msg, command: &str) -> Vec<u8> {
        Event {
            timestamp: 1_700_000_000_123,
            peer_observer_event: Some(PeerObserverEvent::EbpfExtractor(ebpf_extractor::Ebpf {
                ebpf_event: Some(ebpf_extractor::ebpf::EbpfEvent::Message(MessageEvent {
                    meta: Metadata {
                        peer_id: 42,
                        addr: "10.0.0.1:8333".to_string(),
                        conn_type: ConnType::BlockRelayOnly as i32,
                        command: command.to_string(),
                        inbound: true,
                        size: 99,
                    },
                    msg: Some(msg),
                })),
            })),
        }
        .encode_to_vec()
    }

    #[test]
    fn renders_field_names_and_nesting_from_the_schema() {
        let bytes = encoded_event(
            Msg::Unknown(Unknown {
                command: "weird".into(),
                payload: vec![0xDE, 0xAD],
            }),
            "weird",
        );
        let json = schema().event_to_json(&bytes).expect("renders");

        assert_eq!(json["timestamp"], json!(1_700_000_000_123u64));
        let meta = &json["ebpf_extractor"]["message"]["meta"];
        assert_eq!(meta["peer_id"], json!(42));
        assert_eq!(meta["addr"], json!("10.0.0.1:8333"));
        assert_eq!(meta["inbound"], json!(true));
    }

    /// Hashes and payloads must be readable, so bytes render as hex rather than
    /// protobuf-JSON's base64 or an array of numbers.
    #[test]
    fn bytes_fields_render_as_hex() {
        let bytes = encoded_event(
            Msg::Unknown(Unknown {
                command: "x".into(),
                payload: vec![0x00, 0xDE, 0xAD, 0xBE, 0xEF],
            }),
            "x",
        );
        let json = schema().event_to_json(&bytes).expect("renders");

        assert_eq!(
            json["ebpf_extractor"]["message"]["unknown"]["payload"],
            json!("00deadbeef")
        );
    }

    #[test]
    fn enums_render_by_name() {
        let bytes = encoded_event(Msg::Verack(true), "verack");
        let json = schema().event_to_json(&bytes).expect("renders");

        assert_eq!(
            json["ebpf_extractor"]["message"]["meta"]["conn_type"],
            json!("BlockRelayOnly")
        );
    }

    /// The oneof arm is rendered under its own field name, so the event type is
    /// visible in the output rather than having to be inferred.
    #[test]
    fn oneof_arms_appear_by_name() {
        let bytes = encoded_event(Msg::Verack(true), "verack");
        let json = schema().event_to_json(&bytes).expect("renders");

        assert!(json["ebpf_extractor"]["message"]["verack"].is_boolean());
        assert!(json["rpc_extractor"].is_null(), "unset arms are absent");
    }

    #[test]
    fn a_u64_beyond_javascript_precision_becomes_a_string() {
        use crate::proto::ebpf_extractor::message::Ping;
        let bytes = encoded_event(Msg::Ping(Ping { value: u64::MAX }), "ping");
        let json = schema().event_to_json(&bytes).expect("renders");

        assert_eq!(
            json["ebpf_extractor"]["message"]["ping"]["value"],
            json!(u64::MAX.to_string())
        );
    }

    #[test]
    fn undecodable_bytes_report_an_error() {
        assert!(schema().event_to_json(&[0x08]).is_err());
    }
}
