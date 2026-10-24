use std::fmt;

use fleet_core::{Envelope, EventId, Source};
use serde_json::Value;

use crate::v1;

/// Why a wire envelope could not become a [`fleet_core::Envelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConvertError {
    /// The `id` field is not a valid event id.
    InvalidId(String),
    /// The `source` field names no known source.
    InvalidSource(String),
    /// The `payload_json` field is not valid JSON.
    InvalidPayload(String),
}

impl fmt::Display for ConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId(raw) => write!(f, "invalid event id: {raw:?}"),
            Self::InvalidSource(raw) => write!(f, "unknown source: {raw:?}"),
            Self::InvalidPayload(why) => write!(f, "payload is not valid JSON: {why}"),
        }
    }
}

impl std::error::Error for ConvertError {}

impl From<&Envelope> for v1::Envelope {
    fn from(env: &Envelope) -> Self {
        Self {
            id: env.id.to_string(),
            schema_version: env.schema_version,
            r#box: env.box_name.clone(),
            hostname: env.hostname.clone(),
            machine_id: env.machine_id.clone(),
            boot_id: env.boot_id.clone(),
            source: env.source.as_str().to_owned(),
            kind: env.kind.clone(),
            ts_ms: env.ts,
            session_id: env.session_id.clone(),
            prompt_id: env.prompt_id.clone(),
            workdir: env.workdir.clone(),
            occurred_at_ms: env.occurred_at,
            payload_json: env.payload.to_string(),
        }
    }
}

impl TryFrom<v1::Envelope> for Envelope {
    type Error = ConvertError;

    fn try_from(wire: v1::Envelope) -> Result<Self, Self::Error> {
        let id = wire
            .id
            .parse::<EventId>()
            .map_err(|_| ConvertError::InvalidId(wire.id.clone()))?;
        let source = wire
            .source
            .parse::<Source>()
            .map_err(|_| ConvertError::InvalidSource(wire.source.clone()))?;
        let payload = serde_json::from_str::<Value>(&wire.payload_json)
            .map_err(|err| ConvertError::InvalidPayload(err.to_string()))?;
        Ok(Self {
            id,
            schema_version: wire.schema_version,
            box_name: wire.r#box,
            hostname: wire.hostname,
            machine_id: wire.machine_id,
            boot_id: wire.boot_id,
            source,
            kind: wire.kind,
            ts: wire.ts_ms,
            session_id: wire.session_id,
            prompt_id: wire.prompt_id,
            workdir: wire.workdir,
            occurred_at: wire.occurred_at_ms,
            payload,
        })
    }
}

/// Wraps an envelope and its queue sequence number as a wire [`v1::QueuedEvent`].
pub fn queued_event(seq: u64, envelope: &Envelope) -> v1::QueuedEvent {
    v1::QueuedEvent {
        seq,
        envelope: Some(envelope.into()),
    }
}

#[cfg(test)]
mod tests {
    use fleet_core::Identity;

    use super::*;

    fn box_name() -> String {
        format!("box-{}", 7)
    }

    fn sample() -> Envelope {
        let identity = Identity {
            box_name: box_name(),
            hostname: "h".into(),
            machine_id: "m".into(),
            boot_id: "b".into(),
        };
        let mut env = Envelope::new(
            &identity,
            EventId::derive("k", &["a"]),
            Source::Hook,
            "hook.stop",
            42,
        );
        env.payload = serde_json::json!({"last_assistant_message": "ok", "n": [1, 2]});
        env
    }

    #[test]
    fn roundtrip_with_every_optional_set() {
        let mut env = sample();
        env.session_id = Some("s".into());
        env.prompt_id = Some("p".into());
        env.workdir = Some("/w".into());
        env.occurred_at = Some(40);
        let wire = v1::Envelope::from(&env);
        assert_eq!(wire.occurred_at_ms, Some(40));
        assert_eq!(Envelope::try_from(wire).unwrap(), env);
    }

    #[test]
    fn roundtrip_with_no_optionals() {
        let env = sample();
        let wire = v1::Envelope::from(&env);
        assert_eq!(wire.session_id, None);
        assert_eq!(wire.workdir, None);
        assert_eq!(Envelope::try_from(wire).unwrap(), env);
    }

    #[test]
    fn empty_string_optional_stays_distinct_from_none() {
        let mut env = sample();
        env.session_id = Some(String::new());
        env.workdir = None;
        let wire = v1::Envelope::from(&env);
        assert_eq!(wire.session_id, Some(String::new()));
        let back = Envelope::try_from(wire).unwrap();
        assert_eq!(back.session_id, Some(String::new()));
        assert_eq!(back.workdir, None);
    }

    #[test]
    fn optionals_survive_protobuf_encoding() {
        use prost::Message;

        let mut env = sample();
        env.session_id = Some(String::new());
        let bytes = v1::Envelope::from(&env).encode_to_vec();
        let wire = v1::Envelope::decode(bytes.as_slice()).unwrap();
        assert_eq!(wire.session_id, Some(String::new()));
        assert_eq!(wire.prompt_id, None);
    }

    #[test]
    fn rejects_bad_fields() {
        let good = v1::Envelope::from(&sample());

        let mut wire = good.clone();
        wire.id = "nope".into();
        assert_eq!(
            Envelope::try_from(wire),
            Err(ConvertError::InvalidId("nope".into()))
        );

        let mut wire = good.clone();
        wire.source = "other".into();
        assert_eq!(
            Envelope::try_from(wire),
            Err(ConvertError::InvalidSource("other".into()))
        );

        let mut wire = good;
        wire.payload_json = "{".into();
        assert!(matches!(
            Envelope::try_from(wire),
            Err(ConvertError::InvalidPayload(_))
        ));
    }

    #[test]
    fn queued_event_carries_seq_and_envelope() {
        let env = sample();
        let queued = queued_event(9, &env);
        assert_eq!(queued.seq, 9);
        assert_eq!(queued.envelope, Some(v1::Envelope::from(&env)));
    }
}
