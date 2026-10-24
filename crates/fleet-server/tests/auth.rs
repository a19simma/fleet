//! Runs the gRPC services in process on a loopback port. The pool is lazy and points at
//! a closed port, so these tests need no Postgres: every call they make is refused or
//! rejected before storage, or fails as `Unavailable` when it reaches it.

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use fleet_proto::v1::fleet_ingest_client::FleetIngestClient;
    use fleet_proto::v1::fleet_query_client::FleetQueryClient;
    use fleet_proto::v1::{
        Envelope, HeartbeatRequest, ListFleetRequest, PushEventsRequest, QueuedEvent,
    };
    use fleet_server::auth::BearerAuth;
    use fleet_server::config::Token;
    use fleet_server::service::router;
    use fleet_server::store::Store;
    use sqlx::postgres::PgPoolOptions;
    use tonic::codegen::http::{HeaderMap, HeaderValue};
    use tonic::metadata::MetadataMap;
    use tonic::service::Interceptor;
    use tonic::service::interceptor::InterceptedService;
    use tonic::transport::server::TcpIncoming;
    use tonic::transport::{Channel, Endpoint};
    use tonic::{Code, Request, Status};

    const TOKEN: &str = "test-token-0123456789abcdef0123456789";

    fn box_name(n: u32) -> String {
        format!("box-{n}")
    }

    fn spawn() -> SocketAddr {
        let pool = PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(300))
            .connect_lazy("postgres://postgres@127.0.0.1:1/none")
            .unwrap();
        let store = Store::new(pool);
        let auth = BearerAuth::new(&Token::new(TOKEN.to_owned()).unwrap());
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = incoming.local_addr().unwrap();
        tokio::spawn(router(&store, &auth).serve_with_incoming(incoming));
        addr
    }

    fn channel(addr: SocketAddr) -> Channel {
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect_lazy()
    }

    impl Interceptor for Header {
        fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
            self.apply(request)
        }
    }

    #[derive(Clone)]
    struct Header(Option<Vec<u8>>);

    impl Header {
        fn right() -> Self {
            Self(Some(format!("Bearer {TOKEN}").into_bytes()))
        }

        fn apply(&self, mut request: Request<()>) -> Result<Request<()>, Status> {
            if let Some(bytes) = &self.0 {
                let mut headers = HeaderMap::new();
                let value = HeaderValue::from_bytes(bytes)
                    .map_err(|err| Status::internal(err.to_string()))?;
                headers.insert("authorization", value);
                *request.metadata_mut() = MetadataMap::from_headers(headers);
            }
            Ok(request)
        }
    }

    fn bad_headers() -> Vec<Header> {
        vec![
            Header(None),
            Header(Some(b"Bearer wrong".to_vec())),
            Header(Some(TOKEN.as_bytes().to_vec())),
            Header(Some(
                "Bearer t\u{e9}st-token-0123456789abcdef0123456789"
                    .as_bytes()
                    .to_vec(),
            )),
            Header(Some(b"Bearer \xff\xfe".to_vec())),
        ]
    }

    type IngestClient = FleetIngestClient<InterceptedService<Channel, Header>>;

    fn ingest(addr: SocketAddr, header: Header) -> IngestClient {
        FleetIngestClient::with_interceptor(channel(addr), header)
    }

    fn heartbeat(name: &str) -> HeartbeatRequest {
        HeartbeatRequest {
            r#box: name.to_owned(),
            ..HeartbeatRequest::default()
        }
    }

    fn wire_event(seq: u64, name: &str, payload_json: &str) -> QueuedEvent {
        QueuedEvent {
            seq,
            envelope: Some(Envelope {
                id: "00000000000000000000000001".into(),
                schema_version: 1,
                r#box: name.to_owned(),
                hostname: "h".into(),
                machine_id: "m".into(),
                boot_id: "b".into(),
                source: "hook".into(),
                kind: "hook.stop".into(),
                ts_ms: 1,
                payload_json: payload_json.to_owned(),
                ..Envelope::default()
            }),
        }
    }

    fn push(events: Vec<QueuedEvent>) -> PushEventsRequest {
        PushEventsRequest { events }
    }

    #[tokio::test]
    async fn bad_tokens_are_unauthenticated_on_every_rpc() {
        let addr = spawn();
        for header in bad_headers() {
            let shown = format!("{:?}", header.0);
            let mut client = ingest(addr, header.clone());
            let err = client.push_events(push(Vec::new())).await.unwrap_err();
            assert_eq!(err.code(), Code::Unauthenticated, "push {shown:?}");
            let err = client.heartbeat(heartbeat(&box_name(1))).await.unwrap_err();
            assert_eq!(
                err.code(),
                Code::Unauthenticated,
                "heartbeat {:?}",
                header.0
            );

            let mut query = FleetQueryClient::with_interceptor(channel(addr), move |request| {
                header.apply(request)
            });
            let err = query
                .list_fleet(ListFleetRequest::default())
                .await
                .unwrap_err();
            assert_eq!(err.code(), Code::Unauthenticated, "list {shown:?}");
        }
    }

    #[tokio::test]
    async fn right_token_passes_the_interceptor() {
        let addr = spawn();
        let mut client = ingest(addr, Header::right());
        let reply = client
            .push_events(push(Vec::new()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reply.acked_through_seq, 0);

        let mut query = FleetQueryClient::with_interceptor(channel(addr), |request| {
            Header::right().apply(request)
        });
        let err = query
            .list_fleet(ListFleetRequest::default())
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unavailable);
    }

    #[tokio::test]
    async fn invalid_box_name_is_invalid_argument() {
        let addr = spawn();
        let mut client = ingest(addr, Header::right());
        let err = client.heartbeat(heartbeat("alpha")).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        let err = client
            .push_events(push(vec![wire_event(1, "alpha", "{}")]))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    async fn call_unknown_path(addr: SocketAddr, header: Header) -> Result<(), Status> {
        let mut grpc = tonic::client::Grpc::new(channel(addr));
        grpc.ready()
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        let meta = header.apply(Request::new(()))?;
        let mut request = Request::new(push(Vec::new()));
        *request.metadata_mut() = meta.metadata().clone();
        let path = tonic::codegen::http::uri::PathAndQuery::from_static("/other.v1.Other/Nope");
        let codec = tonic_prost::ProstCodec::<PushEventsRequest, PushEventsRequest>::default();
        grpc.unary(request, path, codec).await.map(|_| ())
    }

    #[tokio::test]
    async fn the_layer_covers_paths_no_service_serves() {
        let addr = spawn();
        for header in bad_headers() {
            let shown = format!("{:?}", header.0);
            let err = call_unknown_path(addr, header).await.unwrap_err();
            assert_eq!(err.code(), Code::Unauthenticated, "{shown}");
        }
        let err = call_unknown_path(addr, Header::right()).await.unwrap_err();
        assert_eq!(err.code(), Code::Unimplemented);
    }

    #[tokio::test]
    async fn invalid_box_error_does_not_echo_the_raw_name() {
        let addr = spawn();
        let mut client = ingest(addr, Header::right());
        let err = client
            .push_events(push(vec![wire_event(1, "raw-secret-name", "{}")]))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(
            !err.message().contains("raw-secret-name"),
            "{}",
            err.message()
        );
    }

    #[tokio::test]
    async fn mixed_boxes_in_one_request_are_invalid_argument() {
        let addr = spawn();
        let mut client = ingest(addr, Header::right());
        let events = vec![
            wire_event(1, &box_name(1), "{}"),
            wire_event(2, &box_name(2), "{}"),
        ];
        let err = client.push_events(push(events)).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn more_than_the_event_cap_is_invalid_argument() {
        let addr = spawn();
        let mut client = ingest(addr, Header::right());
        let name = box_name(1);
        let at_cap: Vec<QueuedEvent> = (1..=500).map(|seq| wire_event(seq, &name, "{")).collect();
        let reply = client.push_events(push(at_cap)).await.unwrap().into_inner();
        assert_eq!(reply.rejected.len(), 500);

        let over: Vec<QueuedEvent> = (1..=501).map(|seq| wire_event(seq, &name, "{")).collect();
        let err = client.push_events(push(over)).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn oversize_payload_is_rejected_and_acked() {
        let addr = spawn();
        let mut client = ingest(addr, Header::right());
        let big = format!("\"{}\"", "a".repeat(256 * 1024));
        let events = vec![wire_event(4, &box_name(1), &big)];
        let reply = client.push_events(push(events)).await.unwrap().into_inner();
        assert_eq!(reply.acked_through_seq, 4);
        let seqs: Vec<u64> = reply.rejected.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![4]);
    }

    #[tokio::test]
    async fn unsupported_schema_version_is_not_acked() {
        let addr = spawn();
        let mut client = ingest(addr, Header::right());
        let mut first = wire_event(5, &box_name(1), "{}");
        let mut second = wire_event(6, &box_name(1), "{}");
        for event in [&mut first, &mut second] {
            if let Some(envelope) = event.envelope.as_mut() {
                envelope.schema_version = 2;
            }
        }
        let reply = client
            .push_events(push(vec![first, second]))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(reply.acked_through_seq, 4);
        assert_eq!(reply.stored, 0);
        let seqs: Vec<u64> = reply.rejected.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![5, 6]);
        assert!(
            reply.rejected[0]
                .reason
                .starts_with("unsupported schema_version")
        );
    }

    #[tokio::test]
    async fn nul_in_heartbeat_identity_is_invalid_argument() {
        let addr = spawn();
        let mut client = ingest(addr, Header::right());
        for field in 0..4 {
            let mut request = heartbeat(&box_name(1));
            match field {
                0 => request.hostname = "a\0b".into(),
                1 => request.machine_id = "a\0b".into(),
                2 => request.boot_id = "a\0b".into(),
                _ => request.fleetd_version = "a\0b".into(),
            }
            let err = client.heartbeat(request).await.unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument, "field {field}");
        }
    }

    #[tokio::test]
    async fn unparseable_payload_is_rejected_and_acked() {
        let addr = spawn();
        let mut client = ingest(addr, Header::right());
        let events = vec![
            wire_event(7, &box_name(1), "{"),
            wire_event(9, &box_name(1), "not json"),
        ];
        let reply = client.push_events(push(events)).await.unwrap().into_inner();
        assert_eq!(reply.acked_through_seq, 9);
        assert_eq!((reply.stored, reply.duplicate), (0, 0));
        let seqs: Vec<u64> = reply.rejected.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![7, 9]);
    }
}
