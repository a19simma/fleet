//! Bearer token check for the gRPC services.

use std::sync::Arc;

use fleet_core::constant_time_eq;
use tonic::service::Interceptor;
use tonic::{Request, Status};

use crate::config::Token;

/// A tonic interceptor that requires `authorization: Bearer <token>`.
///
/// The whole header value is compared with [`constant_time_eq`], so a wrong scheme, a
/// wrong token and a header with non-ASCII bytes all fail the same way.
#[derive(Clone)]
pub struct BearerAuth {
    expected: Arc<[u8]>,
}

impl BearerAuth {
    /// Builds a check for `token`.
    pub fn new(token: &Token) -> Self {
        let expected = format!("Bearer {}", token.expose());
        Self {
            expected: Arc::from(expected.into_bytes()),
        }
    }
}

impl std::fmt::Debug for BearerAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerAuth(<redacted>)")
    }
}

impl Interceptor for BearerAuth {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let given = request
            .metadata()
            .get("authorization")
            .map_or(&[][..], |value| value.as_bytes());
        if constant_time_eq(given, &self.expected) {
            Ok(request)
        } else {
            Err(Status::unauthenticated("missing or invalid bearer token"))
        }
    }
}

#[cfg(test)]
mod tests {
    use tonic::Code;
    use tonic::codegen::http::HeaderValue;
    use tonic::metadata::MetadataMap;

    use super::*;

    fn auth() -> BearerAuth {
        BearerAuth::new(&Token::new("secret".into()).unwrap())
    }

    fn request_with(value: Option<&[u8]>) -> Request<()> {
        let mut request = Request::new(());
        if let Some(bytes) = value {
            let mut headers = tonic::codegen::http::HeaderMap::new();
            headers.insert("authorization", HeaderValue::from_bytes(bytes).unwrap());
            *request.metadata_mut() = MetadataMap::from_headers(headers);
        }
        request
    }

    #[test]
    fn right_token_passes() {
        assert!(auth().call(request_with(Some(b"Bearer secret"))).is_ok());
    }

    #[test]
    fn missing_wrong_and_malformed_fail() {
        let cases: [Option<&[u8]>; 6] = [
            None,
            Some(b"Bearer wrong"),
            Some(b"secret"),
            Some(b"bearer secret"),
            Some(b"Bearer secret "),
            Some("Bearer s\u{e9}cret".as_bytes()),
        ];
        for case in cases {
            let err = auth().call(request_with(case)).unwrap_err();
            assert_eq!(err.code(), Code::Unauthenticated, "{case:?}");
        }
    }

    #[test]
    fn raw_non_ascii_bytes_fail() {
        let err = auth()
            .call(request_with(Some(b"Bearer \xff\xfe")))
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
    }
}
