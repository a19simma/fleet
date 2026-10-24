//! Bearer token check for the gRPC services.

use fleet_core::constant_time_eq;
use tonic::service::Interceptor;
use tonic::{Request, Status};

use crate::config::{Secret, Token};

/// A tonic interceptor that requires `authorization: Bearer <token>`.
///
/// The whole header value is compared with [`constant_time_eq`], so a wrong scheme, a
/// wrong token and a header with non-ASCII bytes all fail the same way.
#[derive(Debug, Clone)]
pub struct BearerAuth {
    expected: Secret,
}

impl BearerAuth {
    /// Builds a check for `token`.
    pub fn new(token: &Token) -> Self {
        Self {
            expected: Secret::new(format!("Bearer {}", token.expose())),
        }
    }
}

impl Interceptor for BearerAuth {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let given = request
            .metadata()
            .get("authorization")
            .map_or(&[][..], |value| value.as_bytes());
        if constant_time_eq(given, self.expected.expose().as_bytes()) {
            Ok(request)
        } else {
            tracing::warn!(peer = ?request.remote_addr(), "rejected request with a bad bearer token");
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

    const SECRET: &str = "secret-0123456789abcdef0123456789";

    fn auth() -> BearerAuth {
        BearerAuth::new(&Token::new(SECRET.into()).unwrap())
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
        assert!(
            auth()
                .call(request_with(Some(format!("Bearer {SECRET}").as_bytes())))
                .is_ok()
        );
    }

    #[test]
    fn missing_wrong_and_malformed_fail() {
        let cases: [Option<Vec<u8>>; 6] = [
            None,
            Some(b"Bearer wrong".to_vec()),
            Some(SECRET.as_bytes().to_vec()),
            Some(format!("bearer {SECRET}").into_bytes()),
            Some(format!("Bearer {SECRET} ").into_bytes()),
            Some("Bearer s\u{e9}cret".as_bytes().to_vec()),
        ];
        for case in cases {
            let err = auth().call(request_with(case.as_deref())).unwrap_err();
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
