use std::{any::Any, convert::Infallible, net::IpAddr, sync::Arc};

use h3x::{connection::ConnectionState, dhttp::message::MessageStreamError, quic};
use http_body_util::{Full, combinators::UnsyncBoxBody};
use tracing::debug;

use super::query::{LookupResult, perform_lookup};
use crate::{
    error::{AppError, parse_query_params},
    storage::AppState,
};

pub type Request = http::Request<UnsyncBoxBody<bytes::Bytes, MessageStreamError>>;
pub type Response = http::Response<Full<bytes::Bytes>>;

fn request_source_ip(request: &Request) -> Option<IpAddr> {
    let connection = request
        .extensions()
        .get::<Arc<ConnectionState<dyn quic::DynConnection>>>()?
        .clone();
    let quic = connection.quic();
    let dquic = (quic.as_ref() as &dyn Any).downcast_ref::<dquic::prelude::Connection>()?;
    let ctx = dquic.path_context().ok()?;

    ctx.paths::<Vec<_>>()
        .into_iter()
        .next()
        .map(|(pathway, _)| pathway.remote().addr().ip())
}
pub fn body_response(status: http::StatusCode, body: impl Into<bytes::Bytes>) -> Response {
    http::Response::builder()
        .status(status)
        .body(Full::new(body.into()))
        .expect("response parts must be valid")
}

pub fn write_error(err: AppError) -> Response {
    debug!(
        status = %err.status(),
        error = %err,
        "writing error response"
    );
    body_response(err.status(), bytes::Bytes::from(err.to_string()))
}

// ---------------------------------------------------------------------------
// LookupSvc
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct LookupSvc {
    pub state: AppState,
}

/// Handle a lookup request.
///
/// Always returns multi-record binary body:
/// `[u32 count BE]([u32 dns_len BE][dns][u32 cert_len BE][cert])*`
/// with header `x-record-format: multi`.
///
/// Optional query param `limit=N` caps the number of records returned.
/// Dynamic records are newest-first; configured seed records are appended after them.
pub async fn lookup_with_cert(state: AppState, request: Request) -> Response {
    let params = parse_query_params(request.uri());
    let Some(host) = params.get("host") else {
        return write_error(AppError::MissingHostParam);
    };
    let source_ip = request_source_ip(&request);

    let limit: Option<usize> = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0);

    debug!(host = %host, limit, ?source_ip, "lookup.request");

    match perform_lookup(&state, host, limit, source_ip).await {
        Ok(LookupResult::NotFound) => {
            debug!(host = %host, "lookup.not_found");
            body_response(
                http::StatusCode::NOT_FOUND,
                bytes::Bytes::from_static(b"Not Found"),
            )
        }

        Ok(LookupResult::Multi(resp)) => {
            let body = resp.encode();
            debug!(host = %host, records = resp.records.len(), "lookup.found");
            let mut response = body_response(http::StatusCode::OK, bytes::Bytes::from(body));
            response.headers_mut().insert(
                http::HeaderName::from_static("x-record-format"),
                http::HeaderValue::from_static("multi"),
            );
            response
        }

        Err(e) => write_error(e),
    }
}

impl LookupSvc {
    pub fn call(
        &self,
        request: Request,
    ) -> impl Future<Output = Result<Response, Infallible>> + Send + 'static {
        let state = self.state.clone();
        async move { Ok(lookup_with_cert(state, request).await) }
    }
}
