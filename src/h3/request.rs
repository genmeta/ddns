use std::convert::Infallible;

use h3x::{
    dhttp::message::{MessageStreamError, hyper::client::RequestError as HyperRequestError},
    quic,
};
use http_body_util::BodyExt;

use super::{Error, H3Resolver, LOOKUP_REQUEST_ATTEMPTS, LOOKUP_REQUEST_TIMEOUT};

impl<C> H3Resolver<C>
where
    C: quic::Connect + quic::WithLocalAuthority + Send + Sync + 'static,
    C::Error: Send + Sync + 'static,
    C::Connection: Send + 'static,
{
    pub(super) fn connect_error(
        &self,
        source: h3x::pool::ConnectError<C::Error>,
    ) -> Error<C::Error> {
        // H3 DNS resolvers keep a long-lived endpoint. A network transition may
        // leave the cached H3 connection with stale QUIC paths, so the next
        // attempt must establish a fresh connection instead of reusing it.
        self.endpoint.clear_pool();
        Error::Connect { source }
    }

    pub(super) fn request_error(&self, source: HyperRequestError<Infallible>) -> Error<C::Error> {
        self.endpoint.clear_pool();
        Error::H3Request { source }
    }

    pub(super) async fn execute_request(
        &self,
        request: http::Request<
            impl http_body::Body<Data = bytes::Bytes, Error = Infallible> + Send + 'static,
        >,
    ) -> Result<
        http::Response<impl http_body::Body<Data = bytes::Bytes, Error = MessageStreamError>>,
        Error<C::Error>,
    > {
        let authority = request
            .uri()
            .authority()
            .expect("h3 dns request URL must include an authority")
            .clone();
        tracing::trace!(%authority, "connecting h3 dns endpoint");
        let connection = match self.endpoint.connect(authority.clone()).await {
            Ok(connection) => {
                tracing::trace!(%authority, "connected h3 dns endpoint");
                connection
            }
            Err(source) => return Err(self.connect_error(source)),
        };

        let method = request.method().clone();
        let uri = request.uri().clone();
        tracing::trace!(%method, %uri, "executing h3 dns request");
        match connection.execute_hyper_request(request).await {
            Ok(response) => {
                tracing::trace!(
                    status = %response.status(),
                    "h3 dns request response received"
                );
                Ok(response)
            }
            Err(source) => Err(self.request_error(source)),
        }
    }

    pub(super) fn retryable_lookup_error(error: &Error<C::Error>) -> bool {
        matches!(
            error,
            Error::Connect { .. } | Error::H3Request { .. } | Error::H3Stream { .. }
        )
    }

    pub(super) async fn lookup_response(
        &self,
        uri: http::Uri,
    ) -> Result<bytes::Bytes, Error<C::Error>> {
        let request = http::Request::get(uri)
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .expect("h3 dns lookup request must be valid");
        let resp = self.execute_request(request).await?;

        tracing::trace!("received response with status {}", resp.status());
        match resp.status() {
            http::StatusCode::OK => {}
            http::StatusCode::NOT_FOUND => return Err(Error::NoRecordFound),
            status => return Err(Error::Status { status }),
        }

        match resp.into_body().collect().await {
            Ok(response) => Ok(response.to_bytes()),
            Err(source) => Err(Error::H3Stream { source }),
        }
    }

    pub(super) async fn lookup_response_with_retry(
        &self,
        uri: http::Uri,
    ) -> Result<bytes::Bytes, Error<C::Error>> {
        for attempt in 1..=LOOKUP_REQUEST_ATTEMPTS {
            match tokio::time::timeout(LOOKUP_REQUEST_TIMEOUT, self.lookup_response(uri.clone()))
                .await
            {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(error))
                    if Self::retryable_lookup_error(&error)
                        && attempt < LOOKUP_REQUEST_ATTEMPTS =>
                {
                    self.endpoint.clear_pool();
                    tracing::debug!(
                        attempt,
                        timeout_ms = LOOKUP_REQUEST_TIMEOUT.as_millis(),
                        "h3 dns lookup failed, retrying"
                    );
                }
                Ok(Err(error)) => return Err(error),
                Err(_elapsed) if attempt < LOOKUP_REQUEST_ATTEMPTS => {
                    self.endpoint.clear_pool();
                    tracing::debug!(
                        attempt,
                        timeout_ms = LOOKUP_REQUEST_TIMEOUT.as_millis(),
                        "h3 dns lookup timed out, retrying"
                    );
                }
                Err(_elapsed) => {
                    self.endpoint.clear_pool();
                    return Err(Error::RequestTimeout {
                        timeout: LOOKUP_REQUEST_TIMEOUT,
                    });
                }
            }
        }

        unreachable!("lookup retry loop returns on the final attempt")
    }
}
