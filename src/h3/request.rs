use std::convert::Infallible;

use h3x::{
    dhttp::message::{MessageStreamError, hyper::client::RequestError as HyperRequestError},
    quic,
};
use snafu::IntoError;

use super::{H3RequestError, H3Resolver, h3_request_error};

impl<C> H3Resolver<C>
where
    C: quic::Connect + quic::WithLocalAuthority + Send + Sync + 'static,
    C::Error: Send + Sync + 'static,
    C::Connection: Send + 'static,
{
    pub(super) fn connect_error(
        &self,
        source: h3x::pool::ConnectError<C::Error>,
    ) -> H3RequestError<C::Error> {
        // H3 DNS resolvers keep a long-lived endpoint. A network transition may
        // leave the cached H3 connection with stale QUIC paths, so the next
        // attempt must establish a fresh connection instead of reusing it.
        self.endpoint.clear_pool();
        h3_request_error::ConnectSnafu.into_error(source)
    }

    pub(super) fn request_error(
        &self,
        source: HyperRequestError<Infallible>,
    ) -> H3RequestError<C::Error> {
        self.endpoint.clear_pool();
        h3_request_error::RequestSnafu.into_error(source)
    }

    pub(super) async fn execute_request(
        &self,
        request: http::Request<
            impl http_body::Body<Data = bytes::Bytes, Error = Infallible> + Send + 'static,
        >,
    ) -> Result<
        http::Response<impl http_body::Body<Data = bytes::Bytes, Error = MessageStreamError>>,
        H3RequestError<C::Error>,
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
}
