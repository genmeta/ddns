use std::convert::Infallible;

use h3x::{
    dhttp::message::{MessageStreamError, hyper::client::RequestError as HyperRequestError},
    quic,
};
use snafu::IntoError;

use super::{H3RequestError, H3Resolver, h3_request_error};

fn request_authority(uri: &http::Uri) -> http::uri::Authority {
    let authority = uri
        .authority()
        .expect("h3 dns request URL must include an authority");
    if authority.port_u16().is_some() {
        return authority.clone();
    }

    let default_port = match uri.scheme_str() {
        Some("http") => Some(80),
        Some("https") => Some(443),
        _ => None,
    };
    match default_port {
        Some(port) => format!("{authority}:{port}")
            .parse()
            .expect("a valid authority with a default port remains valid"),
        None => authority.clone(),
    }
}

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
        let authority = request_authority(request.uri());
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

#[cfg(test)]
mod tests {
    use super::request_authority;

    #[test]
    fn request_authority_applies_http_and_https_default_ports() {
        let http: http::Uri = "http://dns.example.test/api".parse().unwrap();
        let https: http::Uri = "https://dns.example.test/api".parse().unwrap();

        assert_eq!(request_authority(&http).as_str(), "dns.example.test:80");
        assert_eq!(request_authority(&https).as_str(), "dns.example.test:443");
    }

    #[test]
    fn request_authority_preserves_explicit_port() {
        let uri: http::Uri = "https://dns.example.test:8443/api".parse().unwrap();

        assert_eq!(request_authority(&uri).as_str(), "dns.example.test:8443");
    }

    #[test]
    fn request_authority_formats_ipv6_with_default_port() {
        let uri: http::Uri = "https://[2001:db8::1]/api".parse().unwrap();

        assert_eq!(request_authority(&uri).as_str(), "[2001:db8::1]:443");
    }
}
