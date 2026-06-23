use std::{convert::Infallible, fmt, io, sync::Arc, time::Duration};

use dquic::qresolve::{Publish, PublishFuture, Resolve, ResolveFuture};
use h3x::{
    dhttp::message::{MessageStreamError, hyper::client::RequestError as HyperRequestError},
    endpoint::H3Endpoint,
    quic,
};
use url::Url;

mod cache;
mod lookup;
mod publish;
mod request;

const LOOKUP_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const LOOKUP_REQUEST_ATTEMPTS: usize = 3;

pub struct H3Resolver<C>
where
    C: quic::Connect + quic::WithLocalAuthority,
{
    endpoint: Arc<H3Endpoint<C, C::Connection>>,
    base_url: Url,
    cache: cache::LookupCache,
}

impl<C> fmt::Debug for H3Resolver<C>
where
    C: quic::Connect + quic::WithLocalAuthority,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H3Resolver")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl<C> fmt::Display for H3Resolver<C>
where
    C: quic::Connect + quic::WithLocalAuthority,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "H3 DNS Resolver({})", self.base_url)
    }
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum H3RequestError<E: std::error::Error + Send + Sync + 'static> {
    #[snafu(display("failed to connect h3 endpoint"))]
    Connect { source: h3x::pool::ConnectError<E> },
    #[snafu(display("h3 request error"))]
    Request {
        source: HyperRequestError<Infallible>,
    },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum H3PublishError<E: std::error::Error + Send + Sync + 'static> {
    #[snafu(transparent)]
    Request { source: H3RequestError<E> },
    #[snafu(display("anonymous h3 endpoint cannot sign dns publish request"))]
    AnonymousEndpoint,
    #[snafu(display("failed to get h3 endpoint local authority"))]
    LocalAuthority { source: h3x::quic::ConnectionError },
    #[snafu(display("failed to sign h3 dns publish request"))]
    SignRequest {
        source: crate::core::signature::SignatureFieldsError,
    },
    #[snafu(display("{status}"))]
    Status { status: http::StatusCode },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum H3LookupError<E: std::error::Error + Send + Sync + 'static> {
    #[snafu(transparent)]
    Request { source: H3RequestError<E> },
    #[snafu(display("h3 stream error"))]
    H3Stream { source: MessageStreamError },
    #[snafu(display("h3 request timed out after {timeout:?}"))]
    RequestTimeout { timeout: Duration },
    #[snafu(display("{status}"))]
    Status { status: http::StatusCode },
    #[snafu(display("no DNS record found"))]
    NoRecordFound,
    #[snafu(display("failed to decode h3 dns lookup response"))]
    Decode { source: LookupDecodeError },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum LookupDecodeError {
    #[snafu(display("failed to decode multi-record response"))]
    MultiResponse,
    #[snafu(display("failed to parse DNS records from response"))]
    ParseRecords {
        source: nom::Err<nom::error::Error<Vec<u8>>>,
    },
}

impl<C> H3Resolver<C>
where
    C: quic::Connect + quic::WithLocalAuthority + Send + Sync + 'static,
    C::Error: Send + Sync + 'static,
    C::Connection: Send + 'static,
{
    pub fn new(
        base_url: impl AsRef<str>,
        client: H3Endpoint<C, C::Connection>,
    ) -> io::Result<Self> {
        Self::from_endpoint(base_url, Arc::new(client))
    }

    pub fn from_endpoint(
        base_url: impl AsRef<str>,
        endpoint: Arc<H3Endpoint<C, C::Connection>>,
    ) -> io::Result<Self> {
        let base_url = Url::parse(base_url.as_ref())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        base_url.host_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "base URL must have a valid host",
            )
        })?;

        Ok(Self {
            endpoint,
            base_url,
            cache: cache::LookupCache::default(),
        })
    }

    pub fn clear_pool(&self) {
        self.endpoint.clear_pool();
    }
}

impl<C> Publish for H3Resolver<C>
where
    C: quic::Connect + quic::WithLocalAuthority + Send + Sync + 'static,
    C::Error: Send + Sync + 'static,
    C::Connection: Send + 'static,
{
    fn publish<'a>(&'a self, name: &'a str, packet: &'a [u8]) -> PublishFuture<'a> {
        Box::pin(async move {
            self.publish_packet(name, packet)
                .await
                .map_err(io::Error::other)
        })
    }
}

impl<C> Resolve for H3Resolver<C>
where
    C: quic::Connect + quic::WithLocalAuthority + Send + Sync + 'static,
    C::Error: Send + Sync + 'static,
    C::Connection: Send + 'static,
{
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
        Box::pin(async move {
            H3Resolver::lookup(self, name)
                .await
                .map_err(io::Error::other)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    #[cfg(feature = "dquic-network")]
    use dquic::{qbase::net::addr::EndpointAddr, qresolve::Source};
    #[cfg(feature = "dquic-network")]
    use futures::StreamExt;

    use super::*;
    #[cfg(feature = "dquic-network")]
    use crate::resolvers::DHTTP_H3_DNS_SERVER;

    #[test]
    fn lookup_retry_budget_leaves_external_timeout_margin() {
        let total_budget = LOOKUP_REQUEST_TIMEOUT * LOOKUP_REQUEST_ATTEMPTS as u32;

        assert!(
            total_budget <= Duration::from_secs(10),
            "h3 lookup must return before common 15s command timeouts so callers can retry"
        );
    }

    #[cfg(feature = "dquic-network")]
    #[tokio::test]
    async fn cached_lookup_reports_h3_dns_source() {
        let endpoint = Arc::new(h3x::endpoint::H3Endpoint::new(
            h3x::dquic::QuicEndpoint::builder().build().await,
        ));
        let resolver = H3Resolver::from_endpoint(DHTTP_H3_DNS_SERVER, endpoint).unwrap();
        resolver.cache.insert_positive(
            "car.lab.dhttp.net",
            vec![EndpointAddr::direct("192.168.5.78:41748".parse().unwrap())],
        );

        let mut records = resolver.lookup("car.lab.dhttp.net").await.unwrap();
        let (source, endpoint) = records.next().await.unwrap();

        assert_eq!(
            source,
            Source::H3 {
                server: Arc::from(resolver.base_url.origin().ascii_serialization())
            }
        );
        assert_eq!(
            endpoint,
            EndpointAddr::direct("192.168.5.78:41748".parse().unwrap())
        );
    }

    #[cfg(feature = "dquic-network")]
    #[tokio::test]
    async fn cached_dns_genmeta_net_record_is_returned() {
        let endpoint = Arc::new(h3x::endpoint::H3Endpoint::new(
            h3x::dquic::QuicEndpoint::builder().build().await,
        ));
        let resolver = H3Resolver::from_endpoint(DHTTP_H3_DNS_SERVER, endpoint).unwrap();
        resolver.cache.insert_positive(
            "dns.genmeta.net",
            vec![EndpointAddr::direct("192.0.2.53:4433".parse().unwrap())],
        );

        let mut records = resolver.lookup("dns.genmeta.net").await.unwrap();
        let (_source, endpoint) = records.next().await.unwrap();

        assert_eq!(
            endpoint,
            EndpointAddr::direct("192.0.2.53:4433".parse().unwrap())
        );
    }

    #[cfg(feature = "dquic-network")]
    #[tokio::test]
    async fn cached_lookup_uses_e_record_port_not_input_port() {
        let endpoint = Arc::new(h3x::endpoint::H3Endpoint::new(
            h3x::dquic::QuicEndpoint::builder().build().await,
        ));
        let resolver = H3Resolver::from_endpoint(DHTTP_H3_DNS_SERVER, endpoint).unwrap();
        resolver.cache.insert_positive(
            "nat.genmeta.net:20004",
            vec![EndpointAddr::direct("192.0.2.10:21000".parse().unwrap())],
        );

        let mut records = resolver.lookup("nat.genmeta.net:20004").await.unwrap();
        let (_source, endpoint) = records.next().await.unwrap();

        assert_eq!(
            endpoint,
            EndpointAddr::direct("192.0.2.10:21000".parse().unwrap())
        );
    }
}
