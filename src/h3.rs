use std::{fmt, io, time::Duration};

use bytes::{Bytes, BytesMut};
use futures::FutureExt;
use http_body_util::BodyExt;
use qresolve::{EndpointAddr, Family, Publish, PublishFuture, Resolve, ResolveFuture};
use url::Url;

pub use crate::api::{InvalidServerOrigin, LookupDecodeError};

mod cache;
mod lookup;
mod publish;

const LOOKUP_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const LOOKUP_REQUEST_ATTEMPTS: usize = 3;
const STATUS_BODY_LIMIT: usize = 4096;

pub struct H3Resolver {
    server_origin: Url,
    endpoint: Option<dhttp::Endpoint>,
    // Each resolver has a fixed origin and identity, so its cache is already isolated.
    cache: cache::LookupCache,
}

impl fmt::Debug for H3Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H3Resolver")
            .field("server_origin", &self.server_origin)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for H3Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "H3 DNS Resolver({})", self.server_origin)
    }
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(h3_lookup_error))]
#[non_exhaustive]
pub enum H3LookupError {
    #[snafu(display("invalid DNS name"))]
    InvalidName,
    #[snafu(display("DHTTP request failed"))]
    Request { source: dhttp::Error },
    #[snafu(display("DHTTP response body failed"))]
    Body { source: dhttp::BoxError },
    #[snafu(display("H3 DNS lookup timed out after {attempts} attempts of {timeout:?}"))]
    Timeout { timeout: Duration, attempts: usize },
    #[snafu(display("H3 DNS response exceeds {limit} bytes"))]
    ResponseTooLarge { limit: usize },
    #[snafu(display("H3 DNS server returned {status}"))]
    Status { status: http::StatusCode },
    #[snafu(display("failed to decode H3 DNS response"))]
    Decode { source: LookupDecodeError },
    #[snafu(display("no DNS record found"))]
    NoRecordFound,
    #[snafu(display("H3 DNS response contained no usable records"))]
    NoUsableRecord,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(h3_publish_error))]
#[non_exhaustive]
pub enum H3PublishError {
    #[snafu(display("publishing requires a named DHTTP endpoint"))]
    IdentityRequired,
    #[snafu(display("invalid or missing DHTTP DNS publish lease"))]
    InvalidLease,
    #[snafu(display("failed to build local DHTTP signing authority"))]
    Credentials { source: io::Error },
    #[snafu(display("invalid DNS name"))]
    InvalidName,
    #[snafu(display("publisher identity does not match DNS name"))]
    IdentityNameMismatch,
    #[snafu(display("failed to encode H3 DNS publish packet"))]
    EncodePacket {
        source: crate::publishers::packet::EncodeAuthorityDnsPacketError,
    },
    #[snafu(display("H3 DNS publish packet exceeds {limit} bytes"))]
    PacketTooLarge { limit: usize },
    #[snafu(display("failed to sign H3 DNS publish request"))]
    SignRequest {
        source: crate::core::signature::SignatureFieldsError,
    },
    #[snafu(display("DHTTP request failed"))]
    Request { source: dhttp::Error },
    #[snafu(display("failed to upload H3 DNS publish packet"))]
    Upload { source: io::Error },
    #[snafu(display("DHTTP response body failed"))]
    Body { source: dhttp::BoxError },
    #[snafu(display("H3 DNS response exceeds {limit} bytes"))]
    ResponseTooLarge { limit: usize },
    #[snafu(display("H3 DNS server returned {status}{message}"))]
    Status {
        status: http::StatusCode,
        message: StatusMessage,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusMessage(String);

impl StatusMessage {
    fn new(message: String) -> Self {
        Self(message)
    }
}

impl fmt::Display for StatusMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            Ok(())
        } else {
            write!(f, ": {}", self.0)
        }
    }
}

impl H3Resolver {
    /// Bind DNS requests to a named DHTTP endpoint.
    ///
    /// Initialize `dhttp::DhttpNetwork` before making requests.
    /// Queries and publishing share the endpoint's already loaded credentials.
    /// Register a bootstrap resolver (for example `qresolve::SystemResolver`) to
    /// resolve the DNS server's conventional hostname.
    pub fn new(
        server_origin: Url,
        endpoint: &dhttp::Endpoint,
    ) -> Result<Self, InvalidServerOrigin> {
        validate_server_origin(&server_origin)?;
        Ok(Self {
            server_origin,
            endpoint: Some(endpoint.clone()),
            cache: cache::LookupCache::default(),
        })
    }

    /// Query DNS over H3 through `dhttp::Anonymous`, without local credentials.
    ///
    /// Initialize `dhttp::DhttpNetwork` and register a bootstrap resolver before
    /// making requests. Anonymous resolvers cannot publish endpoint records.
    pub fn anonymous(server_origin: Url) -> Result<Self, InvalidServerOrigin> {
        validate_server_origin(&server_origin)?;
        Ok(Self {
            server_origin,
            endpoint: None,
            cache: cache::LookupCache::default(),
        })
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}

fn validate_server_origin(url: &Url) -> Result<(), InvalidServerOrigin> {
    crate::api::validate_server_origin(url, true)
}

#[derive(Debug)]
enum ReadBodyError<E> {
    Body(E),
    TooLarge,
}

async fn read_body_limited<B>(mut body: B, limit: usize) -> Result<Bytes, ReadBodyError<B::Error>>
where
    B: http_body::Body<Data = Bytes> + Unpin,
{
    let mut bytes = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(ReadBodyError::Body)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        if data.len() > limit.saturating_sub(bytes.len()) {
            return Err(ReadBodyError::TooLarge);
        }
        bytes.extend_from_slice(&data);
    }
    Ok(bytes.freeze())
}

impl Publish for H3Resolver {
    fn publish<'a>(
        &'a self,
        name: &'a str,
        endpoints: &mut dyn Iterator<Item = EndpointAddr>,
    ) -> PublishFuture<'a> {
        let endpoints = endpoints.collect::<Vec<_>>();
        async move {
            self.publish_endpoints(name, endpoints)
                .await
                .map(|_| ())
                .map_err(io::Error::other)
        }
        .boxed()
    }
}

impl Resolve for H3Resolver {
    fn lookup<'a>(
        &'a self,
        hostname: &'a str,
        servname: &'a str,
        family: Option<Family>,
    ) -> ResolveFuture<'a> {
        async move {
            H3Resolver::lookup(self, hostname, servname, family)
                .await
                .map_err(io::Error::other)
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_validation_blocks_recursive_and_non_origin_urls() {
        assert!(matches!(
            validate_server_origin(&Url::parse("https://dns.dhttp.net/").unwrap()),
            Err(InvalidServerOrigin::DhttpOrigin)
        ));
        assert!(matches!(
            validate_server_origin(&Url::parse("https://dns.example/api").unwrap()),
            Err(InvalidServerOrigin::HasPathQueryOrFragment)
        ));
        assert!(validate_server_origin(&Url::parse("https://dns.example:4433/").unwrap()).is_ok());
    }

    #[tokio::test]
    async fn bounded_reader_accepts_limit_and_rejects_limit_plus_one() {
        let exact = http_body_util::Full::new(Bytes::from_static(b"1234"));
        assert_eq!(read_body_limited(exact, 4).await.unwrap(), "1234");
        let over = http_body_util::Full::new(Bytes::from_static(b"12345"));
        assert!(matches!(
            read_body_limited(over, 4).await,
            Err(ReadBodyError::TooLarge)
        ));
    }
}
