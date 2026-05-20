use std::{convert::Infallible, fmt, io, sync::Arc, time::Duration};

use dashmap::DashMap;
use ddns_core::{MdnsPacket, parser::packet::be_packet, wire::be_multi_response};
use dquic::{
    qbase::net::addr::EndpointAddr,
    qresolve::{Publish, PublishFuture, RecordStream, Resolve, ResolveFuture, Source},
};
use futures::{StreamExt, stream};
use h3x::{
    dquic::ConnectError, endpoint::H3Endpoint, hyper::client::RequestError as HyperRequestError,
    quic,
};
use http_body_util::{BodyExt, Empty, Full};
use tokio::time::Instant;
use tracing::trace;
use url::Url;

const LOOKUP_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const LOOKUP_REQUEST_ATTEMPTS: usize = 3;

pub struct H3Resolver<C: quic::Connect> {
    endpoint: Arc<H3Endpoint<C, C::Connection>>,
    base_url: Url,
    cached_records: DashMap<String, Record>,
    negative_cache: DashMap<String, Instant>,
}

#[derive(Debug)]
struct Record {
    addrs: Vec<EndpointAddr>,
    expire: Instant,
}

impl<C: quic::Connect> fmt::Debug for H3Resolver<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H3Resolver")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl<C: quic::Connect> fmt::Display for H3Resolver<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "H3 DNS Resolver({})",
            self.base_url.host_str().unwrap_or("<unknown server>")
        )
    }
}

#[derive(Debug, snafu::Snafu)]
pub enum Error<E: std::error::Error + Send + Sync + 'static = ConnectError> {
    #[snafu(display("h3 stream error"))]
    H3Stream {
        source: h3x::endpoint::server::MessageStreamError,
    },
    #[snafu(display("failed to connect h3 endpoint"))]
    Connect { source: h3x::pool::ConnectError<E> },
    #[snafu(display("h3 request error"))]
    H3Request {
        source: HyperRequestError<Infallible>,
    },
    #[snafu(display("h3 request timed out after {timeout:?}"))]
    RequestTimeout { timeout: Duration },

    #[snafu(display("{status}"))]
    Status { status: http::StatusCode },

    #[snafu(display("no DNS record found"))]
    NoRecordFound,

    #[snafu(display("failed to parse DNS records from response"))]
    ParseRecords {
        source: nom::Err<nom::error::Error<Vec<u8>>>,
    },

    #[snafu(display("failed to decode multi-record response"))]
    ParseMultiResponse,
}

impl<C: quic::Connect + Send + Sync + 'static> H3Resolver<C>
where
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
            cached_records: DashMap::new(),
            negative_cache: DashMap::new(),
        })
    }

    fn connect_error(&self, source: h3x::pool::ConnectError<C::Error>) -> Error<C::Error> {
        // H3 DNS resolvers keep a long-lived endpoint. A network transition may
        // leave the cached H3 connection with stale QUIC paths, so the next
        // attempt must establish a fresh connection instead of reusing it.
        self.endpoint.clear_pool();
        Error::Connect { source }
    }

    fn request_error(&self, source: HyperRequestError<Infallible>) -> Error<C::Error> {
        self.endpoint.clear_pool();
        Error::H3Request { source }
    }

    async fn execute_request(
        &self,
        request: http::Request<
            impl http_body::Body<Data = bytes::Bytes, Error = Infallible> + Send + 'static,
        >,
    ) -> Result<
        http::Response<
            impl http_body::Body<Data = bytes::Bytes, Error = h3x::endpoint::server::MessageStreamError>,
        >,
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

    pub fn clear_pool(&self) {
        self.endpoint.clear_pool();
    }

    pub async fn publish_endpoints(
        &self,
        name: &str,
        endpoints: &[EndpointAddr],
    ) -> Result<(), Error<C::Error>> {
        trace!("h3x publishing {} with {} endpoints", name, endpoints.len());
        let bytes = {
            let endpoints = endpoints
                .iter()
                .filter_map(|ep| {
                    ddns_core::parser::record::endpoint::EndpointAddr::try_from(*ep).ok()
                })
                .collect();
            let mut hosts = std::collections::HashMap::new();
            hosts.insert(name.to_string(), endpoints);
            MdnsPacket::answer(0, &hosts).to_bytes()
        };

        self.publish_packet(name, &bytes).await
    }

    /// Publish a pre-built DNS packet (with signatures already included).
    pub async fn publish_packet(&self, name: &str, packet: &[u8]) -> Result<(), Error<C::Error>> {
        let mut url = self.base_url.join("publish").expect("Invalid base URL");
        url.set_query(Some(&format!("host={name}")));
        let uri: http::Uri = url.as_str().parse().expect("URL should be valid URI");
        tracing::trace!(
            name,
            packet_len = packet.len(),
            url = %self.base_url,
            "h3x publishing packet"
        );
        let request = http::Request::post(uri)
            .body(Full::new(bytes::Bytes::copy_from_slice(packet)))
            .expect("h3 dns publish request must be valid");
        let resp = self.execute_request(request).await?;

        if resp.status() != http::StatusCode::OK {
            return Err(Error::Status {
                status: resp.status(),
            });
        }

        Ok(())
    }

    fn retryable_lookup_error(error: &Error<C::Error>) -> bool {
        matches!(
            error,
            Error::Connect { .. } | Error::H3Request { .. } | Error::H3Stream { .. }
        )
    }

    async fn lookup_response(&self, uri: http::Uri) -> Result<bytes::Bytes, Error<C::Error>> {
        let request = http::Request::get(uri)
            .body(Empty::<bytes::Bytes>::new())
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

    async fn lookup_response_with_retry(
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

    pub const EXCLUDED_DOMAINS: [&str; 2] = ["dns.genmeta.net", "download.genmeta.net"];

    pub async fn lookup(&self, name: &str) -> Result<RecordStream, Error<C::Error>> {
        use ddns_core::parser::record;
        let server = Arc::from(self.base_url.host_str().unwrap_or("<unknown server>"));
        let source = Source::Http { server };

        let Some(domain) = super::resolvable_name(name) else {
            return Err(Error::NoRecordFound);
        };

        // 1. Exclude certain domains from lookup
        if Self::EXCLUDED_DOMAINS.contains(&domain) {
            return Err(Error::NoRecordFound);
        }

        let now = Instant::now();
        let positive_ttl = Duration::from_secs(10);
        let negative_ttl = Duration::from_secs(2);

        self.cached_records
            .retain(|_host, record| record.expire > now);
        self.negative_cache.retain(|_host, expire| *expire > now);

        if self.negative_cache.get(domain).is_some() {
            return Err(Error::NoRecordFound);
        }

        if let Some(record) = self.cached_records.get(domain) {
            let addrs = record.addrs.clone();
            let stream = stream::iter(addrs.into_iter().map(move |ep| (source.clone(), ep)));
            return Ok(stream.boxed());
        }

        let mut url = self.base_url.join("lookup").expect("Invalid URL");
        url.set_query(Some(&format!("host={}", domain)));
        let uri: http::Uri = url.as_str().parse().expect("URL should be valid URI");

        tracing::trace!("sending lookup request to {}", self.base_url);
        let response = match self.lookup_response_with_retry(uri).await {
            Ok(response) => response,
            Err(Error::NoRecordFound) => {
                self.negative_cache
                    .insert(domain.to_string(), now + negative_ttl);
                return Err(Error::NoRecordFound);
            }
            Err(error) => return Err(error),
        };

        // Server always returns multi-record format.
        let (_remain, multi) =
            be_multi_response(response.as_ref()).map_err(|_| Error::ParseMultiResponse)?;

        let mut addrs = Vec::new();
        for r in multi.records {
            let (_remain, packet) = be_packet(&r.dns).map_err(|source| Error::ParseRecords {
                source: source.to_owned(),
            })?;

            addrs.extend(
                packet
                    .answers
                    .iter()
                    .filter_map(|answer| match answer.data() {
                        record::RData::E(ep) => {
                            let endpoint = TryInto::<EndpointAddr>::try_into(ep.clone()).ok()?;
                            trace!(?endpoint, "parsed endpoint from record");
                            Some(endpoint)
                        }
                        _ => {
                            tracing::debug!(?answer, "ignored record");
                            None
                        }
                    }),
            );
        }

        if addrs.is_empty() {
            self.negative_cache
                .insert(domain.to_string(), now + negative_ttl);
            return Err(Error::NoRecordFound);
        }

        self.cached_records.insert(
            domain.to_string(),
            Record {
                addrs: addrs.clone(),
                expire: now + positive_ttl,
            },
        );

        self.negative_cache.remove(domain);

        Ok(stream::iter(addrs.into_iter().map(move |ep| (source.clone(), ep))).boxed())
    }
}

pub type H3Publisher<C> = H3Resolver<C>;

impl<C: quic::Connect + Send + Sync + 'static> Publish for H3Publisher<C>
where
    C::Error: Send + Sync + 'static,
    C::Connection: Send + 'static,
{
    fn publish<'a>(&'a self, name: &'a str, packet: &'a [u8]) -> PublishFuture<'a> {
        Box::pin(async move {
            match self.publish_packet(name, packet).await {
                Ok(()) => Ok(()),
                Err(error) => Err(io::Error::other(error)),
            }
        })
    }
}

impl<C: quic::Connect + Send + Sync + 'static> Resolve for H3Resolver<C>
where
    C::Error: Send + Sync + 'static,
    C::Connection: Send + 'static,
{
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
        Box::pin(async move {
            match H3Resolver::lookup(self, name).await {
                Ok(stream) => Ok(stream),
                Err(error) => Err(io::Error::other(error)),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_retry_budget_leaves_external_timeout_margin() {
        let total_budget = LOOKUP_REQUEST_TIMEOUT * LOOKUP_REQUEST_ATTEMPTS as u32;

        assert!(
            total_budget <= Duration::from_secs(10),
            "h3 lookup must return before common 15s command timeouts so callers can retry"
        );
    }
}
