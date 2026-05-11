use std::{fmt, io, sync::Arc, time::Duration};

use dashmap::DashMap;
use futures::{FutureExt, StreamExt, TryFutureExt, stream};
use h3x::{
    endpoint::H3Endpoint,
    dquic::{
        ConnectError,
        net::EndpointAddr,
        resolver::{Publish, PublishFuture, RecordStream, Resolve, ResolveFuture, Source},
    },
    quic,
};
use reqwest::IntoUrl;
use tokio::time::Instant;
use tracing::trace;
use url::Url;

use crate::{MdnsPacket, parser::packet::be_packet, wire::be_multi_response};

// Inner struct that holds the actual H3 client and runs on a dedicated thread
pub struct H3Resolver<C: quic::Connect> {
    client: H3Endpoint<C>,
    base_url: Url,
    cached_records: DashMap<String, Record>,
    negative_cache: DashMap<String, Instant>,
}

#[derive(Debug)]
struct Record {
    addrs: Vec<h3x::dquic::net::EndpointAddr>,
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
    #[snafu(display("h3 request error"))]
    H3Request {
        source: h3x::endpoint::client::RequestError<E>,
    },

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

impl<C: quic::Connect> H3Resolver<C>
where
    C::Error: Send + Sync + 'static,
{
    pub fn new(base_url: impl IntoUrl, client: H3Endpoint<C>) -> io::Result<Self> {
        let base_url = base_url
            .into_url()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        base_url.host_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Base URL must have a valid host",
            )
        })?;

        Ok(Self {
            client,
            base_url,
            cached_records: DashMap::new(),
            negative_cache: DashMap::new(),
        })
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
                .filter_map(|ep| match *ep {
                    h3x::dquic::net::EndpointAddr::Socket(ep) => ep.try_into().ok(),
                    h3x::dquic::net::EndpointAddr::Ble(..) => None,
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
        tracing::trace!("h3x publishing packet for {} to {}", name, self.base_url);
        let (_, resp) = self
            .client
            .new_request()
            .with_body(bytes::Bytes::copy_from_slice(packet))
            .post(uri)
            .await
            .map_err(|source| Error::H3Request { source })?;

        if resp.status() != http::StatusCode::OK {
            return Err(Error::Status {
                status: resp.status(),
            });
        }

        Ok(())
    }

    pub const EXCLUDED_DOMAINS: [&str; 2] = ["dns.genmeta.net", "download.genmeta.net"];

    pub async fn lookup(&self, name: &str) -> Result<RecordStream, Error<C::Error>> {
        use crate::parser::record;
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
        let (_req, mut resp) = self
            .client
            .new_request()
            .get(uri)
            .await
            .map_err(|source| Error::H3Request { source })?;

        tracing::trace!("received response with status {}", resp.status());
        match resp.status() {
            http::StatusCode::OK => {}
            http::StatusCode::NOT_FOUND => {
                self.negative_cache
                    .insert(domain.to_string(), now + negative_ttl);
                return Err(Error::NoRecordFound);
            }
            status => return Err(Error::Status { status }),
        }

        let response = resp
            .read_to_bytes()
            .await
            .map_err(|source| Error::H3Stream { source })?;

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
                            let socket_ep = ep.clone().try_into().ok()?;
                            trace!(?socket_ep, "parsed endpoint from record");
                            Some(h3x::dquic::net::EndpointAddr::Socket(socket_ep))
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

impl<C: quic::Connect> Publish for H3Publisher<C>
where
    C::Error: Send + Sync + 'static,
{
    fn publish<'a>(&'a self, name: &'a str, packet: &'a [u8]) -> PublishFuture<'a> {
        self.publish_packet(name, packet)
            .map_err(io::Error::other)
            .boxed()
    }
}

impl<C: quic::Connect> Resolve for H3Resolver<C>
where
    C::Error: Send + Sync + 'static,
{
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
        self.lookup(name).map_err(io::Error::other).boxed()
    }
}
