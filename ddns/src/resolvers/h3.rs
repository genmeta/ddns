use std::{fmt, io, sync::Arc, time::Duration};

use dashmap::DashMap;
use ddns_core::{MdnsPacket, parser::packet::be_packet, wire::be_multi_response};
use dquic::{
    qbase::net::addr::EndpointAddr,
    qresolve::{Publish, PublishFuture, RecordStream, Resolve, ResolveFuture, Source},
};
use futures::{StreamExt, stream};
use h3x::{dquic::ConnectError, endpoint::H3Endpoint, quic};
use tokio::time::Instant;
use tracing::trace;
use url::Url;

// Inner struct that holds the actual H3 client and runs on a dedicated thread
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

impl<C: quic::Connect + Send + Sync + 'static> H3Resolver<C>
where
    C::Error: Send + Sync + 'static,
    C::Connection: Send + 'static,
{
    pub fn new(
        base_url: impl AsRef<str>,
        client: H3Endpoint<C, C::Connection>,
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
            endpoint: Arc::new(client),
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
        tracing::trace!("h3x publishing packet for {} to {}", name, self.base_url);
        let resp = self
            .endpoint
            .post(uri)
            .body(packet)
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
        let mut resp = self
            .endpoint
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
        let (tx, rx) = tokio::sync::oneshot::channel();
        let name = name.to_owned();
        let packed = bytes::Bytes::copy_from_slice(packet);
        let base_url = self.base_url.clone();
        let client = self.endpoint.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build runtime");
            let result = rt.block_on(async {
                let mut url = base_url.join("publish").expect("Invalid base URL");
                url.set_query(Some(&format!("host={name}")));
                let uri: http::Uri = url.as_str().parse().expect("URL should be valid URI");
                let resp = client
                    .post(uri)
                    .body(packed)
                    .await
                    .map_err(|source| Error::H3Request { source })?;
                if resp.status() != http::StatusCode::OK {
                    return Err(Error::Status {
                        status: resp.status(),
                    });
                }
                Ok(())
            });
            let _ = tx.send(result);
        });
        Box::pin(async move {
            match rx.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(io::Error::other(e)),
                Err(_) => Err(io::Error::other("task cancelled")),
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
        let (tx, rx) = tokio::sync::oneshot::channel();
        let name = name.to_owned();
        let base_url = self.base_url.clone();
        let client = self.endpoint.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build runtime");
            let result = rt.block_on(async {
                let mut url = base_url.join("lookup").expect("Invalid URL");
                url.set_query(Some(&format!("host={name}")));
                let uri: http::Uri = url.as_str().parse().expect("URL should be valid URI");
                let mut resp = client
                    .get(uri)
                    .await
                    .map_err(|source| Error::H3Request { source })?;
                match resp.status() {
                    http::StatusCode::OK => {
                        let response = resp
                            .read_to_bytes()
                            .await
                            .map_err(|source| Error::H3Stream { source })?;
                        let (_remain, multi) = be_multi_response(response.as_ref())
                            .map_err(|_| Error::ParseMultiResponse)?;
                        let mut addrs = Vec::new();
                        for r in multi.records {
                            let (_remain, mdns_pkt) =
                                be_packet(&r.dns).map_err(|source| Error::ParseRecords {
                                    source: source.to_owned(),
                                })?;
                            addrs.extend(mdns_pkt.answers.iter().filter_map(|answer| {
                                match answer.data() {
                                    ddns_core::parser::record::RData::E(ep) => {
                                        TryInto::<EndpointAddr>::try_into(ep.clone()).ok()
                                    }
                                    _ => None,
                                }
                            }));
                        }
                        if addrs.is_empty() {
                            return Err(Error::NoRecordFound);
                        }
                        let server: Arc<str> =
                            Arc::from(base_url.host_str().unwrap_or("<unknown server>"));
                        Ok(stream::iter(addrs.into_iter().map(move |ep| {
                            (
                                Source::Http {
                                    server: server.clone(),
                                },
                                ep,
                            )
                        }))
                        .boxed())
                    }
                    http::StatusCode::NOT_FOUND => Err(Error::NoRecordFound),
                    status => Err(Error::Status { status }),
                }
            });
            let _ = tx.send(result);
        });
        Box::pin(async move {
            match rx.await {
                Ok(Ok(stream)) => Ok(stream),
                Ok(Err(e)) => Err(io::Error::other(e)),
                Err(_) => Err(io::Error::other("task cancelled")),
            }
        })
    }
}
