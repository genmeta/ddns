use std::{fmt, io, sync::Arc};

use dashmap::DashMap;
use futures::{FutureExt, StreamExt, TryFutureExt, stream};
use h3x::gm_quic::{H3Client, prelude::ConnectServerError};
use qdns::{EndpointAddr, Publish, PublishFuture, RecordStream, Resolve, ResolveFuture, Source};
use reqwest::IntoUrl;
use tokio::time::Instant;
use tracing::debug;
use url::Url;

use crate::{MdnsPacket, parser::packet::be_packet};

#[derive(Debug)]
struct Record {
    addrs: Vec<EndpointAddr>,
    expire: Instant,
}

// Inner struct that holds the actual H3 client and runs on a dedicated thread
pub struct H3Resolver {
    client: H3Client,
    base_url: Url,
    cached_records: DashMap<String, Record>,
}

impl fmt::Debug for H3Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H3Resolver")
            .field("base_url", &self.base_url)
            .field("cached_records", &self.cached_records)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for H3Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "H3 DNS Resolver({})",
            self.base_url.host_str().unwrap_or("<unknown server>")
        )
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("H3 request error")]
    H3Stream {
        #[from]
        source: h3x::client::StreamError,
    },
    #[error("H3 request error")]
    H3Request {
        #[from]
        source: h3x::client::RequestError<ConnectServerError>,
    },

    #[error("{status}")]
    Status { status: http::StatusCode },

    #[error("No dns record found")]
    NoRecordFound {},

    #[error("Failed to parse dns records from response")]
    ParseRecords {
        #[from]
        source: nom::Err<nom::error::Error<Vec<u8>>>,
    },
}

impl H3Resolver {
    pub fn new(base_url: impl IntoUrl, client: H3Client) -> io::Result<Self> {
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
        })
    }

    pub async fn publish(&self, name: &str, endpoints: &[EndpointAddr]) -> Result<(), Error> {
        debug!("h3x Publishing {} with {} endpoints", name, endpoints.len());
        let bytes = {
            let endpoints = endpoints
                .iter()
                .filter_map(|ep| match *ep {
                    qdns::EndpointAddr::Socket(ep) => ep.try_into().ok(),
                    qdns::EndpointAddr::Ble(..) => None,
                })
                .collect();
            let mut hosts = std::collections::HashMap::new();
            hosts.insert(name.to_string(), endpoints);
            let answer = MdnsPacket::answer(0, &hosts);
            answer.to_bytes()
        };

        let mut url = self.base_url.join("publish").expect("Invalid base URL");
        url.set_query(Some(&format!("host={name}")));
        let uri: http::Uri = url.as_str().parse().expect("URL should be valid URI");

        let (_, resp) = self
            .client
            .new_request()
            .with_body(bytes::Bytes::from(bytes))
            .post(uri)
            .await?;

        if resp.status() != http::StatusCode::OK {
            return Err(Error::Status {
                status: resp.status(),
            });
        }

        Ok(())
    }

    pub const EXCLUDED_DOMAINS: [&str; 4] = [
        "dns.genmeta.net",
        "stun.genmeta.net",
        "nat.genmeta.net",
        "download.genmeta.net",
    ];

    pub async fn lookup(&self, name: &str) -> Result<RecordStream, Error> {
        use crate::parser::record;
        let now = Instant::now();
        let server = Arc::from(self.base_url.host_str().unwrap_or("<unknown server>"));
        let source = Source::Http { server };

        // 0. Exclude certain domains from lookup
        if Self::EXCLUDED_DOMAINS.contains(&name) {
            return Err(Error::NoRecordFound {});
        }

        // 1. Check cache (Lazy expiration)
        if let Some(entry) = self.cached_records.get(name)
            && entry.expire > Instant::now()
        {
            let endpoint_addrs: Vec<_> = entry
                .addrs
                .iter()
                .map(move |ep| (source.clone(), *ep))
                .collect();
            return Ok(futures::stream::iter(endpoint_addrs).boxed());
        }
        // Expired: remove it (drop the entry lock first if needed, but DashMap handles this)
        // We'll just fall through to fetch fresh data and overwrite it.

        let mut url = self.base_url.join("lookup").expect("Invalid URL");
        url.set_query(Some(&format!("host={}", name)));
        let uri: http::Uri = url.as_str().parse().expect("URL should be valid URI");

        tracing::debug!("Cache miss, sending lookup request to {}", self.base_url);
        let (_req, mut resp) = self
            .client
            .new_request()
            .get(uri)
            .await
            .map_err(|source| Error::H3Request { source })?;

        tracing::debug!("Received response with status {}", resp.status());
        match resp.status() {
            http::StatusCode::OK => {}
            http::StatusCode::NOT_FOUND => return Err(Error::NoRecordFound {}),
            status => return Err(Error::Status { status }),
        }

        let response = resp
            .read_to_bytes()
            .await
            .map_err(|source| Error::H3Stream { source })?;

        let (_remain, packet) = be_packet(&response).map_err(|source| Error::ParseRecords {
            source: source.to_owned(),
        })?;

        let addrs = packet
            .answers
            .iter()
            .filter_map(|answer| match answer.data() {
                record::RData::E(ep) => {
                    let socket_ep = ep.clone().try_into().ok()?;
                    Some(qdns::EndpointAddr::Socket(socket_ep))
                }
                _ => {
                    tracing::debug!(?answer, "Ignored record");
                    None
                }
            })
            .collect::<Vec<_>>();

        if addrs.is_empty() {
            return Err(Error::NoRecordFound {});
        }

        // cache the addrs
        self.cached_records.insert(
            name.to_string(),
            Record {
                addrs: addrs.clone(),
                expire: now + std::time::Duration::from_secs(300),
            },
        );

        Ok(stream::iter(addrs.into_iter().map(move |ep| (source.clone(), ep))).boxed())
    }
}

pub type H3Publisher = H3Resolver;

impl Publish for H3Publisher {
    fn publish<'a>(&'a self, name: &'a str, endpoints: &'a [EndpointAddr]) -> PublishFuture<'a> {
        self.publish(name, endpoints)
            .map_err(io::Error::other)
            .boxed()
    }
}

impl Resolve for H3Resolver {
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
        self.lookup(name).map_err(io::Error::other).boxed()
    }
}
