use std::{
    fmt::Display,
    io,
    sync::{Arc, LazyLock},
};

use dashmap::DashMap;
use futures::{StreamExt, TryFutureExt, stream};
use h3x::dquic::resolver::{Publish, PublishFuture, Resolve, ResolveFuture, Source};
use reqwest::{Client, IntoUrl, StatusCode, Url};
use tokio::time::Instant;

use crate::parser::packet::be_packet;

#[derive(Debug)]
struct Record {
    addrs: Vec<h3x::dquic::net::EndpointAddr>,
    expire: Instant,
}

#[derive(Debug)]
pub struct HttpResolver {
    http_client: Client,
    base_url: Url,
    cached_records: DashMap<String, Record>,
}

impl Display for HttpResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Http DNS({})",
            self.base_url.host_str().expect("Cheked in constructor")
        )
    }
}

impl HttpResolver {
    pub fn new(base_url: impl IntoUrl) -> io::Result<Self> {
        let base_url = base_url
            .into_url()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        base_url.host_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Base URL must have a valid host",
            )
        })?;

        static HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| {
            Client::builder()
                .build()
                // with certs?
                .expect("Failed to build HTTP client for HttpResolver")
        });

        Ok(Self {
            http_client: HTTP_CLIENT.clone(),
            base_url,
            cached_records: DashMap::new(),
        })
    }
}

#[derive(Debug, snafu::Snafu)]
enum Error {
    #[snafu(display("HTTP request failed"))]
    Reqwest { source: reqwest::Error },

    #[snafu(display("{status}"))]
    Status { status: StatusCode },

    #[snafu(display("no DNS record found"))]
    NoRecordFound,

    #[snafu(display("failed to parse DNS records from response"))]
    ParseRecords {
        source: nom::Err<nom::error::Error<Vec<u8>>>,
    },
}

impl From<reqwest::Error> for Error {
    fn from(source: reqwest::Error) -> Self {
        match source.status() {
            Some(stateus) if stateus == StatusCode::NOT_FOUND => Error::NoRecordFound,
            Some(status) => Error::Status { status },
            None => Error::Reqwest {
                source: source.without_url(),
            },
        }
    }
}

impl Publish for HttpResolver {
    fn publish<'a>(&'a self, name: &'a str, packet: &'a [u8]) -> PublishFuture<'a> {
        Box::pin(async move {
            let mut url = self.base_url.join("publish").expect("Invalid base URL");
            url.set_query(Some(&format!("host={name}")));
            let client = reqwest::Client::new();
            let response = client
                .post(url)
                .header("Content-Type", "application/octet-stream")
                .body(packet.to_vec())
                .send()
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;

            let _response = response
                .error_for_status()
                .map_err(|e| io::Error::other(e.to_string()))?;
            Ok(())
        })
    }
}

impl Resolve for HttpResolver {
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
        let lookup = async move {
            let Some(domain) = super::resolvable_name(name) else {
                return Err(Error::NoRecordFound);
            };

            let now = Instant::now();
            let server = Arc::from(self.base_url.host_str().unwrap_or("<unknown server>"));
            let soource = Source::Http { server };

            use crate::parser::record;
            self.cached_records
                .retain(|_host, Record { expire, .. }| *expire < now);
            if let Some(record) = self.cached_records.get(domain) {
                let endpoint_addrs: Vec<_> = record
                    .addrs
                    .iter()
                    .map(|e: &h3x::dquic::net::EndpointAddr| (soource.clone(), *e))
                    .collect();
                return Ok(stream::iter(endpoint_addrs).boxed());
            }
            let response = self
                .http_client
                .get(self.base_url.join("lookup").expect("Invalid URL"))
                .query(&[("host", domain)])
                .send()
                .await;

            let response = response?.error_for_status()?.bytes().await?;

            let (_remain, packet) = be_packet(&response).map_err(|source| Error::ParseRecords {
                source: source.to_owned(),
            })?;

            let addrs = packet
                .answers
                .iter()
                .filter_map(|answer| match answer.data() {
                    record::RData::E(ep) => {
                        let endpoint = ep.clone().try_into().ok()?;
                        Some(endpoint)
                    }
                    _ => {
                        tracing::debug!(?answer, "ignored record");
                        None
                    }
                })
                .collect::<Vec<_>>();
            if addrs.is_empty() {
                return Err(Error::NoRecordFound);
            }

            // cache the addrs
            self.cached_records.insert(
                domain.to_string(),
                Record {
                    addrs: addrs.clone(),
                    expire: now + std::time::Duration::from_secs(300),
                },
            );

            Ok(stream::iter(addrs.into_iter().map(move |ep| (soource.clone(), ep))).boxed())
        };
        Box::pin(lookup.map_err(io::Error::other))
    }
}
