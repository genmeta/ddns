use std::{collections::HashMap, fmt::Display, io};

use dashmap::DashMap;
use reqwest::{Client, IntoUrl, StatusCode, Url};
use tokio::time::Instant;

use super::{Publisher, Resolver};
use crate::{
    MdnsPacket,
    parser::{packet::be_packet, record::endpoint::EndpointAddr},
};

#[derive(Debug)]
struct Record {
    addrs: Vec<EndpointAddr>,
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

        let http_client = Client::builder()
            .build()
            // with certs?
            .expect("Failed to build HTTP client");
        Ok(Self {
            http_client,
            base_url,
            cached_records: DashMap::new(),
        })
    }
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error(transparent)]
    Reqwest { source: reqwest::Error },

    #[error("{status}")]
    Status { status: StatusCode },

    #[error("No dns record found")]
    NoRecordFound {},

    #[error("Failed to parse dns records from response")]
    ParseRecords { source: io::Error },
}

impl From<reqwest::Error> for Error {
    fn from(source: reqwest::Error) -> Self {
        match source.status() {
            Some(stateus) if stateus == StatusCode::NOT_FOUND => Error::NoRecordFound {},
            Some(status) => Error::Status { status },
            None => Error::Reqwest {
                source: source.without_url(),
            },
        }
    }
}

impl From<io::Error> for Error {
    fn from(source: io::Error) -> Self {
        Error::ParseRecords { source }
    }
}

#[async_trait::async_trait(?Send)]
impl Publisher for HttpResolver {
    async fn publish(&self, name: &str, endpoint: EndpointAddr) -> io::Result<()> {
        let mut hosts = HashMap::new();
        hosts.insert(name.to_string(), vec![endpoint]);
        let answer = MdnsPacket::answer(0, &hosts);
        let bytes = answer.to_bytes();

        let mut url = self.base_url.join("publish").expect("Invalid base URL");
        url.set_query(Some(&format!("host={name}")));
        let client = reqwest::Client::new();
        let response = client
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .body(bytes)
            .send()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let _response = response
            .error_for_status()
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl Resolver for HttpResolver {
    async fn lookup(&self, name: &str) -> io::Result<Vec<(Option<String>, EndpointAddr)>> {
        let lookup = async {
            use crate::parser::record;
            let now = Instant::now();
            self.cached_records
                .retain(|_host, Record { expire, .. }| *expire < now);
            if let Some(record) = self.cached_records.get(name) {
                return Ok(record
                    .addrs
                    .iter()
                    .map(|e: &EndpointAddr| (None, e.clone()))
                    .collect());
            }
            let response = self
                .http_client
                .get(self.base_url.join("lookup").expect("Invalid URL"))
                .query(&[("host", name)])
                .send()
                .await;

            let response = response?.error_for_status()?.bytes().await?;

            let (_remain, packet) = be_packet(&response).map_err(|error| Error::ParseRecords {
                source: io::Error::other(error.to_string()),
            })?;

            let ret = packet
                .answers
                .iter()
                .filter_map(|answer| match answer.data() {
                    record::RData::E(e) => Some((None, e.clone())),
                    _ => {
                        tracing::debug!(?answer, "Ignored record");
                        None
                    }
                })
                .collect::<Vec<_>>();
            if ret.is_empty() {
                return Err(Error::NoRecordFound {});
            }

            // cache the addrs
            let addrs = ret.iter().map(|(_, e)| e.clone()).collect();
            self.cached_records.insert(
                name.to_string(),
                Record {
                    addrs,
                    expire: now + std::time::Duration::from_secs(300),
                },
            );

            Ok(ret)
        };
        lookup.await.map_err(io::Error::other)
    }
}
