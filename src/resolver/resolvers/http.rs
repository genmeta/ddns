use std::{collections::HashMap, fmt::Display, io};

use dashmap::DashMap;
use reqwest::{Client, IntoUrl, StatusCode, Url};
use rustls::{SignatureScheme, sign::SigningKey};
use tokio::time::Instant;

use super::Resolve;
use crate::{MdnsPacket, parser::packet::be_packet};

#[derive(Debug)]
struct Record {
    addrs: Vec<std::net::SocketAddr>,
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

#[async_trait::async_trait]
impl Resolve for HttpResolver {
    async fn publish(
        &self,
        name: &str,
        is_main: bool,
        sequence: u64,
        key: Option<(&dyn SigningKey, SignatureScheme)>,
        addresses: &[std::net::SocketAddr],
    ) -> io::Result<()> {
        let publish = async {
            tracing::debug!(name, ?addresses, "Publishing DNS for with addresses");
            let dns_eps = addresses
                .iter()
                .map(|&addr| {
                    let mut ep = match addr {
                        std::net::SocketAddr::V4(v4) => crate::MdnsEndpoint::direct_v4(v4),
                        std::net::SocketAddr::V6(v6) => crate::MdnsEndpoint::direct_v6(v6),
                    };
                    ep.set_main(is_main);
                    ep.set_sequence(sequence);
                    if let Some((k, s)) = key {
                        if let Err(e) = ep.sign_with(k, s) {
                            return Err(io::Error::other(format!("Sign error: {}", e)));
                        }
                    }
                    Ok(ep)
                })
                .collect::<Result<Vec<_>, io::Error>>()?;
            let mut hosts = HashMap::new();

            hosts.insert(name.to_string(), dns_eps);
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
                .await;

            let _response = response?.error_for_status()?;
            Result::<_, Error>::Ok(())
        };
        publish.await.map_err(io::Error::other)
    }

    async fn lookup(&self, name: &str) -> io::Result<Vec<std::net::SocketAddr>> {
        let lookup = async {
            use crate::parser::record;
            let now = Instant::now();
            self.cached_records
                .retain(|_host, Record { expire, .. }| *expire < now);
            if let Some(record) = self.cached_records.get(name) {
                return Ok(record.addrs.clone());
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
                    record::RData::E(e) => Some(e.primary),
                    _ => {
                        tracing::debug!(?answer, "Ignored record");
                        None
                    }
                })
                .collect::<Vec<_>>();
            if ret.is_empty() {
                return Err(Error::NoRecordFound {});
            }

            Result::<_, Error>::Ok(ret)
        };
        lookup.await.map_err(io::Error::other)
    }
}
