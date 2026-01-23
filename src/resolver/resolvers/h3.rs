use std::{fmt::Display, io, sync::Arc};

use dashmap::DashMap;
use gm_quic::prelude::{
    QuicClient,
    handy::{ToCertificate, ToPrivateKey},
};
use h3x::client::{BuildClientError, Client};
use reqwest::IntoUrl;
use rustls::RootCertStore;
use tokio::{sync::Mutex, time::Instant};
use url::Url;

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

pub struct H3Resolver {
    client: Arc<Mutex<Client<QuicClient>>>,
    base_url: Url,
    cached_records: DashMap<String, Record>,
}

impl std::fmt::Debug for H3Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Resolver")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl Display for H3Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "H3 DNS({})",
            self.base_url.host_str().expect("Checked in constructor")
        )
    }
}

impl H3Resolver {
    pub fn new(base_url: impl IntoUrl, client: Client<QuicClient>) -> io::Result<Self> {
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
            client: Arc::new(Mutex::new(client)),
            base_url,
            cached_records: DashMap::new(),
        })
    }

    pub fn new_with_identity(
        base_url: impl IntoUrl,
        root_store: RootCertStore,
        client_name: impl Into<String>,
        cert_chain: impl ToCertificate,
        private_key: impl ToPrivateKey,
    ) -> io::Result<Self> {
        let client_name = client_name.into();
        let client = h3x::client::Client::<QuicClient>::builder()
            .with_root_certificates(std::sync::Arc::new(root_store))
            .with_identity(client_name, cert_chain, private_key)
            .map_err(|e: BuildClientError| io::Error::other(e.to_string()))?
            .build();
        Self::new(base_url, client)
    }
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("{status}")]
    Status { status: http::StatusCode },

    #[error("No dns record found")]
    NoRecordFound {},

    #[error("Failed to parse dns records from response")]
    ParseRecords { source: io::Error },

    #[error("H3 request error: {message}")]
    H3 { message: String },
}

impl From<io::Error> for Error {
    fn from(source: io::Error) -> Self {
        Error::ParseRecords { source }
    }
}

#[async_trait::async_trait(?Send)]
impl Publisher for H3Resolver {
    async fn publish(&self, name: &str, endpoint: EndpointAddr) -> io::Result<()> {
        let bytes = {
            let mut hosts = std::collections::HashMap::new();
            hosts.insert(name.to_string(), vec![endpoint]);
            let answer = MdnsPacket::answer(0, &hosts);
            answer.to_bytes()
        };

        let mut url = self.base_url.join("publish").expect("Invalid base URL");
        url.set_query(Some(&format!("host={name}")));
        let uri: http::Uri = url
            .as_str()
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let client = self.client.clone().lock_owned().await;
        let (_req, mut resp) = client
            .new_request()
            .with_body(bytes::Bytes::from(bytes))
            .post(uri)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        if resp.status() != http::StatusCode::OK {
            return Err(io::Error::other(Error::Status {
                status: resp.status(),
            }));
        }

        _ = resp.read_to_bytes().await.map_err(|e| {
            io::Error::other(Error::H3 {
                message: e.to_string(),
            })
        })?;

        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl Resolver for H3Resolver {
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

            let url = self.base_url.join("lookup").expect("Invalid URL");
            let uri: http::Uri = format!("{}?host={}", url.as_str(), name)
                .parse()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

            let client = self.client.clone().lock_owned().await;
            let (_req, mut resp) = client
                .new_request()
                .get(uri)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;

            match resp.status() {
                http::StatusCode::OK => {}
                http::StatusCode::NOT_FOUND => return Err(Error::NoRecordFound {}),
                status => return Err(Error::Status { status }),
            }

            let response = resp.read_to_bytes().await.map_err(|e| Error::H3 {
                message: e.to_string(),
            })?;

            let (_remain, packet) = be_packet(&response).map_err(|error| Error::ParseRecords {
                source: io::Error::other(error.to_string()),
            })?;

            let ret = packet
                .answers
                .iter()
                .filter_map(|answer| match answer.data() {
                    record::RData::E(e) => Some((None, e.clone())),
                    _ => None,
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
