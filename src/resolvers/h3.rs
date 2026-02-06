use std::{fmt::Display, io, sync::Arc};

use dashmap::DashMap;
use futures::{StreamExt, stream};
use h3x::gm_quic::{
    H3Client,
    prelude::{
        ConnectServerError, QuicClient,
        handy::{ToCertificate, ToPrivateKey},
    },
};
use qdns::{EndpointAddr, Publish, PublishFuture, RecordStream, Resolve, ResolveFuture, Source};
use reqwest::IntoUrl;
use rustls::RootCertStore;
use tokio::{
    sync::{mpsc, oneshot},
    time::Instant,
};
use tracing::debug;
use url::Url;

use crate::{MdnsPacket, parser::packet::be_packet};

#[derive(Debug)]
struct Record {
    addrs: Vec<EndpointAddr>,
    expire: Instant,
}

// Internal message types for communication with the worker thread

enum Command {
    Publish {
        name: String,
        endpoints: Vec<EndpointAddr>,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    Lookup {
        name: String,
        reply: oneshot::Sender<Result<RecordStream<'static>, Error>>,
    },
}

// Inner struct that holds the actual H3 client and runs on a dedicated thread
struct H3ResolverInner {
    client: H3Client,
    base_url: Url,
    cached_records: DashMap<String, Record>,
}

impl H3ResolverInner {
    async fn publish(&self, name: &str, endpoints: &[EndpointAddr]) -> Result<(), Error> {
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

    async fn lookup(&self, name: &str) -> Result<RecordStream<'static>, Error> {
        use crate::parser::record;
        let now = Instant::now();
        let server = Arc::from(self.base_url.host_str().unwrap_or("<unknown server>"));
        let source = Source::Http { server };

        // 1. Check cache (Lazy expiration)
        if let Some(entry) = self.cached_records.get(name)
            && entry.expire > Instant::now()
        {
            let endpoint_addrs: Vec<_> =
                entry.addrs.iter().map(|ep| (source.clone(), *ep)).collect();
            return Ok(futures::stream::iter(endpoint_addrs).boxed());
        }
        // Expired: remove it (drop the entry lock first if needed, but DashMap handles this)
        // We'll just fall through to fetch fresh data and overwrite it.

        let mut url = self.base_url.join("lookup").expect("Invalid URL");
        url.set_query(Some(&format!("host={}", name)));
        let uri: http::Uri = url.as_str().parse().expect("URL should be valid URI");

        let (_req, mut resp) = self
            .client
            .new_request()
            .get(uri)
            .await
            .map_err(|source| Error::H3Request { source })?;

        match resp.status() {
            http::StatusCode::OK => {}
            http::StatusCode::NOT_FOUND => {
                return Err(Error::NoRecordFound {});
            }
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

    async fn run(self: Arc<Self>, mut rx: mpsc::Receiver<Command>) {
        while let Some(cmd) = rx.recv().await {
            let this = self.clone();
            // 2. Concurrency: Spawn a task for each request to avoid blocking
            tokio::task::spawn_local(async move {
                match cmd {
                    Command::Publish {
                        name,
                        endpoints,
                        reply,
                    } => {
                        let result = this.publish(&name, &endpoints).await;
                        let _ = reply.send(result);
                    }
                    Command::Lookup { name, reply } => {
                        let result = this.lookup(&name).await;
                        let _ = reply.send(result);
                    }
                }
            });
        }
    }
}

pub struct H3Resolver {
    tx: mpsc::Sender<Command>,
    base_url: Url,
}

pub struct H3Publisher {
    tx: mpsc::Sender<Command>,
    base_url: Url,
}

impl std::fmt::Debug for H3Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Resolver")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for H3Publisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Publisher")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl Display for H3Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "H3 DNS Resolver({})",
            self.base_url.host_str().expect("Checked in constructor")
        )
    }
}

impl Display for H3Publisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "H3 DNS Publisher({})",
            self.base_url.host_str().expect("Checked in constructor")
        )
    }
}

impl H3Resolver {
    pub fn new(base_url: impl IntoUrl, client: H3Client) -> io::Result<Self> {
        let (tx, base_url) = create_inner(base_url, client)?;
        Ok(Self { tx, base_url })
    }
}

impl H3Publisher {
    pub fn new(base_url: impl IntoUrl, client: H3Client) -> io::Result<Self> {
        let (tx, base_url) = create_inner(base_url, client)?;
        Ok(Self { tx, base_url })
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
            .map_err(io::Error::other)?
            .build();
        Self::new(base_url, client)
    }
}

fn create_inner(
    base_url: impl IntoUrl,
    client: H3Client,
) -> io::Result<(mpsc::Sender<Command>, Url)> {
    let base_url = base_url
        .into_url()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    base_url.host_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Base URL must have a valid host",
        )
    })?;

    let inner = Arc::new(H3ResolverInner {
        client,
        base_url: base_url.clone(),
        cached_records: DashMap::new(),
    });

    let (tx, rx) = mpsc::channel(32);

    let inner_clone = inner.clone();
    tokio::spawn(async move {
        inner_clone.run(rx).await;
    });

    Ok((tx, base_url))
}

#[derive(thiserror::Error, Debug)]
enum Error {
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

// H3Resolver uses a dedicated worker thread with LocalSet to handle non-Send futures.
// Communication happens via channels, making the public API fully Send + Sync compatible.

const EXCLUDED_DOMAINS: [&str; 4] = [
    "dns.genmeta.net",
    "stun.genmeta.net",
    "nat.genmeta.net",
    "download.genmeta.net",
];

impl Publish for H3Publisher {
    fn publish<'a>(&'a self, name: &'a str, endpoints: &'a [EndpointAddr]) -> PublishFuture<'a> {
        let publish = async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.tx
                .send(Command::Publish {
                    name: name.to_string(),
                    endpoints: endpoints.to_vec(),
                    reply: reply_tx,
                })
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "H3Resolver worker stopped")
                })?;

            reply_rx
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "H3Resolver worker stopped")
                })?
                .map_err(io::Error::other)
        };
        Box::pin(publish)
    }
}

impl Resolve for H3Resolver {
    fn lookup<'r, 'n: 'r>(&'r self, name: &'n str) -> ResolveFuture<'r, 'n> {
        Box::pin(async move {
            let domain = name.split(':').next().unwrap_or(name);
            if (!domain.ends_with(".genmeta.net") && domain != "genmeta.net")
                || EXCLUDED_DOMAINS.contains(&domain)
            {
                return Err(io::Error::other(Error::NoRecordFound {}));
            }

            let (reply_tx, reply_rx) = oneshot::channel();
            self.tx
                .send(Command::Lookup {
                    name: name.to_string(),
                    reply: reply_tx,
                })
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "H3Resolver worker stopped")
                })?;

            reply_rx
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "H3Resolver worker stopped")
                })?
                .map_err(io::Error::other)
        })
    }
}
