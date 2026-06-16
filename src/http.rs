use std::{fmt::Display, io, sync::Arc};

use dashmap::DashMap;
use dquic::{
    qbase::net::addr::EndpointAddr,
    qresolve::{Publish, PublishFuture, Resolve, ResolveFuture, Source},
};
use futures::{StreamExt, TryFutureExt, stream};
use reqwest::{Client, IntoUrl, StatusCode, Url};
use tokio::time::Instant;

use crate::core::{
    parser::packet::be_packet,
    signature::{CONTENT_DIGEST_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER, SignatureFields},
    wire::be_multi_response,
};

const LOOKUP_API_PATH: &str = "/api/v2/lookup";
const PUBLISH_API_PATH: &str = "/api/v2/publish";

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

fn lookup_url(base_url: &Url, name: &str) -> Url {
    api_url(base_url, LOOKUP_API_PATH, name)
}

fn publish_url(base_url: &Url, name: &str) -> Url {
    api_url(base_url, PUBLISH_API_PATH, name)
}

fn api_url(base_url: &Url, path: &str, name: &str) -> Url {
    let mut url = base_url.join(path).expect("ddns api path must be valid");
    url.query_pairs_mut().append_pair("host", name);
    url
}

impl Display for HttpResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Http DNS({})",
            self.base_url.host_str().expect("checked in constructor")
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
                "base URL must have a valid host",
            )
        })?;

        Ok(Self {
            http_client: build_http_client()?,
            base_url,
            cached_records: DashMap::new(),
        })
    }

    pub async fn publish_signed(
        &self,
        name: &str,
        packet: &[u8],
        signature_fields: &SignatureFields,
    ) -> io::Result<()> {
        self.publish_packet_with_signature(name, packet, signature_fields)
            .await
            .map_err(io::Error::other)
    }

    async fn publish_packet_with_signature(
        &self,
        name: &str,
        packet: &[u8],
        signature_fields: &SignatureFields,
    ) -> Result<(), Error> {
        let url = publish_url(&self.base_url, name);
        let mut request = self
            .http_client
            .post(url)
            .header("Content-Type", "application/octet-stream");
        if !signature_fields.is_empty() {
            request = request
                .header(
                    CONTENT_DIGEST_HEADER,
                    signature_fields.content_digest.as_slice(),
                )
                .header(
                    SIGNATURE_INPUT_HEADER,
                    signature_fields.signature_input.as_slice(),
                )
                .header(SIGNATURE_HEADER, signature_fields.signature.as_slice());
        }
        request
            .body(packet.to_vec())
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

fn build_http_client() -> io::Result<Client> {
    let native_certs = rustls_native_certs::load_native_certs();
    for error in &native_certs.errors {
        let report = snafu::Report::from_error(error);
        tracing::warn!(error = %report, "failed to load native root certificate");
    }

    let mut root_store = rustls::RootCertStore::empty();
    let (valid_roots, invalid_roots) = root_store.add_parsable_certificates(native_certs.certs);
    if invalid_roots > 0 {
        tracing::debug!(invalid_roots, "ignored invalid native root certificates");
    }
    if valid_roots == 0 {
        tracing::warn!("no native root certificates loaded for http resolver");
    }

    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Client::builder()
        .use_preconfigured_tls(tls)
        .build()
        .map_err(io::Error::other)
}

#[derive(Debug, snafu::Snafu)]
enum Error {
    #[snafu(display("http request failed"))]
    Reqwest { source: reqwest::Error },

    #[snafu(display("{status}"))]
    Status { status: StatusCode },

    #[snafu(display("no DNS record found"))]
    NoRecordFound,

    #[snafu(display("failed to parse DNS records from response"))]
    ParseRecords {
        source: nom::Err<nom::error::Error<Vec<u8>>>,
    },

    #[snafu(display("failed to decode multi-record response"))]
    ParseMultiResponse,
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
            self.publish_packet_with_signature(name, packet, &SignatureFields::empty())
                .await
                .map_err(io::Error::other)
        })
    }
}

impl Resolve for HttpResolver {
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
        let lookup = async move {
            let Some(domain) = crate::resolvers::resolvable_name(name) else {
                return Err(Error::NoRecordFound);
            };

            let now = Instant::now();
            let server = Arc::from(self.base_url.host_str().unwrap_or("<unknown server>"));
            let soource = Source::Http { server };

            use crate::core::parser::record;
            self.cached_records
                .retain(|_host, Record { expire, .. }| *expire < now);
            if let Some(record) = self.cached_records.get(domain) {
                let endpoint_addrs: Vec<_> = record
                    .addrs
                    .iter()
                    .map(|endpoint: &EndpointAddr| (soource.clone(), *endpoint))
                    .collect();
                return Ok(stream::iter(endpoint_addrs).boxed());
            }
            let response = self
                .http_client
                .get(lookup_url(&self.base_url, domain))
                .send()
                .await;

            let response = response?.error_for_status()?.bytes().await?;
            let (remain, multi) =
                be_multi_response(response.as_ref()).map_err(|_| Error::ParseMultiResponse)?;
            if !remain.is_empty() {
                return Err(Error::ParseMultiResponse);
            }

            let mut addrs = Vec::new();
            for r in multi.records {
                if !r.signature_fields.is_empty() {
                    match r.signature_fields.verify(&r.dns, &r.cert) {
                        Ok(true) => {}
                        Ok(false) => {
                            tracing::debug!("ignored record with invalid DNS packet signature");
                            continue;
                        }
                        Err(error) => {
                            tracing::debug!(error = %snafu::Report::from_error(&error), "ignored record with malformed DNS packet signature");
                            continue;
                        }
                    }
                }
                let (_remain, packet) =
                    be_packet(&r.dns).map_err(|source| Error::ParseRecords {
                        source: source.to_owned(),
                    })?;

                addrs.extend(
                    packet
                        .answers
                        .iter()
                        .filter_map(|answer| match answer.data() {
                            record::RData::E(ep) => {
                                if answer.name() != domain {
                                    tracing::debug!(
                                        answer_name = %answer.name(),
                                        query = domain,
                                        "ignored endpoint answer for different name"
                                    );
                                    return None;
                                }
                                let endpoint =
                                    TryInto::<EndpointAddr>::try_into(ep.clone()).ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_publish_url_targets_v2_api_from_origin_base() {
        let base_url = Url::parse("https://dns.example.test").expect("url");
        let url = publish_url(&base_url, "demo.dhttp.net");

        assert_eq!(
            url.as_str(),
            "https://dns.example.test/api/v2/publish?host=demo.dhttp.net"
        );
    }

    #[test]
    fn http_lookup_url_does_not_duplicate_v2_base_path() {
        let base_url = Url::parse("https://dns.example.test/api/v2/").expect("url");
        let url = lookup_url(&base_url, "demo.dhttp.net");

        assert_eq!(
            url.as_str(),
            "https://dns.example.test/api/v2/lookup?host=demo.dhttp.net"
        );
    }
}
