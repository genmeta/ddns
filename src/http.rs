use std::{fmt::Display, io, sync::Arc};

use dashmap::DashMap;
use dhttp_identity::certificate::CertificateSequence;
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

fn lookup_url(base_url: &Url, name: &str, sequence: Option<CertificateSequence>) -> Url {
    let mut url = api_url(base_url, LOOKUP_API_PATH, name);
    if let Some(sequence) = sequence {
        let sequence_text = sequence.get().to_string();
        url.query_pairs_mut()
            .append_pair("sequence", &sequence_text);
    }
    url
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
            "HTTP DNS Resolver({})",
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
        let response = request.body(packet.to_vec()).send().await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.bytes().await?;
            return Err(Error::Status {
                status,
                message: StatusBody::new(bounded_status_body(&body)),
            });
        }
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

fn dns_packet_for_http_publish(
    name: &str,
    endpoints: impl IntoIterator<Item = EndpointAddr>,
) -> io::Result<Vec<u8>> {
    let mut encoded = Vec::new();
    for endpoint in endpoints {
        let endpoint = crate::core::parser::record::endpoint::EndpointAddr::try_from(endpoint)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "failed to encode endpoint address",
                )
            })?;
        encoded.push(endpoint);
    }

    let mut hosts = std::collections::HashMap::new();
    hosts.insert(name.to_owned(), encoded);
    Ok(crate::core::MdnsPacket::answer(0, &hosts).to_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StatusBody(String);

impl StatusBody {
    fn new(body: String) -> Self {
        Self(body)
    }
}

impl std::fmt::Display for StatusBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            Ok(())
        } else {
            write!(f, ": {}", self.0)
        }
    }
}

const STATUS_BODY_LIMIT: usize = 4096;

fn bounded_status_body(body: &[u8]) -> String {
    let body = if body.len() > STATUS_BODY_LIMIT {
        &body[..STATUS_BODY_LIMIT]
    } else {
        body
    };
    String::from_utf8_lossy(body).trim().to_owned()
}

#[derive(Debug, snafu::Snafu)]
enum Error {
    #[snafu(display("http request failed"))]
    Reqwest { source: reqwest::Error },

    #[snafu(display("{status}{message}"))]
    Status {
        status: StatusCode,
        message: StatusBody,
    },

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
            Some(status) => Error::Status {
                status,
                message: StatusBody::new(String::new()),
            },
            None => Error::Reqwest {
                source: source.without_url(),
            },
        }
    }
}

impl Publish for HttpResolver {
    fn publish<'a>(
        &'a self,
        name: &'a str,
        endpoints: &mut dyn Iterator<Item = EndpointAddr>,
    ) -> PublishFuture<'a> {
        let endpoints: Vec<_> = endpoints.collect();
        Box::pin(async move {
            let packet = dns_packet_for_http_publish(name, endpoints)?;
            self.publish_packet_with_signature(name, &packet, &SignatureFields::empty())
                .await
                .map_err(io::Error::other)
        })
    }
}

fn decode_candidate_groups(
    domain: &str,
    response: &[u8],
) -> Result<crate::resolvers::endpoint_candidates::EndpointCandidateGroups<()>, Error> {
    use crate::core::parser::record;

    let (remain, multi) = be_multi_response(response).map_err(|_| Error::ParseMultiResponse)?;
    if !remain.is_empty() {
        return Err(Error::ParseMultiResponse);
    }

    let mut endpoint_records = Vec::new();
    for r in multi.records {
        let publisher_chain_key = r.publisher_certificate_chain_key();
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
        let (_remain, packet) = be_packet(&r.dns).map_err(|source| Error::ParseRecords {
            source: source.to_owned(),
        })?;

        endpoint_records.extend(
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
                        Some(
                            crate::resolvers::endpoint_candidates::TaggedEndpointCandidate {
                                tag: (),
                                record: ep.clone(),
                                fallback_chain_key: publisher_chain_key.clone(),
                            },
                        )
                    }
                    _ => {
                        tracing::debug!(?answer, "ignored record");
                        None
                    }
                }),
        );
    }

    Ok(crate::resolvers::endpoint_candidates::grouped_endpoint_candidates(endpoint_records))
}

impl Resolve for HttpResolver {
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
        let lookup = async move {
            let Some((domain, sequence)) =
                crate::resolvers::endpoint_lookup_name_and_sequence(name)
            else {
                return Err(Error::NoRecordFound);
            };

            let now = Instant::now();
            let server = Arc::from(self.base_url.host_str().unwrap_or("<unknown server>"));
            let source = Source::Http { server };

            self.cached_records
                .retain(|_host, Record { expire, .. }| *expire > now);
            if let Some(record) = self.cached_records.get(name) {
                let endpoint_addrs: Vec<_> = record
                    .addrs
                    .iter()
                    .map(|endpoint: &EndpointAddr| (source.clone(), *endpoint))
                    .collect();
                return Ok(stream::iter(endpoint_addrs).boxed());
            }

            let response = self
                .http_client
                .get(lookup_url(&self.base_url, domain, sequence))
                .send()
                .await?
                .error_for_status()?
                .bytes()
                .await?;

            let addrs = decode_candidate_groups(domain, response.as_ref())?
                .into_iter()
                .find(|(chain_key, _)| match sequence {
                    Some(sequence) => {
                        chain_key.kind()
                            == dhttp_identity::certificate::CertificateChainKind::Primary
                            && chain_key.sequence() == sequence
                    }
                    None => true,
                })
                .map(|(_, endpoints)| {
                    endpoints
                        .into_iter()
                        .map(|((), endpoint)| endpoint)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if addrs.is_empty() {
                return Err(Error::NoRecordFound);
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
        };
        Box::pin(lookup.map_err(io::Error::other))
    }
}

impl crate::resolvers::endpoint_candidates::ResolveEndpointCandidates for HttpResolver {
    fn lookup_endpoint_candidates<'a>(
        &'a self,
        name: &'a str,
    ) -> crate::resolvers::endpoint_candidates::EndpointCandidateFuture<'a> {
        let lookup = async move {
            let Some((domain, _sequence)) =
                crate::resolvers::endpoint_lookup_name_and_sequence(name)
            else {
                return Err(Error::NoRecordFound);
            };
            let server = Arc::from(self.base_url.host_str().unwrap_or("<unknown server>"));
            let source = Source::Http { server };
            let response = self
                .http_client
                .get(lookup_url(&self.base_url, domain, None))
                .send()
                .await?
                .error_for_status()?
                .bytes()
                .await?;
            let groups = decode_candidate_groups(domain, response.as_ref())?
                .into_iter()
                .map(|(chain, endpoints)| {
                    crate::resolvers::endpoint_candidates::EndpointCandidateGroup {
                        chain,
                        endpoints: endpoints
                            .into_iter()
                            .map(|((), endpoint)| endpoint)
                            .collect(),
                        sources: vec![source.clone()],
                    }
                })
                .collect();
            Ok(crate::resolvers::endpoint_candidates::EndpointCandidates { groups })
        };
        Box::pin(lookup.map_err(io::Error::other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct(
        addr: &str,
        main: bool,
        sequence: u32,
    ) -> crate::core::parser::record::endpoint::EndpointAddr {
        let socket: std::net::SocketAddrV4 = addr.parse().expect("socket addr");
        let mut endpoint = crate::core::parser::record::endpoint::EndpointAddr::direct_v4(socket);
        endpoint.set_main(main);
        endpoint.set_sequence(
            dhttp_identity::certificate::CertificateSequence::try_from(sequence).unwrap(),
        );
        endpoint
    }

    fn response_for(
        name: &str,
        endpoints: Vec<crate::core::parser::record::endpoint::EndpointAddr>,
    ) -> Vec<u8> {
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(name.to_owned(), endpoints);
        let packet = crate::core::MdnsPacket::answer(0, &hosts).to_bytes();
        crate::core::wire::MultiResponse::new([crate::core::wire::ResponseRecord::unsigned(
            packet,
            Vec::new(),
        )])
        .encode()
    }

    #[test]
    fn http_decode_candidate_groups_returns_all_primary_sequences() {
        let response = response_for(
            "demo.dhttp.net",
            vec![
                direct("192.0.2.10:4433", true, 0),
                direct("192.0.2.20:4433", true, 1),
            ],
        );

        let groups = decode_candidate_groups("demo.dhttp.net", response.as_ref())
            .expect("candidate groups decode");

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].0.to_string(), "primary:0");
        assert_eq!(groups[1].0.to_string(), "primary:1");
    }

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
        let url = lookup_url(&base_url, "demo.dhttp.net", None);

        assert_eq!(
            url.as_str(),
            "https://dns.example.test/api/v2/lookup?host=demo.dhttp.net"
        );
    }

    #[test]
    fn http_lookup_url_appends_sequence_query() {
        let base_url = Url::parse("https://dns.example.test").expect("url");
        let url = lookup_url(
            &base_url,
            "demo.dhttp.net",
            Some(CertificateSequence::from(7u8)),
        );

        assert_eq!(
            url.as_str(),
            "https://dns.example.test/api/v2/lookup?host=demo.dhttp.net&sequence=7"
        );
    }
}
