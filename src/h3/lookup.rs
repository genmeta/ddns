use std::{io, sync::Arc};

use dhttp_identity::certificate::CertificateSequence;
use dquic::qresolve::{RecordStream, Source};
use futures::{StreamExt, stream};
use h3x::quic;
use http_body_util::BodyExt;
use snafu::{IntoError, ResultExt};
use tokio::time::Instant;

use super::{
    H3LookupError, H3Resolver, LOOKUP_REQUEST_ATTEMPTS, LOOKUP_REQUEST_TIMEOUT, LookupDecodeError,
    h3_lookup_error, lookup_decode_error,
};
use crate::{
    core::{parser::packet::be_packet, wire::be_multi_response},
    resolvers::endpoint_candidates::{
        EndpointCandidateGroup, EndpointCandidates, ResolveEndpointCandidates,
    },
};

const LOOKUP_API_PATH: &str = "/api/v2/lookup";

fn lookup_url(base_url: &url::Url, name: &str, sequence: Option<CertificateSequence>) -> url::Url {
    let mut url = base_url
        .join(LOOKUP_API_PATH)
        .expect("h3 dns lookup api path must be valid");
    url.query_pairs_mut().append_pair("host", name);
    if let Some(sequence) = sequence {
        let sequence_text = sequence.get().to_string();
        url.query_pairs_mut()
            .append_pair("sequence", &sequence_text);
    }
    url
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LookupRecords {
    pub(super) endpoints: Vec<dquic::qbase::net::addr::EndpointAddr>,
}

impl LookupRecords {
    pub(super) fn decode_candidate_groups(
        domain: &str,
        response: &[u8],
    ) -> Result<crate::resolvers::endpoint_candidates::EndpointCandidateGroups<()>, LookupDecodeError>
    {
        use crate::core::parser::record;

        let (remain, multi) = match be_multi_response(response) {
            Ok(response) => response,
            Err(_error) => return Err(LookupDecodeError::MultiResponse),
        };
        if !remain.is_empty() {
            return Err(LookupDecodeError::MultiResponse);
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
                        tracing::debug!(
                            error = %snafu::Report::from_error(&error),
                            "ignored record with malformed DNS packet signature"
                        );
                        continue;
                    }
                }
            }

            let (_remain, packet) = match be_packet(&r.dns) {
                Ok(packet) => packet,
                Err(source) => {
                    return Err(
                        lookup_decode_error::ParseRecordsSnafu.into_error(source.to_owned())
                    );
                }
            };

            endpoint_records.extend(packet.answers.iter().filter_map(
                |answer| match answer.data() {
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
                },
            ));
        }

        Ok(crate::resolvers::endpoint_candidates::grouped_endpoint_candidates(endpoint_records))
    }

    pub(super) fn decode(
        domain: &str,
        sequence: Option<CertificateSequence>,
        response: &[u8],
    ) -> Result<Self, LookupDecodeError> {
        let groups = Self::decode_candidate_groups(domain, response)?;
        let endpoints = match sequence {
            Some(sequence) => groups
                .into_iter()
                .find(|(chain_key, _)| {
                    chain_key.kind() == dhttp_identity::certificate::CertificateChainKind::Primary
                        && chain_key.sequence() == sequence
                })
                .map(|(_, endpoints)| endpoints)
                .unwrap_or_default(),
            None => groups
                .into_iter()
                .next()
                .map(|(_, endpoints)| endpoints)
                .unwrap_or_default(),
        };

        Ok(Self {
            endpoints: endpoints
                .into_iter()
                .map(|((), endpoint)| endpoint)
                .collect(),
        })
    }
}

impl<C> H3Resolver<C>
where
    C: quic::Connect + quic::WithLocalAuthority + Send + Sync + 'static,
    C::Error: Send + Sync + 'static,
    C::Connection: Send + 'static,
{
    pub(super) fn retryable_lookup_error(error: &H3LookupError<C::Error>) -> bool {
        matches!(
            error,
            H3LookupError::Request { .. } | H3LookupError::H3Stream { .. }
        )
    }

    pub(super) async fn lookup_response(
        &self,
        uri: http::Uri,
    ) -> Result<bytes::Bytes, H3LookupError<C::Error>> {
        let request = http::Request::get(uri)
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .expect("h3 dns lookup request must be valid");
        let resp = self.execute_request(request).await?;

        tracing::trace!("received response with status {}", resp.status());
        match resp.status() {
            http::StatusCode::OK => {}
            http::StatusCode::NOT_FOUND => return Err(H3LookupError::NoRecordFound),
            status => return Err(H3LookupError::Status { status }),
        }

        match resp.into_body().collect().await {
            Ok(response) => Ok(response.to_bytes()),
            Err(source) => Err(H3LookupError::H3Stream { source }),
        }
    }

    pub(super) async fn lookup_response_with_retry(
        &self,
        uri: http::Uri,
    ) -> Result<bytes::Bytes, H3LookupError<C::Error>> {
        for attempt in 1..=LOOKUP_REQUEST_ATTEMPTS {
            match tokio::time::timeout(LOOKUP_REQUEST_TIMEOUT, self.lookup_response(uri.clone()))
                .await
            {
                Ok(Ok(response)) => return Ok(response),
                Ok(Err(error))
                    if Self::retryable_lookup_error(&error)
                        && attempt < LOOKUP_REQUEST_ATTEMPTS =>
                {
                    self.endpoint.clear_pool();
                    tracing::debug!(
                        attempt,
                        timeout_ms = LOOKUP_REQUEST_TIMEOUT.as_millis(),
                        "h3 dns lookup failed, retrying"
                    );
                }
                Ok(Err(error)) => return Err(error),
                Err(_elapsed) if attempt < LOOKUP_REQUEST_ATTEMPTS => {
                    // A lookup timeout cancels only this request future. It is
                    // not proof that the shared endpoint pool is stale, and
                    // clearing the pool here can drop an in-flight connection
                    // attempt that concurrent lookups are waiting on.
                    tracing::debug!(
                        attempt,
                        timeout_ms = LOOKUP_REQUEST_TIMEOUT.as_millis(),
                        "h3 dns lookup timed out, retrying"
                    );
                }
                Err(_elapsed) => {
                    return Err(H3LookupError::RequestTimeout {
                        timeout: LOOKUP_REQUEST_TIMEOUT,
                    });
                }
            }
        }

        unreachable!("lookup retry loop returns on the final attempt")
    }

    pub async fn lookup(&self, name: &str) -> Result<RecordStream, H3LookupError<C::Error>> {
        let server = Arc::from(self.base_url.origin().ascii_serialization());
        let source = Source::H3 { server };

        let Some((domain, sequence)) = crate::resolvers::endpoint_lookup_name_and_sequence(name)
        else {
            return Err(H3LookupError::NoRecordFound);
        };

        let now = Instant::now();
        self.cache.prune_expired(now);

        if self.cache.negative_hit(name) {
            return Err(H3LookupError::NoRecordFound);
        }

        if let Some(addrs) = self.cache.positive_hit(name) {
            let stream = stream::iter(addrs.into_iter().map(move |ep| (source.clone(), ep)));
            return Ok(stream.boxed());
        }

        let url = lookup_url(&self.base_url, domain, sequence);
        let uri: http::Uri = url.as_str().parse().expect("URL should be valid URI");

        tracing::trace!("sending lookup request to {}", self.base_url);
        let response = match self.lookup_response_with_retry(uri).await {
            Ok(response) => response,
            Err(H3LookupError::NoRecordFound) => {
                self.cache.insert_negative(name);
                return Err(H3LookupError::NoRecordFound);
            }
            Err(error) => return Err(error),
        };

        let records = LookupRecords::decode(domain, sequence, response.as_ref())
            .context(h3_lookup_error::DecodeSnafu)?;
        let addrs = records.endpoints;

        if addrs.is_empty() {
            self.cache.insert_negative(name);
            return Err(H3LookupError::NoRecordFound);
        }

        self.cache.insert_positive(name, addrs.clone());

        Ok(stream::iter(addrs.into_iter().map(move |ep| (source.clone(), ep))).boxed())
    }
}

impl<C> ResolveEndpointCandidates for H3Resolver<C>
where
    C: quic::Connect + quic::WithLocalAuthority + Send + Sync + 'static,
    C::Error: Send + Sync + 'static,
    C::Connection: Send + 'static,
{
    fn lookup_endpoint_candidates<'a>(
        &'a self,
        name: &'a str,
    ) -> crate::resolvers::endpoint_candidates::EndpointCandidateFuture<'a> {
        Box::pin(async move {
            let Some((domain, _sequence)) =
                crate::resolvers::endpoint_lookup_name_and_sequence(name)
            else {
                return Err(io::Error::other("no DNS record found"));
            };

            let url = lookup_url(&self.base_url, domain, None);
            let uri: http::Uri = url.as_str().parse().expect("URL should be valid URI");
            let response = self
                .lookup_response_with_retry(uri)
                .await
                .map_err(io::Error::other)?;
            let source = Source::H3 {
                server: Arc::from(self.base_url.origin().ascii_serialization()),
            };
            let groups = LookupRecords::decode_candidate_groups(domain, response.as_ref())
                .map_err(io::Error::other)?
                .into_iter()
                .map(|(chain, endpoints)| EndpointCandidateGroup {
                    chain,
                    endpoints: endpoints
                        .into_iter()
                        .map(|((), endpoint)| endpoint)
                        .collect(),
                    sources: vec![source.clone()],
                })
                .collect();

            Ok(EndpointCandidates { groups })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, net::SocketAddrV4};

    use super::*;
    use crate::core::{
        MdnsPacket,
        parser::record::endpoint::EndpointAddr as DnsEndpointAddr,
        wire::{MultiResponse, ResponseRecord},
    };

    fn direct(addr: &str, main: bool, sequence: u32) -> DnsEndpointAddr {
        let socket: SocketAddrV4 = addr.parse().expect("socket addr");
        let mut endpoint = DnsEndpointAddr::direct_v4(socket);
        endpoint.set_main(main);
        endpoint.set_sequence(
            dhttp_identity::certificate::CertificateSequence::try_from(sequence).unwrap(),
        );
        endpoint
    }

    fn response_for(name: &str, endpoints: Vec<DnsEndpointAddr>) -> Vec<u8> {
        let mut hosts = HashMap::new();
        hosts.insert(name.to_owned(), endpoints);
        let packet = MdnsPacket::answer(0, &hosts).to_bytes();
        MultiResponse::new([ResponseRecord::unsigned(packet, Vec::new())]).encode()
    }

    #[test]
    fn lookup_records_decode_candidate_groups_returns_all_primary_sequences() {
        let response = response_for(
            "demo.dhttp.net",
            vec![
                direct("192.0.2.10:4433", true, 0),
                direct("192.0.2.20:4433", true, 1),
                direct("192.0.2.21:4433", true, 1),
            ],
        );

        let groups = LookupRecords::decode_candidate_groups("demo.dhttp.net", response.as_ref())
            .expect("candidate groups decode");

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].0.to_string(), "primary:0");
        assert_eq!(groups[0].1.len(), 1);
        assert_eq!(groups[1].0.to_string(), "primary:1");
        assert_eq!(groups[1].1.len(), 2);
    }

    #[test]
    fn h3_lookup_url_targets_v2_api_from_origin_base() {
        let base_url = url::Url::parse("https://dns.example.test:4433").expect("url");
        let url = lookup_url(&base_url, "demo.dhttp.net", None);

        assert_eq!(
            url.as_str(),
            "https://dns.example.test:4433/api/v2/lookup?host=demo.dhttp.net"
        );
    }

    #[test]
    fn h3_lookup_url_does_not_duplicate_v2_base_path() {
        let base_url = url::Url::parse("https://dns.example.test:4433/api/v2/").expect("url");
        let url = lookup_url(&base_url, "demo.dhttp.net", None);

        assert_eq!(
            url.as_str(),
            "https://dns.example.test:4433/api/v2/lookup?host=demo.dhttp.net"
        );
    }

    #[test]
    fn h3_lookup_url_appends_sequence_query() {
        let base_url = url::Url::parse("https://dns.example.test:4433").expect("url");
        let url = lookup_url(
            &base_url,
            "demo.dhttp.net",
            Some(CertificateSequence::from(3u8)),
        );

        assert_eq!(
            url.as_str(),
            "https://dns.example.test:4433/api/v2/lookup?host=demo.dhttp.net&sequence=3"
        );
    }

    #[test]
    fn lookup_records_selects_first_server_ordered_group() {
        let response = response_for(
            "demo.dhttp.net",
            vec![
                direct("192.0.2.10:4433", true, 2),
                direct("192.0.2.11:4433", true, 2),
                direct("192.0.2.30:4433", true, 3),
                direct("192.0.2.20:4433", false, 1),
            ],
        );

        let records = LookupRecords::decode("demo.dhttp.net", None, &response).expect("records");

        assert_eq!(records.endpoints.len(), 2);
        assert_eq!(
            records.endpoints[0],
            dquic::qbase::net::addr::EndpointAddr::direct("192.0.2.10:4433".parse().unwrap())
        );
        assert_eq!(
            records.endpoints[1],
            dquic::qbase::net::addr::EndpointAddr::direct("192.0.2.11:4433".parse().unwrap())
        );
    }

    #[test]
    fn lookup_records_ignore_answer_name_mismatch() {
        let response = response_for("other.dhttp.net", vec![direct("192.0.2.50:4433", true, 1)]);

        let records = LookupRecords::decode("demo.dhttp.net", None, &response).expect("records");

        assert!(records.endpoints.is_empty());
    }

    #[test]
    fn lookup_records_filter_requested_primary_sequence() {
        let response = response_for(
            "demo.dhttp.net",
            vec![
                direct("192.0.2.10:4433", true, 0),
                direct("192.0.2.11:4433", true, 0),
                direct("192.0.2.20:4433", true, 1),
            ],
        );

        let records = LookupRecords::decode(
            "demo.dhttp.net",
            Some(CertificateSequence::from(1u8)),
            &response,
        )
        .expect("records");

        assert_eq!(
            records.endpoints,
            vec![dquic::qbase::net::addr::EndpointAddr::direct(
                "192.0.2.20:4433".parse().unwrap()
            )]
        );
    }
}
