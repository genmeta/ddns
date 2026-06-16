use std::sync::Arc;

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
use crate::core::{parser::packet::be_packet, wire::be_multi_response};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LookupRecords {
    pub(super) endpoints: Vec<dquic::qbase::net::addr::EndpointAddr>,
}

impl LookupRecords {
    pub(super) fn decode(domain: &str, response: &[u8]) -> Result<Self, LookupDecodeError> {
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
                        Some(ep.clone())
                    }
                    _ => {
                        tracing::debug!(?answer, "ignored record");
                        None
                    }
                },
            ));
        }

        Ok(Self {
            endpoints: crate::resolvers::selector::selected_endpoint_addrs(endpoint_records),
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
                    self.endpoint.clear_pool();
                    tracing::debug!(
                        attempt,
                        timeout_ms = LOOKUP_REQUEST_TIMEOUT.as_millis(),
                        "h3 dns lookup timed out, retrying"
                    );
                }
                Err(_elapsed) => {
                    self.endpoint.clear_pool();
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

        let Some(domain) = crate::resolvers::resolvable_name(name) else {
            return Err(H3LookupError::NoRecordFound);
        };

        let now = Instant::now();
        self.cache.prune_expired(now);

        if self.cache.negative_hit(domain) {
            return Err(H3LookupError::NoRecordFound);
        }

        if let Some(addrs) = self.cache.positive_hit(domain) {
            let stream = stream::iter(addrs.into_iter().map(move |ep| (source.clone(), ep)));
            return Ok(stream.boxed());
        }

        let mut url = self.base_url.join("lookup").expect("Invalid URL");
        url.set_query(Some(&format!("host={}", domain)));
        let uri: http::Uri = url.as_str().parse().expect("URL should be valid URI");

        tracing::trace!("sending lookup request to {}", self.base_url);
        let response = match self.lookup_response_with_retry(uri).await {
            Ok(response) => response,
            Err(H3LookupError::NoRecordFound) => {
                self.cache.insert_negative(domain);
                return Err(H3LookupError::NoRecordFound);
            }
            Err(error) => return Err(error),
        };

        let records = LookupRecords::decode(domain, response.as_ref())
            .context(h3_lookup_error::DecodeSnafu)?;
        let addrs = records.endpoints;

        if addrs.is_empty() {
            self.cache.insert_negative(domain);
            return Err(H3LookupError::NoRecordFound);
        }

        self.cache.insert_positive(domain, addrs.clone());

        Ok(stream::iter(addrs.into_iter().map(move |ep| (source.clone(), ep))).boxed())
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

    fn direct(addr: &str, main: bool, sequence: u64) -> DnsEndpointAddr {
        let socket: SocketAddrV4 = addr.parse().expect("socket addr");
        let mut endpoint = DnsEndpointAddr::direct_v4(socket);
        endpoint.set_main(main);
        endpoint.set_sequence(sequence);
        endpoint
    }

    fn response_for(name: &str, endpoints: Vec<DnsEndpointAddr>) -> Vec<u8> {
        let mut hosts = HashMap::new();
        hosts.insert(name.to_owned(), endpoints);
        let packet = MdnsPacket::answer(0, &hosts).to_bytes();
        MultiResponse::new([ResponseRecord::unsigned(packet, Vec::new())]).encode()
    }

    #[test]
    fn lookup_records_select_primary_group() {
        let response = response_for(
            "demo.dhttp.net",
            vec![
                direct("192.0.2.20:4433", false, 1),
                direct("192.0.2.10:4433", true, 2),
                direct("192.0.2.11:4433", true, 2),
                direct("192.0.2.30:4433", true, 3),
            ],
        );

        let records = LookupRecords::decode("demo.dhttp.net", &response).expect("records");

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

        let records = LookupRecords::decode("demo.dhttp.net", &response).expect("records");

        assert!(records.endpoints.is_empty());
    }
}
