use std::{sync::Arc, time::Duration};

use dquic::{
    qbase::net::addr::EndpointAddr,
    qresolve::{RecordStream, Source},
};
use futures::{StreamExt, stream};
use h3x::quic;
use http_body_util::BodyExt;
use tokio::time::Instant;
use tracing::trace;

use super::{
    H3LookupError, H3Resolver, LOOKUP_REQUEST_ATTEMPTS, LOOKUP_REQUEST_TIMEOUT, LookupDecodeError,
    Record,
};
use crate::core::{parser::packet::be_packet, wire::be_multi_response};

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
        use crate::core::parser::record;
        let server = Arc::from(self.base_url.origin().ascii_serialization());
        let source = Source::H3 { server };

        let Some(domain) = crate::resolvers::resolvable_name(name) else {
            return Err(H3LookupError::NoRecordFound);
        };

        let now = Instant::now();
        let positive_ttl = Duration::from_secs(10);
        let negative_ttl = Duration::from_secs(2);

        self.cached_records
            .retain(|_host, record| record.expire > now);
        self.negative_cache.retain(|_host, expire| *expire > now);

        if self.negative_cache.get(domain).is_some() {
            return Err(H3LookupError::NoRecordFound);
        }

        if let Some(record) = self.cached_records.get(domain) {
            let addrs = record.addrs.clone();
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
                self.negative_cache
                    .insert(domain.to_string(), now + negative_ttl);
                return Err(H3LookupError::NoRecordFound);
            }
            Err(error) => return Err(error),
        };

        // Server always returns multi-record format.
        let (remain, multi) = match be_multi_response(response.as_ref()) {
            Ok(response) => response,
            Err(_error) => {
                return Err(H3LookupError::Decode {
                    source: LookupDecodeError::MultiResponse,
                });
            }
        };
        if !remain.is_empty() {
            return Err(H3LookupError::Decode {
                source: LookupDecodeError::MultiResponse,
            });
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

            let (_remain, packet) = match be_packet(&r.dns) {
                Ok(packet) => packet,
                Err(source) => {
                    return Err(H3LookupError::Decode {
                        source: LookupDecodeError::ParseRecords {
                            source: source.to_owned(),
                        },
                    });
                }
            };

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
                            let endpoint = TryInto::<EndpointAddr>::try_into(ep.clone()).ok()?;
                            trace!(?endpoint, "parsed endpoint from record");
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
            self.negative_cache
                .insert(domain.to_string(), now + negative_ttl);
            return Err(H3LookupError::NoRecordFound);
        }

        self.cached_records.insert(
            domain.to_string(),
            Record {
                addrs: addrs.clone(),
                expire: now + positive_ttl,
            },
        );

        self.negative_cache.remove(domain);

        Ok(stream::iter(addrs.into_iter().map(move |ep| (source.clone(), ep))).boxed())
    }
}
