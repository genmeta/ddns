use std::{sync::Arc, time::Duration};

use dquic::{
    qbase::net::addr::EndpointAddr,
    qresolve::{RecordStream, Source},
};
use futures::{StreamExt, stream};
use h3x::quic;
use tokio::time::Instant;
use tracing::trace;

use super::{Error, H3Resolver, Record};
use crate::core::{parser::packet::be_packet, wire::be_multi_response};

impl<C> H3Resolver<C>
where
    C: quic::Connect + quic::WithLocalAuthority + Send + Sync + 'static,
    C::Error: Send + Sync + 'static,
    C::Connection: Send + 'static,
{
    pub async fn lookup(&self, name: &str) -> Result<RecordStream, Error<C::Error>> {
        use crate::core::parser::record;
        let server = Arc::from(self.base_url.origin().ascii_serialization());
        let source = Source::H3 { server };

        let Some(domain) = crate::resolvers::resolvable_name(name) else {
            return Err(Error::NoRecordFound);
        };

        let now = Instant::now();
        let positive_ttl = Duration::from_secs(10);
        let negative_ttl = Duration::from_secs(2);

        self.cached_records
            .retain(|_host, record| record.expire > now);
        self.negative_cache.retain(|_host, expire| *expire > now);

        if self.negative_cache.get(domain).is_some() {
            return Err(Error::NoRecordFound);
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
            Err(Error::NoRecordFound) => {
                self.negative_cache
                    .insert(domain.to_string(), now + negative_ttl);
                return Err(Error::NoRecordFound);
            }
            Err(error) => return Err(error),
        };

        // Server always returns multi-record format.
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

            let (_remain, packet) = be_packet(&r.dns).map_err(|source| Error::ParseRecords {
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
            return Err(Error::NoRecordFound);
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
