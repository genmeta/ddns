use std::{collections::HashSet, time::Duration};

use qresolve::Source;
use url::Url;

use crate::resolvers::endpoint_candidates::{
    EndpointCandidateGroup, EndpointCandidates, EndpointLookup, TaggedEndpointCandidate,
};

pub(crate) const MAX_LOOKUP_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_RESPONSE_RECORDS: usize = 256;

#[derive(Debug, snafu::Snafu)]
#[snafu(module(invalid_server_origin))]
#[non_exhaustive]
pub enum InvalidServerOrigin {
    #[snafu(display("DNS server origin must use https"))]
    NotHttps,
    #[snafu(display("DNS server origin must include a host"))]
    MissingHost,
    #[snafu(display("DNS server origin must not include credentials"))]
    HasCredentials,
    #[snafu(display("DNS server origin must not include a path, query, or fragment"))]
    HasPathQueryOrFragment,
    #[snafu(display("H3 DNS server origin must be outside dhttp.net"))]
    DhttpOrigin,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(lookup_decode_error))]
#[non_exhaustive]
pub enum LookupDecodeError {
    #[snafu(display("multi-response contains more than {limit} records"))]
    TooManyRecords { limit: usize },
    #[snafu(display("invalid multi-record response"))]
    MultiResponse,
    #[snafu(display("failed to parse DNS records from response"))]
    ParseRecords {
        source: nom::Err<nom::error::Error<Vec<u8>>>,
    },
}

pub(crate) enum LookupSemanticError {
    Decode(LookupDecodeError),
    NoRecordFound,
    NoUsableRecord,
}

pub(crate) struct LookupAnswer {
    pub(crate) candidates: EndpointCandidates,
    pub(crate) ttl: Duration,
}

pub(crate) fn validate_server_origin(
    url: &Url,
    reject_dhttp: bool,
) -> Result<(), InvalidServerOrigin> {
    if url.scheme() != "https" {
        return Err(InvalidServerOrigin::NotHttps);
    }
    let host = url.host_str().ok_or(InvalidServerOrigin::MissingHost)?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(InvalidServerOrigin::HasCredentials);
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(InvalidServerOrigin::HasPathQueryOrFragment);
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if reject_dhttp && (host == "dhttp.net" || host.ends_with(".dhttp.net")) {
        return Err(InvalidServerOrigin::DhttpOrigin);
    }
    Ok(())
}

pub(crate) fn lookup_url(server_origin: &Url, name: &str, lookup: EndpointLookup) -> Url {
    let mut url = server_origin
        .join("/api/v2/lookup")
        .expect("fixed lookup path is a valid URL");
    url.query_pairs_mut().append_pair("host", name);
    crate::resolvers::endpoint_candidates::append_endpoint_lookup_query(&mut url, lookup);
    url
}

pub(crate) fn decode_lookup_response(
    name: &str,
    lookup: EndpointLookup,
    source: Source,
    headers: &http::HeaderMap,
    body: &[u8],
) -> Result<LookupAnswer, LookupSemanticError> {
    let (groups, rejected) =
        decode_candidate_groups(name, body).map_err(LookupSemanticError::Decode)?;
    let groups = crate::resolvers::endpoint_candidates::select_group_pairs(
        crate::resolvers::endpoint_candidates::filter_endpoint_candidate_groups(
            groups,
            lookup.family(),
        ),
        lookup.sequences(),
    );

    let mut ttl = None::<u32>;
    let mut candidates = Vec::new();
    for (chain, records) in groups {
        let mut seen = HashSet::new();
        let endpoints = records
            .into_iter()
            .filter(|(_, endpoint)| seen.insert(*endpoint))
            .take(
                lookup
                    .record_limit()
                    .map_or(usize::MAX, |limit| limit.get()),
            )
            .map(|(record_ttl, endpoint)| {
                ttl = Some(ttl.map_or(record_ttl, |current| current.min(record_ttl)));
                endpoint
            })
            .collect::<Vec<_>>();
        if !endpoints.is_empty() {
            candidates.push(EndpointCandidateGroup {
                chain,
                endpoints,
                sources: vec![source.clone()],
            });
        }
    }

    if candidates.is_empty() {
        return Err(if rejected == 0 {
            LookupSemanticError::NoRecordFound
        } else {
            LookupSemanticError::NoUsableRecord
        });
    }
    Ok(LookupAnswer {
        candidates: EndpointCandidates { groups: candidates },
        ttl: freshness(Duration::from_secs(u64::from(ttl.unwrap_or(0))), headers),
    })
}

fn decode_candidate_groups(
    name: &str,
    body: &[u8],
) -> Result<
    (
        crate::resolvers::endpoint_candidates::EndpointCandidateGroups<u32>,
        usize,
    ),
    LookupDecodeError,
> {
    if body.len() < 4 {
        return Err(LookupDecodeError::MultiResponse);
    }
    let count = u32::from_be_bytes(body[..4].try_into().expect("four checked bytes")) as usize;
    if count > MAX_RESPONSE_RECORDS {
        return Err(LookupDecodeError::TooManyRecords {
            limit: MAX_RESPONSE_RECORDS,
        });
    }
    let (remain, multi) =
        crate::core::wire::be_multi_response(body).map_err(|_| LookupDecodeError::MultiResponse)?;
    if !remain.is_empty() {
        return Err(LookupDecodeError::MultiResponse);
    }

    let mut rejected = 0;
    let mut endpoints = Vec::new();
    for response in multi.records {
        let fallback_chain_key = response.publisher_certificate_chain_key();
        if !response.signature_fields.is_empty()
            && !matches!(
                response
                    .signature_fields
                    .verify(&response.dns, &response.cert),
                Ok(true)
            )
        {
            rejected += 1;
            continue;
        }
        let (remain, packet) =
            crate::core::parser::packet::be_packet(&response.dns).map_err(|source| {
                LookupDecodeError::ParseRecords {
                    source: source.to_owned(),
                }
            })?;
        if !remain.is_empty() {
            return Err(LookupDecodeError::MultiResponse);
        }
        endpoints.extend(packet.answers.iter().filter_map(|answer| {
            let crate::core::parser::record::RData::E(record) = answer.data() else {
                return None;
            };
            (answer.name() == name).then(|| TaggedEndpointCandidate {
                tag: answer.ttl(),
                record: record.clone(),
                fallback_chain_key: fallback_chain_key.clone(),
            })
        }));
    }
    Ok((
        crate::resolvers::endpoint_candidates::grouped_endpoint_candidates(endpoints),
        rejected,
    ))
}

fn freshness(dns_ttl: Duration, headers: &http::HeaderMap) -> Duration {
    if headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|directive| {
            let name = directive.trim().split('=').next().unwrap_or("").trim();
            name.eq_ignore_ascii_case("no-store") || name.eq_ignore_ascii_case("no-cache")
        })
    {
        return Duration::ZERO;
    }
    let max_age = headers
        .get(http::header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value.split(',').find_map(|directive| {
                let (name, value) = directive.trim().split_once('=')?;
                name.eq_ignore_ascii_case("max-age")
                    .then(|| value.trim_matches('"').parse::<u64>().ok())
                    .flatten()
            })
        })
        .map(Duration::from_secs);
    let age = headers
        .get(http::header::AGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map_or(Duration::ZERO, Duration::from_secs);
    max_age
        .map_or(dns_ttl, |max_age| dns_ttl.min(max_age))
        .saturating_sub(age)
}

pub(crate) fn exact_override(
    lookup: EndpointLookup,
    sequence: Option<dhttp_home::certificate::CertificateSequence>,
) -> EndpointLookup {
    sequence.map_or(lookup, |sequence| {
        let mut exact = EndpointLookup::exact(sequence).with_family(lookup.family());
        if let Some(limit) = lookup.record_limit() {
            exact = exact.with_record_limit(limit);
        }
        exact
    })
}

#[cfg(test)]
mod freshness_tests {
    use super::*;
    #[test]
    fn no_store_and_no_cache_override_dns_ttl_and_every_cache_control_field() {
        for directive in ["no-store", "NO-CACHE", "no-cache=\"e-record\""] {
            let mut headers = http::HeaderMap::new();
            headers.insert(http::header::CACHE_CONTROL, "max-age=60".parse().unwrap());
            headers.append(http::header::CACHE_CONTROL, directive.parse().unwrap());
            assert_eq!(
                freshness(Duration::from_secs(300), &headers),
                Duration::ZERO
            );
        }
    }
    #[test]
    fn ordinary_freshness_still_uses_dns_http_and_age() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CACHE_CONTROL, "max-age=60".parse().unwrap());
        headers.insert(http::header::AGE, "10".parse().unwrap());
        assert_eq!(
            freshness(Duration::from_secs(300), &headers),
            Duration::from_secs(50)
        );
        assert_eq!(freshness(Duration::from_secs(5), &headers), Duration::ZERO);
    }
}
