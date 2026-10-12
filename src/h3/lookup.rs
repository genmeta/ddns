use std::{io, sync::Arc};

use futures::StreamExt;
use qresolve::{Family, RecordStream, Source};

use super::{
    H3LookupError, H3Resolver, LOOKUP_REQUEST_ATTEMPTS, LOOKUP_REQUEST_TIMEOUT, ReadBodyError,
    cache::LookupKey, read_body_limited,
};
use crate::{
    api::{LookupSemanticError, MAX_LOOKUP_RESPONSE_BYTES},
    resolvers::endpoint_candidates::{
        EndpointCandidates, EndpointLookup, ResolveEndpointCandidates,
    },
};

impl H3Resolver {
    pub async fn lookup(
        &self,
        hostname: &str,
        _servname: &str,
        family: Option<Family>,
    ) -> Result<RecordStream, H3LookupError> {
        let host = hostname
            .rsplit_once(':')
            .filter(|(host, suffix)| {
                !host.contains(':')
                    && !suffix.is_empty()
                    && suffix.bytes().all(|b| b.is_ascii_digit())
            })
            .map_or(hostname, |(host, _)| host)
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if host != "dhttp.net" && !host.ends_with(".dhttp.net") {
            return Err(H3LookupError::NoRecordFound);
        }
        let candidates = self
            .lookup_candidates(hostname, EndpointLookup::default().with_family(family))
            .await?;
        let source = Source::H3 {
            server: Arc::from(self.server_origin.origin().ascii_serialization()),
        };
        Ok(
            futures::stream::iter(candidates.groups.into_iter().flat_map(move |group| {
                let source = source.clone();
                group
                    .endpoints
                    .into_iter()
                    .map(move |endpoint| (source.clone(), endpoint))
            }))
            .boxed(),
        )
    }

    async fn lookup_candidates(
        &self,
        name: &str,
        requested: EndpointLookup,
    ) -> Result<EndpointCandidates, H3LookupError> {
        let (name, legacy_sequence) = crate::resolvers::endpoint_lookup_name_and_sequence(name)
            .ok_or(H3LookupError::InvalidName)?;
        // The global dhttp resolver can call us while bootstrapping our own origin.
        // Let the other registered sources resolve it instead of recursively sending H3.
        if self.server_origin.host_str().is_some_and(|host| {
            host.trim_end_matches('.')
                .eq_ignore_ascii_case(name.trim_end_matches('.'))
        }) {
            return Err(H3LookupError::NoRecordFound);
        }
        let endpoint = self.endpoint.as_ref();
        let lookup = crate::api::exact_override(requested, legacy_sequence);
        let key = LookupKey::new(name, lookup);
        if let Some(cached) = self.cache.get(&key) {
            return Ok((*cached).clone());
        }

        let url = crate::api::lookup_url(&self.server_origin, name, lookup);
        tracing::debug!(host = name, %url, named = endpoint.is_some(), "H3 DNS lookup started");
        let (headers, body) =
            lookup_response_with_retry(endpoint, &url)
                .await
                .map_err(|error| {
                    tracing::debug!(host = name, %url, %error, "H3 DNS lookup failed");
                    error
                })?;
        let source = Source::H3 {
            server: Arc::from(self.server_origin.origin().ascii_serialization()),
        };
        let answer = crate::api::decode_lookup_response(name, lookup, source, &headers, &body)
            .map_err(map_semantic_error)
            .map_err(|error| {
                tracing::debug!(host = name, %url, %error, bytes = body.len(), "H3 DNS lookup response rejected");
                error
            })?;
        let candidates = Arc::new(answer.candidates);
        self.cache.insert(key, candidates.clone(), answer.ttl);
        Ok((*candidates).clone())
    }
}

fn map_semantic_error(error: LookupSemanticError) -> H3LookupError {
    match error {
        LookupSemanticError::Decode(source) => H3LookupError::Decode { source },
        LookupSemanticError::NoRecordFound => H3LookupError::NoRecordFound,
        LookupSemanticError::NoUsableRecord => H3LookupError::NoUsableRecord,
    }
}

async fn lookup_response_with_retry(
    endpoint: Option<&dhttp::Endpoint>,
    url: &url::Url,
) -> Result<(http::HeaderMap, bytes::Bytes), H3LookupError> {
    for attempt in 1..=LOOKUP_REQUEST_ATTEMPTS {
        match tokio::time::timeout(LOOKUP_REQUEST_TIMEOUT, lookup_response(endpoint, url)).await {
            Ok(Ok(response)) => return Ok(response),
            Ok(Err(error))
                if matches!(
                    error,
                    H3LookupError::Request { .. } | H3LookupError::Body { .. }
                ) && attempt < LOOKUP_REQUEST_ATTEMPTS =>
            {
                tracing::debug!(attempt, %error, "H3 DNS lookup failed; retrying");
            }
            Ok(Err(error)) => return Err(error),
            Err(_) if attempt < LOOKUP_REQUEST_ATTEMPTS => {
                tracing::debug!(attempt, "H3 DNS lookup timed out; retrying");
            }
            Err(_) => {
                return Err(H3LookupError::Timeout {
                    timeout: LOOKUP_REQUEST_TIMEOUT,
                    attempts: LOOKUP_REQUEST_ATTEMPTS,
                });
            }
        }
    }
    unreachable!("the final lookup attempt returns")
}

async fn lookup_response(
    endpoint: Option<&dhttp::Endpoint>,
    url: &url::Url,
) -> Result<(http::HeaderMap, bytes::Bytes), H3LookupError> {
    let uri = url.as_str().parse().expect("validated HTTPS URL is a URI");
    let request = match endpoint {
        Some(endpoint) => endpoint.get(uri),
        None => dhttp::Anonymous.get(uri),
    };
    let response = request
        .await
        .map_err(|source| H3LookupError::Request { source })?;
    tracing::debug!(%url, status = %response.status(), headers = ?response.headers(), "H3 DNS lookup response");
    match response.status() {
        http::StatusCode::OK => {}
        http::StatusCode::NOT_FOUND => return Err(H3LookupError::NoRecordFound),
        status => return Err(H3LookupError::Status { status }),
    }
    let (parts, body) = response.into_parts();
    let body = read_body_limited(body, MAX_LOOKUP_RESPONSE_BYTES)
        .await
        .map_err(|error| match error {
            ReadBodyError::Body(source) => H3LookupError::Body { source },
            ReadBodyError::TooLarge => H3LookupError::ResponseTooLarge {
                limit: MAX_LOOKUP_RESPONSE_BYTES,
            },
        })?;
    Ok((parts.headers, body))
}

impl ResolveEndpointCandidates for H3Resolver {
    fn lookup_endpoint_candidates<'a>(
        &'a self,
        name: &'a str,
        lookup: EndpointLookup,
    ) -> crate::resolvers::endpoint_candidates::EndpointCandidateFuture<'a> {
        Box::pin(async move {
            self.lookup_candidates(name, lookup)
                .await
                .map_err(io::Error::other)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_url_encodes_exact_sequence() {
        let lookup = EndpointLookup::exact(dhttp_home::certificate::CertificateSequence::from(1u8));
        assert_eq!(
            crate::api::lookup_url(
                &url::Url::parse("https://dns.example/").unwrap(),
                "demo.dhttp.net",
                lookup,
            )
            .as_str(),
            "https://dns.example/api/v2/lookup?host=demo.dhttp.net&sequence=1"
        );
    }
}
