use std::{fmt, io, sync::Arc, time::Duration};

use bytes::BytesMut;
use dashmap::DashMap;
use futures::{FutureExt, StreamExt};
use qresolve::{Family, RecordStream, Resolve, ResolveFuture, Source};
use reqwest::Client;
use tokio::time::Instant;
use url::Url;

pub use crate::api::{InvalidServerOrigin, LookupDecodeError};
use crate::{
    api::{LookupSemanticError, MAX_LOOKUP_RESPONSE_BYTES},
    resolvers::endpoint_candidates::{
        EndpointCandidates, EndpointLookup, ResolveEndpointCandidates,
    },
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(9);

#[derive(Debug, snafu::Snafu)]
#[snafu(module(build_http_resolver_error))]
#[non_exhaustive]
pub enum BuildHttpResolverError {
    #[snafu(display("invalid HTTP DNS server origin"))]
    InvalidOrigin { source: InvalidServerOrigin },
    #[snafu(display("no usable system trust roots"))]
    NoUsableTrustRoots,
    #[snafu(display("failed to build HTTP DNS client"))]
    BuildClient { source: reqwest::Error },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(http_lookup_error))]
#[non_exhaustive]
pub enum HttpLookupError {
    #[snafu(display("HTTP DNS request failed"))]
    Request { source: reqwest::Error },
    #[snafu(display("HTTP DNS request timed out after {timeout:?}"))]
    Timeout { timeout: Duration },
    #[snafu(display("HTTP DNS response exceeds {limit} bytes"))]
    ResponseTooLarge { limit: usize },
    #[snafu(display("HTTP DNS server returned {status}"))]
    Status { status: http::StatusCode },
    #[snafu(display("failed to decode HTTP DNS response"))]
    Decode { source: LookupDecodeError },
    #[snafu(display("no DNS record found"))]
    NoRecordFound,
    #[snafu(display("HTTP DNS response contained no usable records"))]
    NoUsableRecord,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CacheKey {
    name: String,
    lookup: EndpointLookup,
}

#[derive(Clone, Debug)]
struct CachedAnswer {
    candidates: Arc<EndpointCandidates>,
    expires_at: Instant,
}

pub struct HttpResolver {
    server_origin: Url,
    client: Client,
    cache: DashMap<CacheKey, CachedAnswer>,
}

impl fmt::Debug for HttpResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResolver")
            .field("server_origin", &self.server_origin)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for HttpResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP DNS Resolver({})", self.server_origin)
    }
}

impl HttpResolver {
    pub fn new(server_origin: Url) -> Result<Self, BuildHttpResolverError> {
        crate::api::validate_server_origin(&server_origin, false)
            .map_err(|source| BuildHttpResolverError::InvalidOrigin { source })?;
        Ok(Self {
            server_origin,
            client: build_http_client()?,
            cache: DashMap::new(),
        })
    }

    pub async fn lookup(
        &self,
        hostname: &str,
        _servname: &str,
        family: Option<Family>,
    ) -> Result<RecordStream, HttpLookupError> {
        let candidates = self
            .lookup_candidates(hostname, EndpointLookup::default().with_family(family))
            .await?;
        let source = self.source();
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

    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    fn source(&self) -> Source {
        Source::Http {
            server: Arc::from(self.server_origin.origin().ascii_serialization()),
        }
    }

    async fn lookup_candidates(
        &self,
        name: &str,
        requested: EndpointLookup,
    ) -> Result<EndpointCandidates, HttpLookupError> {
        let (name, legacy_sequence) = crate::resolvers::endpoint_lookup_name_and_sequence(name)
            .ok_or(HttpLookupError::NoRecordFound)?;
        let lookup = crate::api::exact_override(requested, legacy_sequence);
        let key = CacheKey {
            name: name.trim_end_matches('.').to_ascii_lowercase(),
            lookup,
        };
        if let Some(answer) = self.cache.get(&key) {
            if answer.expires_at > Instant::now() {
                return Ok((*answer.candidates).clone());
            }
            drop(answer);
            self.cache.remove(&key);
        }

        let url = crate::api::lookup_url(&self.server_origin, name, lookup);
        let (headers, body) = tokio::time::timeout(REQUEST_TIMEOUT, self.fetch(url))
            .await
            .map_err(|_| HttpLookupError::Timeout {
                timeout: REQUEST_TIMEOUT,
            })??;
        let answer =
            crate::api::decode_lookup_response(name, lookup, self.source(), &headers, &body)
                .map_err(map_semantic_error)?;
        let candidates = Arc::new(answer.candidates);
        if !answer.ttl.is_zero() {
            self.cache.insert(
                key,
                CachedAnswer {
                    candidates: candidates.clone(),
                    expires_at: Instant::now() + answer.ttl,
                },
            );
        }
        Ok((*candidates).clone())
    }

    async fn fetch(&self, url: Url) -> Result<(http::HeaderMap, bytes::Bytes), HttpLookupError> {
        let mut response =
            self.client
                .get(url)
                .send()
                .await
                .map_err(|source| HttpLookupError::Request {
                    source: source.without_url(),
                })?;
        match response.status() {
            http::StatusCode::OK => {}
            http::StatusCode::NOT_FOUND => return Err(HttpLookupError::NoRecordFound),
            status => return Err(HttpLookupError::Status { status }),
        }
        let headers = response.headers().clone();
        let mut body = BytesMut::new();
        while let Some(chunk) =
            response
                .chunk()
                .await
                .map_err(|source| HttpLookupError::Request {
                    source: source.without_url(),
                })?
        {
            if chunk.len() > MAX_LOOKUP_RESPONSE_BYTES.saturating_sub(body.len()) {
                return Err(HttpLookupError::ResponseTooLarge {
                    limit: MAX_LOOKUP_RESPONSE_BYTES,
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok((headers, body.freeze()))
    }
}

fn map_semantic_error(error: LookupSemanticError) -> HttpLookupError {
    match error {
        LookupSemanticError::Decode(source) => HttpLookupError::Decode { source },
        LookupSemanticError::NoRecordFound => HttpLookupError::NoRecordFound,
        LookupSemanticError::NoUsableRecord => HttpLookupError::NoUsableRecord,
    }
}

fn build_http_client() -> Result<Client, BuildHttpResolverError> {
    let native = rustls_native_certs::load_native_certs();
    for error in native.errors {
        tracing::warn!(%error, "failed to load a native root certificate");
    }
    let mut roots = rustls::RootCertStore::empty();
    let (valid, invalid) = roots.add_parsable_certificates(native.certs);
    tracing::debug!(valid, invalid, "loaded native root certificates");
    if valid == 0 {
        return Err(BuildHttpResolverError::NoUsableTrustRoots);
    }
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Client::builder()
        .use_preconfigured_tls(tls)
        .build()
        .map_err(|source| BuildHttpResolverError::BuildClient { source })
}

impl Resolve for HttpResolver {
    fn lookup<'a>(
        &'a self,
        hostname: &'a str,
        servname: &'a str,
        family: Option<Family>,
    ) -> ResolveFuture<'a> {
        async move {
            HttpResolver::lookup(self, hostname, servname, family)
                .await
                .map_err(io::Error::other)
        }
        .boxed()
    }
}

impl ResolveEndpointCandidates for HttpResolver {
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
    fn rejects_non_origin_url_before_building_client() {
        let error =
            HttpResolver::new(url::Url::parse("https://dns.example/api").unwrap()).unwrap_err();
        assert!(matches!(
            error,
            BuildHttpResolverError::InvalidOrigin { .. }
        ));
    }
}
