use std::{convert::Infallible, sync::Arc};

use ddns::core::signature::{
    CONTENT_DIGEST_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER, SignatureFields,
};
use h3x::{connection::ConnectionState, quic};
use http_body_util::BodyExt;
use tracing::{debug, warn};

use super::store::{clear_record, publish_record};
use crate::{
    error::{AppError, normalize_host, parse_query_params},
    lookup::{Request, Response, write_error},
    policy::{DomainPolicy, ValidatedDnsPacket, client_allowed_host, validate_dns_packet},
    storage::AppState,
};

// ---------------------------------------------------------------------------
// PublishSvc
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct PublishSvc {
    pub state: AppState,
}

impl PublishSvc {
    pub fn call(
        &self,
        request: Request,
    ) -> impl Future<Output = Result<Response, Infallible>> + Send + 'static {
        let state = self.state.clone();
        async move { Ok(publish_with_cert(state, request).await) }
    }
}

async fn publish_with_cert(state: AppState, request: Request) -> Response {
    debug!("received publish request");

    let params = parse_query_params(request.uri());
    debug!("query params: {:?}", params);

    let Some(host) = params.get("host") else {
        warn!("missing host parameter");
        return write_error(AppError::MissingHostParam);
    };

    let host = match normalize_host(host, state.host_allowlist.as_ref()) {
        Ok(h) => h,
        Err(e) => return write_error(e),
    };
    debug!(host = %host, "publish.host");

    // Require a valid client certificate for all publish requests.
    let authority = match request_connection(&request) {
        Some(connection) => match connection.remote_authority().await {
            Ok(Some(authority)) => authority,
            Ok(None) => {
                warn!("missing client certificate");
                return write_error(AppError::MissingClientCertificate);
            }
            Err(error) => {
                warn!(error = %snafu::Report::from_error(&error), "failed to read client certificate");
                return write_error(AppError::MissingClientCertificate);
            }
        },
        None => {
            warn!("missing client certificate");
            return write_error(AppError::MissingClientCertificate);
        }
    };

    let policy = state.policies.policy_for(&host).clone();

    // Standard policy: cert SAN must match the target host.
    // OpenMulti policy: any authenticated node may publish — skip SAN check.
    if policy == DomainPolicy::Standard {
        let allowed = match client_allowed_host(authority.as_ref(), state.host_allowlist.as_ref()) {
            Ok(h) => h,
            Err(e) => {
                warn!(error = %snafu::Report::from_error(&e), "client certificate domain not allowed");
                return write_error(e);
            }
        };
        if allowed != host {
            warn!(allowed = %allowed, requested = %host, "publish.host_mismatch");
            return write_error(AppError::HostMismatch);
        }
    }

    let signature_fields = signature_fields_from_headers(request.headers());

    let body = match request.into_body().collect().await {
        Ok(body) => body.to_bytes(),
        Err(e) => {
            warn!(error = %snafu::Report::from_error(&e), "failed to read request body");
            return write_error(AppError::InvalidDnsPacket {
                message: e.to_string(),
            });
        }
    };

    // Validate DNS packet; signature check only for Standard hosts.
    let require_sig = policy == DomainPolicy::Standard && state.require_signature;
    debug!(
        host = %host,
        bytes = body.len(),
        require_signature = require_sig,
        "validating publish packet"
    );
    let packet = match validate_dns_packet(
        body.as_ref(),
        require_sig,
        authority.as_ref(),
        &signature_fields,
        state.host_allowlist.as_ref(),
        &host,
    ) {
        Ok(n) => n,
        Err(e) => {
            debug!(host = %host, error = %e, "publish packet rejected");
            return write_error(e);
        }
    };

    match packet {
        ValidatedDnsPacket::Records { host: packet_name } => {
            let packet_host = match normalize_host(&packet_name, state.host_allowlist.as_ref()) {
                Ok(h) => h,
                Err(e) => return write_error(e),
            };

            if packet_host != host {
                return write_error(AppError::HostMismatch);
            }

            publish_record(&state, &host, &body, authority.as_ref(), signature_fields).await
        }
        ValidatedDnsPacket::Empty => clear_record(&state, &host, authority.as_ref()).await,
    }
}

fn signature_fields_from_headers(headers: &http::HeaderMap) -> SignatureFields {
    let header = |name: &'static str| {
        headers
            .get(name)
            .map(|value| value.as_bytes().to_vec())
            .unwrap_or_default()
    };

    SignatureFields {
        content_digest: header(CONTENT_DIGEST_HEADER),
        signature_input: header(SIGNATURE_INPUT_HEADER),
        signature: header(SIGNATURE_HEADER),
    }
}

fn request_connection(request: &Request) -> Option<Arc<ConnectionState<dyn quic::DynConnection>>> {
    request
        .extensions()
        .get::<Arc<ConnectionState<dyn quic::DynConnection>>>()
        .cloned()
}
