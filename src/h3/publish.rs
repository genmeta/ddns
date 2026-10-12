use qresolve::EndpointAddr;
use tokio::io::AsyncWriteExt;

use super::{
    H3PublishError, H3Resolver, ReadBodyError, STATUS_BODY_LIMIT, StatusMessage, read_body_limited,
};
use crate::core::signature::{
    CONTENT_DIGEST_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER, SignatureFields,
};

const PUBLISH_API_PATH: &str = "/api/v2/publish";
const DNS_PACKET_LIMIT: usize = u16::MAX as usize;

fn publish_url(server_origin: &url::Url, name: &str) -> url::Url {
    let mut url = server_origin
        .join(PUBLISH_API_PATH)
        .expect("fixed publish path is a valid URL");
    url.query_pairs_mut().append_pair("host", name);
    url
}

impl H3Resolver {
    pub async fn publish_endpoints(
        &self,
        name: &str,
        endpoints: impl IntoIterator<Item = EndpointAddr>,
    ) -> Result<std::time::Duration, H3PublishError> {
        dhttp_home::validate_name(name).map_err(|_| H3PublishError::InvalidName)?;
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or(H3PublishError::IdentityRequired)?;
        if endpoint.name() != name {
            return Err(H3PublishError::IdentityNameMismatch);
        }

        let identity =
            endpoint
                .local_authority()
                .map_err(|source| H3PublishError::Credentials {
                    source: std::io::Error::other(source),
                })?;
        let mut endpoints = endpoints.into_iter().peekable();
        let empty = endpoints.peek().is_none();
        let packet =
            crate::publishers::packet::dns_packet_for_authority(&identity, name, &mut endpoints)
                .map_err(|source| H3PublishError::EncodePacket { source })?;
        if packet.len() > DNS_PACKET_LIMIT {
            return Err(H3PublishError::PacketTooLarge {
                limit: DNS_PACKET_LIMIT,
            });
        }
        let fields = SignatureFields::sign(&packet, &identity)
            .await
            .map_err(|source| H3PublishError::SignRequest { source })?;
        let url = publish_url(&self.server_origin, name);
        let (mut writer, response) = endpoint
            .post(url.as_str().parse().expect("validated HTTPS URL is a URI"))
            .header(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/octet-stream"),
            )
            .header(
                http::HeaderName::from_static(CONTENT_DIGEST_HEADER),
                http::HeaderValue::from_bytes(&fields.content_digest)
                    .expect("encoded digest is a header value"),
            )
            .header(
                http::HeaderName::from_static(SIGNATURE_INPUT_HEADER),
                http::HeaderValue::from_bytes(&fields.signature_input)
                    .expect("encoded signature input is a header value"),
            )
            .header(
                http::HeaderName::from_static(SIGNATURE_HEADER),
                http::HeaderValue::from_bytes(&fields.signature)
                    .expect("encoded signature is a header value"),
            )
            .write(&packet)
            .await
            .map_err(|source| H3PublishError::Request { source })?;
        writer
            .shutdown()
            .await
            .map_err(|source| H3PublishError::Upload { source })?;
        let response = response
            .await
            .map_err(|source| H3PublishError::Request { source })?;
        let status = response.status();
        tracing::debug!(?status, headers = ?response.headers(), "H3 DNS publish response");
        if status != http::StatusCode::OK {
            let body = read_body_limited(response.into_body(), STATUS_BODY_LIMIT)
                .await
                .map_err(|error| match error {
                    ReadBodyError::Body(source) => H3PublishError::Body { source },
                    ReadBodyError::TooLarge => H3PublishError::ResponseTooLarge {
                        limit: STATUS_BODY_LIMIT,
                    },
                })?;
            return Err(H3PublishError::Status {
                status,
                message: StatusMessage::new(String::from_utf8_lossy(&body).trim().to_owned()),
            });
        }

        let lease = publish_lease(response.headers(), empty)?;
        self.cache.invalidate_name(name);
        Ok(lease)
    }
}

fn publish_lease(
    headers: &http::HeaderMap,
    empty: bool,
) -> Result<std::time::Duration, H3PublishError> {
    let mut values = headers.get_all("dhttp-dns-lease-millis").iter();
    // Temporary compatibility with the deployed pre-lease server. The legacy
    // record TTL is 300 seconds; this is a renewal window, not a server lease.
    let Some(value) = values.next() else {
        return Ok(if empty {
            std::time::Duration::ZERO
        } else {
            std::time::Duration::from_secs(300)
        });
    };
    if values.next().is_some() {
        return Err(H3PublishError::InvalidLease);
    }
    let value = value.to_str().map_err(|_| H3PublishError::InvalidLease)?;
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(H3PublishError::InvalidLease);
    }
    let millis = value
        .parse::<u64>()
        .map_err(|_| H3PublishError::InvalidLease)?;
    if empty != (millis == 0) {
        return Err(H3PublishError::InvalidLease);
    }
    let lease = std::time::Duration::from_millis(millis);
    if tokio::time::Instant::now().checked_add(lease).is_none() {
        return Err(H3PublishError::InvalidLease);
    }
    Ok(lease)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_url_percent_encodes_name() {
        let url = publish_url(
            &url::Url::parse("https://dns.example:4433/").unwrap(),
            "demo name.dhttp.net",
        );
        assert_eq!(
            url.as_str(),
            "https://dns.example:4433/api/v2/publish?host=demo+name.dhttp.net"
        );
    }
}

#[cfg(test)]
mod lease_tests {
    use super::*;
    #[test]
    fn requires_one_numeric_header_with_matching_clear_semantics() {
        let mut headers = http::HeaderMap::new();
        assert_eq!(
            publish_lease(&headers, false).unwrap(),
            std::time::Duration::from_secs(300)
        );
        assert_eq!(
            publish_lease(&headers, true).unwrap(),
            std::time::Duration::ZERO
        );
        for value in ["", "-1", "+1", "1.5", "18446744073709551616", "30000,30000"] {
            headers.insert("dhttp-dns-lease-millis", value.parse().unwrap());
            assert!(
                matches!(
                    publish_lease(&headers, false),
                    Err(H3PublishError::InvalidLease)
                ),
                "{value}"
            );
        }
        headers.insert("dhttp-dns-lease-millis", "30000".parse().unwrap());
        assert_eq!(
            publish_lease(&headers, false).unwrap(),
            std::time::Duration::from_secs(30)
        );
        assert!(matches!(
            publish_lease(&headers, true),
            Err(H3PublishError::InvalidLease)
        ));
        headers.append("dhttp-dns-lease-millis", "30000".parse().unwrap());
        assert!(matches!(
            publish_lease(&headers, false),
            Err(H3PublishError::InvalidLease)
        ));
        headers.insert("dhttp-dns-lease-millis", "0".parse().unwrap());
        assert_eq!(
            publish_lease(&headers, true).unwrap(),
            std::time::Duration::ZERO
        );
        assert!(matches!(
            publish_lease(&headers, false),
            Err(H3PublishError::InvalidLease)
        ));
        headers.insert("dhttp-dns-lease-millis", "1".parse().unwrap());
        assert_eq!(
            publish_lease(&headers, false).unwrap(),
            std::time::Duration::from_millis(1)
        );
    }
}
