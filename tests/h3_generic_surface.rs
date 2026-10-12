#![cfg(feature = "h3")]

#[test]
fn h3_resolver_is_non_generic_and_reexported() {
    let _ = core::any::type_name::<ddns::H3Resolver>();
    let _ = core::any::type_name::<ddns::h3::H3Resolver>();
    let _ = core::any::type_name::<ddns::resolvers::H3Resolver>();
}

#[tokio::test]
async fn h3_resolver_accepts_name_bound_dhttp_endpoint() {
    use std::sync::Arc;

    use ddns::h3::{H3LookupError, H3PublishError};

    let signing_key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["alice.smith.dhttp.net".into()]).unwrap();
    let ski = format!("1:0:{}", "0123456789abcdef".repeat(4));
    let mut extension = vec![0x04, ski.len() as u8];
    extension.extend_from_slice(ski.as_bytes());
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 14],
            extension,
        ));
    let cert = params.self_signed(&signing_key).unwrap();
    let identity = qbase::endpoint::Endpoint::new(
        "alice.smith.dhttp.net",
        vec![cert.der().clone()],
        qtls::PrivateKeyDer::Pkcs8(signing_key.serialize_der().into()),
        b"test-ocsp".to_vec(),
    )
    .unwrap();
    let endpoint = Arc::new(dhttp::Endpoint::new(identity));
    assert_eq!(endpoint.name(), "alice.smith.dhttp.net");
    let resolver =
        ddns::H3Resolver::new("https://dns.example/".parse().unwrap(), &endpoint).unwrap();
    assert!(matches!(
        resolver.publish_endpoints("other.dhttp.net", []).await,
        Err(H3PublishError::IdentityNameMismatch)
    ));
    assert!(matches!(
        resolver.lookup("invalid name", "443", None).await,
        Err(H3LookupError::NoRecordFound)
    ));
    // Querying an in-memory endpoint must reach dhttp without reloading its profile.
    assert!(matches!(
        resolver.lookup("demo.dhttp.net", "443", None).await,
        Err(H3LookupError::Request {
            source: dhttp::Error::NetworkNotInitialized,
        })
    ));
    drop(endpoint);
    assert!(matches!(
        resolver.lookup("demo.dhttp.net", "443", None).await,
        Err(H3LookupError::Request {
            source: dhttp::Error::NetworkNotInitialized
        })
    ));
    assert!(matches!(
        resolver
            .publish_endpoints("alice.smith.dhttp.net", [])
            .await,
        Err(H3PublishError::Request {
            source: dhttp::Error::NetworkNotInitialized
        })
    ));
}

#[tokio::test]
async fn anonymous_queries_require_no_identity_and_do_not_resolve_their_own_origin() {
    use ddns::h3::{H3LookupError, H3PublishError};

    let resolver =
        ddns::H3Resolver::anonymous("https://dns.example:4433/".parse().unwrap()).unwrap();
    assert!(matches!(
        resolver.lookup("DNS.EXAMPLE.", "4433", None).await,
        Err(H3LookupError::NoRecordFound)
    ));
    assert!(matches!(
        resolver.lookup("demo.dhttp.net", "443", None).await,
        Err(H3LookupError::Request {
            source: dhttp::Error::NetworkNotInitialized,
        })
    ));
    assert!(matches!(
        resolver.publish_endpoints("demo.dhttp.net", []).await,
        Err(H3PublishError::IdentityRequired)
    ));
}
