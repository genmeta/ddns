#![cfg(feature = "h3")]

use std::{
    collections::HashMap,
    fs,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use ddns::{
    H3Resolver,
    core::{
        MdnsPacket,
        parser::record::endpoint::EndpointAddr as DnsEndpointAddr,
        signature::{
            CONTENT_DIGEST_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER, SignatureFields,
        },
        wire::{MultiResponse, ResponseRecord},
    },
    h3::H3LookupError,
    resolvers::endpoint_candidates::{EndpointLookup, ResolveEndpointCandidates},
};
use dhttp::{Body, Endpoint, HandshakeSummary};
use futures::StreamExt;
use http_body_util::{BodyExt, Full};
use qprotocol::{Dock, UdpSocket};
use qresolve::{EndpointAddr, Family, Source};

#[path = "support/h3_credentials.rs"]
mod credentials;

#[tokio::test]
#[ignore = "requires OpenSSL and local UDP socket permission"]
async fn new_dhttp_drives_named_and_anonymous_h3_dns_requests() {
    let root = std::env::temp_dir().join(format!("ddns-h3-roundtrip-{}", std::process::id()));
    let _files = scopeguard::guard(root.clone(), |root| {
        let _ = fs::remove_dir_all(root);
    });
    credentials::generate(
        &root,
        &[("origin", "localhost"), ("client", "client.dhttp.net")],
    );
    // This binary has one test. Set its isolated home before starting network tasks.
    unsafe { std::env::set_var("DHTTP_HOME", &root) };
    dhttp::DhttpNetwork::init().await.unwrap();
    let ca = fs::read(root.join("ca.crt")).unwrap();
    qtls::RootCerts::set(
        rustls_pemfile::certs(&mut ca.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
    )
    .unwrap();

    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let address = socket.local_addr().unwrap();
    Dock::global().add(socket.clone()).unwrap().unwrap();
    let _socket = scopeguard::guard(socket, |socket| {
        Dock::global().remove(&socket);
    });
    let ssl = root.join("origin/ssl");
    let certs = fs::read(ssl.join("fullchain.crt")).unwrap();
    let key = fs::read(ssl.join("privkey.pem")).unwrap();
    let origin = Endpoint::new(
        qbase::endpoint::Endpoint::new(
            &qtls::default_provider(),
            "localhost",
            rustls_pemfile::certs(&mut certs.as_slice())
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            rustls_pemfile::private_key(&mut key.as_slice())
                .unwrap()
                .unwrap(),
            fs::read(ssl.join("ocsp.der")).unwrap(),
        )
        .unwrap(),
    );
    let client = Arc::new(Endpoint::load("client").await.unwrap());
    let mut record = DnsEndpointAddr::direct_v4("192.0.2.10:4433".parse().unwrap());
    record.set_main(true);
    record.set_sequence(1u8.into());
    let mut records = HashMap::new();
    records.insert("client.dhttp.net".to_owned(), vec![record]);
    let answer = MultiResponse::new([ResponseRecord::unsigned(
        MdnsPacket::answer(0, &records).to_bytes(),
        vec![],
    )])
    .encode();
    let client_cert = fs::read(root.join("client/ssl/fullchain.crt")).unwrap();
    let client_cert = rustls_pemfile::certs(&mut client_cert.as_slice())
        .next()
        .unwrap()
        .unwrap();
    let lookups = Arc::new(AtomicUsize::new(0));
    let publishes = Arc::new(AtomicUsize::new(0));
    let named = Arc::new(AtomicUsize::new(0));
    let anonymous = Arc::new(AtomicUsize::new(0));
    let listening = tokio::spawn({
        let lookups = lookups.clone();
        let publishes = publishes.clone();
        let named = named.clone();
        let anonymous = anonymous.clone();
        async move {
            origin
                .listen(
                    dhttp::Scope::Loopback.into(),
                    tower::service_fn(move |request: http::Request<Body>| {
                        let answer = answer.clone();
                        let client_cert = client_cert.clone();
                        let lookups = lookups.clone();
                        let publishes = publishes.clone();
                        let named = named.clone();
                        let anonymous = anonymous.clone();
                        async move {
                            assert_eq!(request.version(), http::Version::HTTP_3);
                            assert_eq!(
                                request.uri().authority().unwrap().port_u16(),
                                Some(address.port())
                            );
                            let handshake = request.extensions().get::<HandshakeSummary>().unwrap();
                            match handshake.remote.as_ref() {
                                Some(peer) => {
                                    assert_eq!(peer.name(), "client.dhttp.net");
                                    named.fetch_add(1, Ordering::SeqCst);
                                }
                                None => {
                                    anonymous.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                            let mut response = http::Response::new(Full::new(Bytes::new()));
                            match request.uri().path() {
                                "/api/v2/publish" => {
                                    assert_eq!(request.method(), http::Method::POST);
                                    assert_eq!(
                                        request.uri().query(),
                                        Some("host=client.dhttp.net")
                                    );
                                    assert_eq!(
                                        request.headers()[http::header::CONTENT_TYPE],
                                        "application/octet-stream"
                                    );
                                    let fields = SignatureFields {
                                        content_digest: request.headers()[CONTENT_DIGEST_HEADER]
                                            .as_bytes()
                                            .to_vec(),
                                        signature_input: request.headers()[SIGNATURE_INPUT_HEADER]
                                            .as_bytes()
                                            .to_vec(),
                                        signature: request.headers()[SIGNATURE_HEADER]
                                            .as_bytes()
                                            .to_vec(),
                                    };
                                    let body = request.into_body().collect().await?.to_bytes();
                                    assert!(fields.verify(&body, client_cert.as_ref()).unwrap());
                                    let (remaining, packet) =
                                        ddns::core::parser::packet::be_packet(&body).unwrap();
                                    assert!(remaining.is_empty());
                                    assert!(packet.answers.len() <= 1);
                                    if let Some(answer) = packet.answers.first() {
                                        assert_eq!(answer.name(), "client.dhttp.net");
                                    }
                                    response.headers_mut().insert(
                                        "dhttp-dns-lease-millis",
                                        if packet.answers.is_empty() {
                                            "0"
                                        } else {
                                            "30000"
                                        }
                                        .parse()
                                        .unwrap(),
                                    );
                                    publishes.fetch_add(1, Ordering::SeqCst);
                                }
                                "/api/v2/lookup" => {
                                    assert_eq!(request.method(), http::Method::GET);
                                    let query = request.uri().query().unwrap();
                                    lookups.fetch_add(1, Ordering::SeqCst);
                                    if query.starts_with("host=missing.dhttp.net") {
                                        *response.status_mut() = http::StatusCode::NOT_FOUND;
                                    } else {
                                        assert!(query.starts_with("host=client.dhttp.net"));
                                        *response.body_mut() = Full::new(Bytes::from(answer));
                                        response.headers_mut().insert(
                                            http::header::CACHE_CONTROL,
                                            if publishes.load(Ordering::SeqCst) >= 3 {
                                                "no-store"
                                            } else {
                                                "max-age=60"
                                            }
                                            .parse()
                                            .unwrap(),
                                        );
                                    }
                                }
                                path => panic!("unexpected DNS API path: {path}"),
                            }
                            Ok::<_, dhttp::BoxError>(response)
                        }
                    }),
                )
                .await
                .unwrap()
                .await
        }
    });
    let listening = scopeguard::guard(listening, |task| task.abort());
    // Wait for the listener's service registration, without coupling to qconn internals.
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(!listening.is_finished());

    let url = format!("https://localhost:{}/", address.port());
    let resolver = H3Resolver::new(url.parse().unwrap(), &client).unwrap();
    let anonymous_resolver = Arc::new(H3Resolver::anonymous(url.parse().unwrap()).unwrap());
    qresolve::Resolver::add(anonymous_resolver.clone());
    qresolve::Resolver::add(Arc::new(qresolve::SystemResolver));
    let expected = EndpointAddr::direct("192.0.2.10:4433".parse().unwrap());
    let lookup = EndpointLookup::exact(1u8.into()).with_family(Some(Family::V4));
    let candidates = tokio::time::timeout(
        Duration::from_secs(10),
        resolver.lookup_endpoint_candidates("client.dhttp.net", lookup),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(candidates.groups[0].endpoints, vec![expected]);
    assert_eq!(candidates.groups[0].chain.sequence().get(), 1);
    let before_cache_hit = lookups.load(Ordering::SeqCst);
    resolver
        .lookup_endpoint_candidates("client.dhttp.net", lookup)
        .await
        .unwrap();
    assert_eq!(lookups.load(Ordering::SeqCst), before_cache_hit);
    tokio::time::timeout(
        Duration::from_secs(10),
        resolver.publish_endpoints("client.dhttp.net", [expected]),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(publishes.load(Ordering::SeqCst), 1);
    resolver
        .lookup_endpoint_candidates("client.dhttp.net", lookup)
        .await
        .unwrap();
    assert_eq!(lookups.load(Ordering::SeqCst), before_cache_hit + 1);

    // Queries, publication and withdrawal retain the loaded credentials after profile deletion.
    fs::remove_dir_all(root.join("client")).unwrap();
    assert_eq!(
        resolver
            .publish_endpoints("client.dhttp.net", [expected])
            .await
            .unwrap(),
        Duration::from_secs(30)
    );
    assert_eq!(
        resolver
            .publish_endpoints("client.dhttp.net", [])
            .await
            .unwrap(),
        Duration::ZERO
    );
    assert_eq!(publishes.load(Ordering::SeqCst), 3);
    resolver.clear_cache();
    let records = resolver
        .lookup("client.dhttp.net", "443", None)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await;
    assert_eq!(
        records,
        vec![(
            Source::H3 {
                server: Arc::from(url.trim_end_matches('/'))
            },
            expected
        )]
    );
    let uncached = lookups.load(Ordering::SeqCst);
    let _ = resolver
        .lookup("client.dhttp.net", "443", None)
        .await
        .unwrap();
    assert_eq!(
        lookups.load(Ordering::SeqCst),
        uncached + 1,
        "no-store prevents a DNS TTL cache hit"
    );
    let records = anonymous_resolver
        .lookup("client.dhttp.net", "443", None)
        .await
        .unwrap()
        .collect::<Vec<_>>()
        .await;
    assert_eq!(records[0].1, expected);
    assert!(named.load(Ordering::SeqCst) >= 4);
    assert_eq!(anonymous.load(Ordering::SeqCst), 1);
    assert!(matches!(
        anonymous_resolver
            .lookup("missing.dhttp.net", "443", None)
            .await,
        Err(H3LookupError::NoRecordFound)
    ));
}
