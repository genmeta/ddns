use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
};

use ddns::core::{MdnsPacket, parser::record::endpoint::EndpointAddr, signature::SignatureFields};
use dhttp_identity::identity::RemoteAuthority;
use rustls::pki_types::CertificateDer;

use super::store::{clear_record, publish_record};
use crate::{
    lookup::query::{LookupResult, perform_lookup},
    policy::DomainPolicies,
    storage::{AppState, MemoryStorage, SeedRecords, Storage},
};

#[derive(Debug)]
struct TestAuthority {
    name: &'static str,
    certs: Vec<CertificateDer<'static>>,
}

impl TestAuthority {
    fn new(name: &'static str, cert_bytes: Vec<u8>) -> Self {
        Self {
            name,
            certs: vec![CertificateDer::from(cert_bytes)],
        }
    }
}

impl RemoteAuthority for TestAuthority {
    fn name(&self) -> &str {
        self.name
    }

    fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.certs
    }
}

fn memory_state() -> AppState {
    AppState {
        storage: Storage::Memory(MemoryStorage::new()),
        host_allowlist: Arc::new(vec!["genmeta.net".to_string(), "dhttp.net".to_string()]),
        require_signature: true,
        ttl_secs: 30,
        policies: Arc::new(DomainPolicies::default()),
        seed_records: SeedRecords::default(),
        geo: None,
    }
}

fn packet_for(host: &str, last_octet: u8) -> bytes::Bytes {
    let endpoint = EndpointAddr::direct_v4(SocketAddrV4::new(
        Ipv4Addr::new(203, 0, 113, last_octet),
        4433,
    ));
    let mut hosts = HashMap::new();
    hosts.insert(host.to_owned(), vec![endpoint]);
    bytes::Bytes::from(MdnsPacket::answer(0, &hosts).to_bytes())
}

#[tokio::test]
async fn clear_record_removes_only_current_certificate_fingerprint() {
    let state = memory_state();
    let host = "reimu.pilot.dhttp.net";
    let authority_a = TestAuthority::new("authority-a", vec![1]);
    let authority_b = TestAuthority::new("authority-b", vec![2]);
    let packet_a = packet_for(host, 1);
    let packet_b = packet_for(host, 2);

    assert_eq!(
        publish_record(
            &state,
            host,
            &packet_a,
            &authority_a,
            SignatureFields::empty()
        )
        .await
        .status(),
        http::StatusCode::OK
    );
    assert_eq!(
        publish_record(
            &state,
            host,
            &packet_b,
            &authority_b,
            SignatureFields::empty()
        )
        .await
        .status(),
        http::StatusCode::OK
    );

    assert_eq!(
        clear_record(&state, host, &authority_a).await.status(),
        http::StatusCode::OK
    );

    let LookupResult::Multi(response) = perform_lookup(&state, host, None, None).await.unwrap()
    else {
        panic!("authority b record should remain");
    };
    assert_eq!(response.records.len(), 1);
    assert_eq!(response.records[0].cert, authority_b.certs[0].as_ref());
}

#[tokio::test]
async fn clear_record_is_idempotent_for_missing_fingerprint() {
    let state = memory_state();
    let host = "reimu.pilot.dhttp.net";
    let authority = TestAuthority::new("authority", vec![1]);

    assert_eq!(
        clear_record(&state, host, &authority).await.status(),
        http::StatusCode::OK
    );
    assert!(matches!(
        perform_lookup(&state, host, None, None).await.unwrap(),
        LookupResult::NotFound
    ));
}
