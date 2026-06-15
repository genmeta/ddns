use std::{
    cmp::Ordering,
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::Arc,
};

use ddns::core::{MdnsEndpoint, MdnsPacket, signature::SignatureFields, wire::ResponseRecord};
use deadpool_redis::redis;

use super::{
    query::{LookupResult, perform_lookup, redis_host_blacklisted},
    ranking::{
        GeoSortKey, build_geo_sort_key, compare_geo_sort_keys, lookup_endpoint,
        normalize_lookup_records, sort_lookup_records, sort_lookup_records_with_geo,
    },
};
use crate::{
    geo::{GeoPoint, GeoResolver, GeoTraits},
    storage::{AppState, LookupRecord, MemoryStorage, SeedRecords, Storage, redis_blacklist_key},
};

fn fixture_geo_resolver() -> GeoResolver {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let city_db = manifest_dir.join("geoip/GeoLite2-City.mmdb");
    let asn_db = manifest_dir.join("geoip/GeoLite2-ASN.mmdb");

    GeoResolver::open(&city_db, &asn_db, true, 100).expect("fixture geo db should open")
}

fn lookup_record(host: &str, addr: SocketAddr, load: Option<f32>) -> LookupRecord {
    let mut endpoint = match addr {
        SocketAddr::V4(addr) => MdnsEndpoint::direct_v4(addr),
        SocketAddr::V6(addr) => MdnsEndpoint::direct_v6(addr),
    };
    endpoint.set_load(load);

    let mut hosts = HashMap::new();
    hosts.insert(host.to_string(), vec![endpoint]);

    ResponseRecord::unsigned(MdnsPacket::answer(0, &hosts).to_bytes(), Vec::new())
}

struct FakeRedis {
    response: redis::Value,
    packed_commands: Vec<Vec<u8>>,
}

impl redis::aio::ConnectionLike for FakeRedis {
    fn req_packed_command<'a>(
        &'a mut self,
        cmd: &'a redis::Cmd,
    ) -> redis::RedisFuture<'a, redis::Value> {
        self.packed_commands.push(cmd.get_packed_command());
        let response = self.response.clone();
        Box::pin(async move { Ok(response) })
    }

    fn req_packed_commands<'a>(
        &'a mut self,
        _cmd: &'a redis::Pipeline,
        _offset: usize,
        _count: usize,
    ) -> redis::RedisFuture<'a, Vec<redis::Value>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn get_db(&self) -> i64 {
        0
    }
}

#[tokio::test]
async fn redis_host_blacklisted_queries_external_blacklist_set() {
    let mut redis = FakeRedis {
        response: redis::Value::Int(1),
        packed_commands: Vec::new(),
    };

    let blacklisted = redis_host_blacklisted(&mut redis, "blocked.example.genmeta.net")
        .await
        .unwrap();

    assert!(blacklisted);
    assert_eq!(redis.packed_commands.len(), 1);
    let command = String::from_utf8(redis.packed_commands.remove(0)).unwrap();
    assert!(command.contains("SISMEMBER"));
    assert!(command.contains(redis_blacklist_key()));
    assert!(command.contains("blocked.example.genmeta.net"));
}

#[tokio::test]
async fn memory_blacklist_returns_not_found_before_seed_records() {
    let host = "blocked.example.genmeta.net";
    let mut seed_records = HashMap::new();
    seed_records.insert(
        host.to_string(),
        vec![lookup_record(
            host,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478)),
            None,
        )],
    );
    let state = AppState {
        storage: Storage::Memory(MemoryStorage::with_blacklist([host.to_string()])),
        host_allowlist: Arc::new(vec!["genmeta.net".to_string()]),
        require_signature: false,
        ttl_secs: 30,
        policies: Arc::new(crate::policy::DomainPolicies::default()),
        seed_records: SeedRecords::new(seed_records),
        geo: None,
    };

    let result = perform_lookup(&state, host, None, None).await.unwrap();

    assert!(matches!(result, LookupResult::NotFound));
}

#[test]
fn normalize_lookup_records_keeps_signed_packets_whole() {
    let mut record = lookup_record(
        "stun.example.com",
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478)),
        None,
    );
    record.signature_fields = SignatureFields {
        content_digest: b"sha-256=:abc:".to_vec(),
        signature_input: b"dns=(\"content-digest\");created=1;keyid=\"sha256:abc\";alg=\"ed25519\""
            .to_vec(),
        signature: b"dns=:sig:".to_vec(),
    };

    let normalized = normalize_lookup_records(vec![record.clone()]);

    assert_eq!(normalized.len(), 1);
    assert_eq!(normalized[0], record);
}

#[test]
fn compare_geo_sort_keys_follows_documented_priority() {
    let best = GeoSortKey {
        same_country: true,
        same_asn: true,
        family_match: true,
        same_city: true,
        load: Some(0.2),
        geo_distance: Some(20.0),
    };
    let worse_load = GeoSortKey {
        load: Some(0.8),
        ..best
    };
    let worse_family = GeoSortKey {
        same_asn: true,
        family_match: false,
        same_city: true,
        load: Some(0.1),
        geo_distance: Some(1.0),
        ..best
    };
    let worse_city = GeoSortKey {
        same_city: false,
        load: Some(0.1),
        geo_distance: Some(1.0),
        ..best
    };
    let worse_asn = GeoSortKey {
        same_asn: false,
        family_match: true,
        same_city: true,
        load: Some(0.1),
        geo_distance: Some(1.0),
        ..best
    };
    let worse_country = GeoSortKey {
        same_country: false,
        same_asn: true,
        family_match: true,
        same_city: false,
        load: Some(0.1),
        geo_distance: Some(1.0),
    };

    assert_eq!(compare_geo_sort_keys(best, worse_load), Ordering::Less);
    assert_eq!(compare_geo_sort_keys(best, worse_family), Ordering::Less);
    assert_eq!(compare_geo_sort_keys(best, worse_city), Ordering::Less);
    assert_eq!(compare_geo_sort_keys(best, worse_asn), Ordering::Less);
    assert_eq!(compare_geo_sort_keys(best, worse_country), Ordering::Less);
}

#[test]
fn compare_geo_sort_keys_skips_unknown_dimensions() {
    let known_distance = GeoSortKey {
        same_country: true,
        same_asn: true,
        family_match: true,
        same_city: true,
        load: Some(0.2),
        geo_distance: Some(10.0),
    };
    let missing_distance = GeoSortKey {
        geo_distance: None,
        ..known_distance
    };
    let missing_load = GeoSortKey {
        load: None,
        ..known_distance
    };

    assert_eq!(
        compare_geo_sort_keys(known_distance, missing_distance),
        Ordering::Equal
    );
    assert_eq!(
        compare_geo_sort_keys(known_distance, missing_load),
        Ordering::Equal
    );
}

#[test]
fn sort_lookup_records_with_geo_prefers_same_source_endpoint_even_with_higher_load() {
    let geo = fixture_geo_resolver();
    let source_ip = Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let matching = lookup_record(
        "stun.example.com",
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478)),
        Some(0.9),
    );
    let non_matching = lookup_record(
        "stun.example.com",
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 3478)),
        Some(0.1),
    );

    let sorted =
        sort_lookup_records_with_geo(vec![non_matching, matching.clone()], source_ip, &geo);

    let (endpoint, _) = lookup_endpoint(&sorted[0].dns).expect("sorted record should decode");
    assert_eq!(endpoint.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
}

#[test]
fn sort_lookup_records_without_geo_ignores_ip_prefix_and_prefers_lower_load() {
    let source_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let closer_prefix_higher_load = lookup_record(
        "stun.example.com",
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 3478)),
        Some(0.9),
    );
    let farther_prefix_lower_load = lookup_record(
        "stun.example.com",
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478)),
        Some(0.1),
    );

    let sorted = sort_lookup_records(
        vec![closer_prefix_higher_load, farther_prefix_lower_load],
        source_ip,
    );

    let (endpoint, _) = lookup_endpoint(&sorted[0].dns).expect("sorted record should decode");
    assert_eq!(endpoint.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
}

#[test]
fn sort_lookup_records_with_geo_prefers_same_asn_then_same_country_on_real_ips() {
    let geo = fixture_geo_resolver();
    let source_ip = Some(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)));

    let different_country = lookup_record(
        "stun.example.com",
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478)),
        Some(0.01),
    );
    let same_country_different_asn = lookup_record(
        "stun.example.com",
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(114, 114, 114, 114), 3478)),
        Some(0.02),
    );
    let same_country_same_asn = lookup_record(
        "stun.example.com",
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(223, 5, 5, 5), 3478)),
        Some(0.9),
    );

    let sorted = sort_lookup_records_with_geo(
        vec![
            different_country,
            same_country_different_asn,
            same_country_same_asn,
        ],
        source_ip,
        &geo,
    );

    let ordered_ips = sorted
        .iter()
        .map(|record| {
            lookup_endpoint(&record.dns)
                .expect("record should decode")
                .0
                .ip()
        })
        .collect::<Vec<_>>();

    assert_eq!(
        ordered_ips,
        vec![
            IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
            IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ]
    );
}

#[test]
fn sort_lookup_records_with_geo_prefers_same_country_over_lower_load_on_real_ips() {
    let geo = fixture_geo_resolver();
    let source_ip = Some(IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114)));

    let different_country_low_load = lookup_record(
        "stun.example.com",
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(80, 80, 80, 80), 3478)),
        Some(0.01),
    );
    let same_country_higher_load = lookup_record(
        "stun.example.com",
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(223, 5, 5, 5), 3478)),
        Some(0.9),
    );

    let sorted = sort_lookup_records_with_geo(
        vec![different_country_low_load, same_country_higher_load.clone()],
        source_ip,
        &geo,
    );

    let (endpoint, _) = lookup_endpoint(&sorted[0].dns).expect("sorted record should decode");
    assert_eq!(endpoint.ip(), IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)));
}

#[test]
fn build_geo_sort_key_ignores_city_distance_when_accuracy_is_too_large() {
    let geo = fixture_geo_resolver();
    let source_traits = GeoTraits {
        country: Some("CN".to_string()),
        city: Some("Beijing".to_string()),
        asn: Some(64512),
        point: Some(GeoPoint {
            latitude: 39.9,
            longitude: 116.4,
            accuracy_radius_km: 500,
        }),
    };
    let endpoint_traits = GeoTraits {
        country: Some("CN".to_string()),
        city: Some("Shanghai".to_string()),
        asn: Some(64512),
        point: Some(GeoPoint {
            latitude: 31.2,
            longitude: 121.5,
            accuracy_radius_km: 10,
        }),
    };

    let key = build_geo_sort_key(
        Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        Some(&source_traits),
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 3478)),
        Some(0.2),
        &endpoint_traits,
        &geo,
    );

    assert!(key.same_country);
    assert!(key.same_asn);
    assert!(!key.same_city);
    assert_eq!(key.geo_distance, None);
}

#[test]
fn build_geo_sort_key_prefers_same_city_when_available() {
    let geo = fixture_geo_resolver();
    let source_traits = GeoTraits {
        country: Some("CN".to_string()),
        city: Some("Hangzhou".to_string()),
        asn: Some(64512),
        point: None,
    };
    let same_city_traits = GeoTraits {
        country: Some("CN".to_string()),
        city: Some("Hangzhou".to_string()),
        asn: Some(64513),
        point: None,
    };
    let different_city_traits = GeoTraits {
        country: Some("CN".to_string()),
        city: Some("Shanghai".to_string()),
        asn: Some(64513),
        point: None,
    };

    let same_city_key = build_geo_sort_key(
        Some(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5))),
        Some(&source_traits),
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(223, 6, 6, 6), 3478)),
        Some(0.9),
        &same_city_traits,
        &geo,
    );
    let different_city_key = build_geo_sort_key(
        Some(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5))),
        Some(&source_traits),
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(114, 114, 114, 114), 3478)),
        Some(0.1),
        &different_city_traits,
        &geo,
    );

    assert!(same_city_key.same_city);
    assert!(!different_city_key.same_city);
    assert_eq!(
        compare_geo_sort_keys(same_city_key, different_city_key),
        Ordering::Less
    );
}
