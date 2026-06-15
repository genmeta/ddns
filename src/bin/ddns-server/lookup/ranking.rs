use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
};

use ddns::core::{
    MdnsPacket,
    parser::{packet::be_packet, record::RData},
    wire::ResponseRecord,
};

use crate::{
    geo::{GeoResolver, GeoTraits},
    storage::LookupRecord,
};

type EndpointKey = (SocketAddr, Option<SocketAddr>);

pub(super) const LOOKUP_CANDIDATE_CAP_TOTAL: usize = 64;
pub(super) const LOOKUP_CANDIDATE_CAP_ASN: usize = 16;
pub(super) const LOOKUP_CANDIDATE_CAP_COUNTRY: usize = 16;
pub(super) const LOOKUP_CANDIDATE_CAP_ALL: usize = 32;

// GEO-aware ranking dimensions. Final ordering still falls back to the original
// record index so we keep lookups stable when all computed dimensions tie.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct GeoSortKey {
    pub(super) same_country: bool,
    pub(super) same_asn: bool,
    pub(super) family_match: bool,
    pub(super) same_city: bool,
    pub(super) load: Option<f32>,
    pub(super) geo_distance: Option<f64>,
}

pub(super) fn normalize_lookup_records(records: Vec<LookupRecord>) -> Vec<LookupRecord> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();

    for record in records {
        if !record.signature_fields.is_empty() {
            normalized.push(record);
            continue;
        }

        let Ok((_, packet)) = be_packet(&record.dns) else {
            normalized.push(record);
            continue;
        };

        let mut emitted_endpoint = false;

        for answer in &packet.answers {
            let RData::E(endpoint) = answer.data() else {
                continue;
            };

            emitted_endpoint = true;
            let key: EndpointKey = (endpoint.addr(), endpoint.agent_addr());

            if !seen.insert(key) {
                continue;
            }

            let mut hosts = HashMap::new();
            hosts.insert(answer.name().to_string(), vec![endpoint.clone()]);
            normalized.push(ResponseRecord::unsigned(
                MdnsPacket::answer(0, &hosts).to_bytes(),
                record.cert.clone(),
            ));
        }

        if !emitted_endpoint {
            normalized.push(record);
        }
    }

    normalized
}

pub(super) fn lookup_endpoint(dns_bytes: &[u8]) -> Option<(SocketAddr, Option<f32>)> {
    let (_, packet) = be_packet(dns_bytes).ok()?;
    packet
        .answers
        .iter()
        .find_map(|answer| match answer.data() {
            RData::E(endpoint) => Some((endpoint.addr(), endpoint.load())),
            _ => None,
        })
}

// Fallback ordering when GEO routing is disabled: prefer matching address family,
// then lower load, and finally preserve input order. We intentionally avoid
// IP prefix heuristics here because they are not reliable on the public Internet.
pub(super) fn sort_lookup_records(
    records: Vec<LookupRecord>,
    source_ip: Option<IpAddr>,
) -> Vec<LookupRecord> {
    let mut decorated = records
        .into_iter()
        .enumerate()
        .map(|(index, record)| {
            let sort_key = lookup_endpoint(&record.dns).map(|(endpoint, load)| {
                let family_match = source_ip
                    .map(|source| source.is_ipv4() == endpoint.ip().is_ipv4())
                    .unwrap_or(false);

                (family_match, load)
            });
            (sort_key, index, record)
        })
        .collect::<Vec<_>>();

    decorated.sort_by(|(left_key, left_index, _), (right_key, right_index, _)| {
        match (left_key, right_key) {
            (Some((left_family, left_load)), Some((right_family, right_load))) => right_family
                .cmp(left_family)
                .then_with(|| match (left_load, right_load) {
                    (Some(left), Some(right)) => left.partial_cmp(right).unwrap_or(Ordering::Equal),
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => Ordering::Equal,
                }),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        }
        .then_with(|| left_index.cmp(right_index))
    });

    decorated.into_iter().map(|(_, _, record)| record).collect()
}

pub(super) fn request_source_geo_traits(
    source_ip: Option<IpAddr>,
    geo: Option<&GeoResolver>,
) -> Option<GeoTraits> {
    Some(geo?.lookup_traits(source_ip?))
}

fn lookup_endpoint_geo_traits(
    dns_bytes: &[u8],
    geo: &GeoResolver,
) -> Option<(SocketAddr, Option<f32>, GeoTraits)> {
    let (endpoint, load) = lookup_endpoint(dns_bytes)?;
    Some((endpoint, load, geo.lookup_traits(endpoint.ip())))
}

fn compare_optional_partial<T: PartialOrd>(left: Option<T>, right: Option<T>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.partial_cmp(&right).unwrap_or(Ordering::Equal),
        _ => Ordering::Equal,
    }
}

// GEO ordering is layered rather than score-based:
// country > ASN > address family > city name > lower load > shorter GEO distance.
// Missing optional values do not penalize a candidate; they simply skip that layer.
pub(super) fn compare_geo_sort_keys(left: GeoSortKey, right: GeoSortKey) -> Ordering {
    right
        .same_country
        .cmp(&left.same_country)
        .then_with(|| right.same_asn.cmp(&left.same_asn))
        .then_with(|| right.family_match.cmp(&left.family_match))
        .then_with(|| right.same_city.cmp(&left.same_city))
        .then_with(|| compare_optional_partial(left.load, right.load))
        .then_with(|| compare_optional_partial(left.geo_distance, right.geo_distance))
}

// Build the per-endpoint GEO ranking tuple. City name only participates when both
// sides have a name and already match on country; coordinate distance only
// participates when GeoResolver accepts both accuracy radii.
pub(super) fn build_geo_sort_key(
    source_ip: Option<IpAddr>,
    source_traits: Option<&GeoTraits>,
    endpoint: SocketAddr,
    load: Option<f32>,
    endpoint_traits: &GeoTraits,
    geo: &GeoResolver,
) -> GeoSortKey {
    let family_match = source_ip
        .map(|source| source.is_ipv4() == endpoint.ip().is_ipv4())
        .unwrap_or(false);

    let same_country = source_traits
        .and_then(|source| source.country.as_deref())
        .zip(endpoint_traits.country.as_deref())
        .is_some_and(|(source, target)| source == target);

    let same_asn = source_traits
        .and_then(|source| source.asn)
        .zip(endpoint_traits.asn)
        .is_some_and(|(source, target)| source == target);

    let same_city = same_country
        && source_traits
            .and_then(|source| source.city.as_deref())
            .zip(endpoint_traits.city.as_deref())
            .is_some_and(|(source, target)| source == target);

    let geo_distance = source_traits
        .and_then(|source| source.point.as_ref())
        .zip(endpoint_traits.point.as_ref())
        .and_then(|(source, target)| geo.geo_distance_km(source, target));

    GeoSortKey {
        same_country,
        same_asn,
        family_match,
        same_city,
        load,
        geo_distance,
    }
}
pub(super) fn sort_lookup_records_with_geo(
    records: Vec<LookupRecord>,
    source_ip: Option<IpAddr>,
    geo: &GeoResolver,
) -> Vec<LookupRecord> {
    let source_traits = request_source_geo_traits(source_ip, Some(geo));

    let mut decorated = records
        .into_iter()
        .enumerate()
        .map(|(index, record)| {
            let sort_key = lookup_endpoint_geo_traits(&record.dns, geo).map(
                |(endpoint, load, endpoint_traits)| {
                    build_geo_sort_key(
                        source_ip,
                        source_traits.as_ref(),
                        endpoint,
                        load,
                        &endpoint_traits,
                        geo,
                    )
                },
            );
            (sort_key, index, record)
        })
        .collect::<Vec<_>>();

    decorated.sort_by(|(left_key, left_index, _), (right_key, right_index, _)| {
        match (left_key, right_key) {
            (Some(left_key), Some(right_key)) => compare_geo_sort_keys(*left_key, *right_key),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        }
        .then_with(|| left_index.cmp(right_index))
    });

    decorated.into_iter().map(|(_, _, record)| record).collect()
}
