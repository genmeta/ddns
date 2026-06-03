use std::{io, net::IpAddr, path::Path};

use maxminddb::{Reader, geoip2};

#[derive(Clone, Debug)]
pub struct GeoPoint {
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy_radius_km: u16,
}

#[derive(Clone, Debug, Default)]
pub struct GeoTraits {
    pub country: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub point: Option<GeoPoint>,
}

#[derive(Debug)]
pub struct GeoResolver {
    city: Reader<Vec<u8>>,
    asn: Reader<Vec<u8>>,
    city_distance_routing: bool,
    max_accuracy_radius_km: u32,
}

impl GeoResolver {
    pub fn open(
        city_db: &Path,
        asn_db: &Path,
        city_distance_routing: bool,
        max_accuracy_radius_km: u32,
    ) -> io::Result<Self> {
        let city = Reader::open_readfile(city_db).map_err(io::Error::other)?;
        let asn = Reader::open_readfile(asn_db).map_err(io::Error::other)?;

        Ok(Self {
            city,
            asn,
            city_distance_routing,
            max_accuracy_radius_km,
        })
    }

    pub fn lookup_traits(&self, ip: IpAddr) -> GeoTraits {
        GeoTraits {
            country: self.lookup_country(ip),
            city: self.lookup_city(ip),
            asn: self.lookup_asn(ip),
            point: self.lookup_point(ip),
        }
    }

    pub fn city_build_epoch(&self) -> u64 {
        self.city.metadata.build_epoch
    }

    pub fn asn_build_epoch(&self) -> u64 {
        self.asn.metadata.build_epoch
    }

    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let city = self.city.lookup::<geoip2::City>(ip).ok()??;
        city.country?.iso_code.map(str::to_owned)
    }

    pub fn lookup_asn(&self, ip: IpAddr) -> Option<u32> {
        let asn = self.asn.lookup::<geoip2::Asn>(ip).ok()??;
        asn.autonomous_system_number
    }

    pub fn lookup_city(&self, ip: IpAddr) -> Option<String> {
        let city = self.city.lookup::<geoip2::City>(ip).ok()??;
        city.city?.names?.get("en").copied().map(str::to_owned)
    }

    pub fn lookup_point(&self, ip: IpAddr) -> Option<GeoPoint> {
        let city = self.city.lookup::<geoip2::City>(ip).ok()??;
        let location = city.location?;
        let latitude = location.latitude?;
        let longitude = location.longitude?;
        let accuracy_radius_km = location.accuracy_radius?;

        Some(GeoPoint {
            latitude,
            longitude,
            accuracy_radius_km,
        })
    }

    pub fn geo_distance_km(&self, left: &GeoPoint, right: &GeoPoint) -> Option<f64> {
        if !self.city_distance_routing {
            return None;
        }

        if u32::from(left.accuracy_radius_km) > self.max_accuracy_radius_km
            || u32::from(right.accuracy_radius_km) > self.max_accuracy_radius_km
        {
            return None;
        }

        Some(haversine_distance_km(
            left.latitude,
            left.longitude,
            right.latitude,
            right.longitude,
        ))
    }
}

fn haversine_distance_km(
    left_latitude: f64,
    left_longitude: f64,
    right_latitude: f64,
    right_longitude: f64,
) -> f64 {
    let earth_radius_km = 6_371.0;
    let lat_delta = (right_latitude - left_latitude).to_radians();
    let lon_delta = (right_longitude - left_longitude).to_radians();
    let left_latitude = left_latitude.to_radians();
    let right_latitude = right_latitude.to_radians();

    let haversine = (lat_delta / 2.0).sin().powi(2)
        + left_latitude.cos() * right_latitude.cos() * (lon_delta / 2.0).sin().powi(2);
    let arc = 2.0 * haversine.sqrt().asin();

    earth_radius_km * arc
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, path::PathBuf, str::FromStr};

    use super::*;

    fn fixture_geo_resolver() -> GeoResolver {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let city_db = manifest_dir.join("geoip/GeoLite2-City.mmdb");
        let asn_db = manifest_dir.join("geoip/GeoLite2-ASN.mmdb");

        GeoResolver::open(&city_db, &asn_db, true, 100).expect("fixture geo db should open")
    }

    #[test]
    fn bundled_geolite_maps_real_ips_to_expected_country_and_asn() {
        let geo = fixture_geo_resolver();
        let cases = [
            ("8.8.8.8", "US", 15169_u32),
            ("223.5.5.5", "CN", 45102_u32),
            ("80.80.80.80", "NL", 60679_u32),
            ("168.95.1.1", "TW", 3462_u32),
            ("200.160.0.8", "BR", 22548_u32),
        ];

        for (candidate, expected_country, expected_asn) in cases {
            let ip = IpAddr::from_str(candidate).unwrap();
            let traits = geo.lookup_traits(ip);

            assert_eq!(traits.country.as_deref(), Some(expected_country));
            assert_eq!(traits.asn, Some(expected_asn));
            assert!(
                traits.point.is_some(),
                "{candidate} should resolve to a city point"
            );
        }
    }

    #[test]
    fn bundled_geolite_exposes_city_name_separately_from_accuracy_radius() {
        let geo = fixture_geo_resolver();
        let ip = IpAddr::from_str("223.5.5.5").unwrap();
        let traits = geo.lookup_traits(ip);

        assert_eq!(traits.country.as_deref(), Some("CN"));
        assert_eq!(traits.city.as_deref(), Some("Hangzhou"));
        assert_eq!(
            traits.point.as_ref().map(|point| point.accuracy_radius_km),
            Some(20)
        );
    }

    #[test]
    fn bundled_geolite_may_have_coordinates_without_city_name() {
        let geo = fixture_geo_resolver();
        let ip = IpAddr::from_str("168.95.1.1").unwrap();
        let traits = geo.lookup_traits(ip);

        assert_eq!(traits.country.as_deref(), Some("TW"));
        assert_eq!(traits.city, None);
        assert_eq!(
            traits.point.as_ref().map(|point| point.accuracy_radius_km),
            Some(200)
        );
    }
}
