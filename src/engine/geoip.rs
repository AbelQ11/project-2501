// src/engine/geoip.rs
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::RwLock;

use maxminddb::{geoip2, Reader};
use tracing::{info, warn};

pub struct GeoResolver {
    cache: RwLock<HashMap<String, (String, String)>>,
    reader: Option<Reader<Vec<u8>>>,
}

impl GeoResolver {
    /// `db_path` should point to a MaxMind GeoLite2/GeoIP2 Country `.mmdb` file.
    /// When it is missing or unreadable, the resolver falls back to a small
    /// heuristic mapping instead of returning bogus data silently.
    pub fn new(db_path: Option<&Path>) -> Self {
        let reader = db_path.and_then(|path| match Reader::open_readfile(path) {
            Ok(reader) => {
                info!("GeoIP database loaded from {}", path.display());
                Some(reader)
            }
            Err(error) => {
                warn!(
                    "Could not open GeoIP database '{}': {}. Falling back to approximate lookup.",
                    path.display(),
                    error
                );
                None
            }
        });

        if reader.is_none() {
            info!("GeoIP: no database configured; using approximate first-octet mapping.");
        }

        Self {
            cache: RwLock::new(HashMap::with_capacity(512)),
            reader,
        }
    }

    /// Resolve an IP address to a (Country Code, Country Name) pair.
    pub fn resolve(&self, ip: &str) -> (String, String) {
        if crate::netutil::is_internal_ip(ip) {
            return ("LOC".to_string(), "Local Network".to_string());
        }

        if let Ok(cache) = self.cache.read() {
            if let Some(result) = cache.get(ip) {
                return result.clone();
            }
        }

        let result = self
            .lookup_database(ip)
            .unwrap_or_else(|| Self::lookup_heuristic(ip));

        if let Ok(mut cache) = self.cache.write() {
            cache.insert(ip.to_string(), result.clone());
        }

        result
    }

    fn lookup_database(&self, ip: &str) -> Option<(String, String)> {
        let reader = self.reader.as_ref()?;
        let address: IpAddr = ip.parse().ok()?;
        let lookup = reader.lookup(address).ok()?;
        let record: geoip2::Country = lookup.decode().ok().flatten()?;

        let code = record.country.iso_code.unwrap_or("GL").to_string();
        let name = record
            .country
            .names
            .english
            .unwrap_or("Global Neural")
            .to_string();

        Some((code, name))
    }

    /// Approximate fallback used only when no MaxMind database is available.
    fn lookup_heuristic(ip: &str) -> (String, String) {
        let first_octet: u8 = ip
            .split('.')
            .next()
            .and_then(|octet| octet.parse().ok())
            .unwrap_or(0);

        match first_octet {
            88 | 51 | 164 | 141 => ("FR".to_string(), "France".to_string()),
            45 | 185 | 194 | 195 => ("DE".to_string(), "Germany".to_string()),
            133 | 150 | 210 | 221 => ("JP".to_string(), "Japan".to_string()),
            34 | 35 | 52 | 54 => ("US".to_string(), "United States".to_string()),
            188 | 178 | 91 => ("RU".to_string(), "Russia".to_string()),
            114 | 116 | 222 => ("CN".to_string(), "China".to_string()),
            _ => ("GL".to_string(), "Global Neural".to_string()),
        }
    }
}
