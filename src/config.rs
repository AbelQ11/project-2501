use std::env;
use std::path::PathBuf;

use ipnet::IpNet;
use rand::RngCore;

use crate::logwatch::ChannelTarget;
use crate::netutil;

#[derive(Debug, Clone)]
pub struct Config {
    pub interface: String,
    pub server_public_ip: String,
    pub channels: Vec<ChannelTarget>,

    // Anomaly Thresholds
    pub syn_flood_threshold: u32,
    pub syn_window_seconds: u64,
    pub scan_404_threshold: u32,
    pub scan_window_seconds: u64,
    pub alert_cooldown_minutes: u64,

    // Discord Alerting
    pub discord_enabled: bool,
    pub discord_webhook_url: Option<String>,

    // SMTP Alerting
    pub smtp_enabled: bool,
    pub smtp_url: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub alert_to: String,

    // Firewall Active Defense (Fail2ban IPS)
    pub firewall_enabled: bool,
    pub ban_duration_minutes: u64,
    pub ip_whitelist: Vec<IpNet>,

    // Storage & Dashboard
    pub db_path: PathBuf,
    pub dashboard_port: u16,
    pub dashboard_bind: String,

    // Privacy / GeoIP
    pub visitor_salt: String,
    pub geoip_db_path: Option<PathBuf>,
}

impl Config {
    pub fn load() -> Self {
        dotenvy::dotenv().ok();

        let interface = env::var("INTERFACE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "eth0".to_string());
        let server_public_ip = env::var("SERVER_PUBLIC_IP").unwrap_or_default();

        let mut channels = Vec::new();

        // Dynamically load all configured channels: CHANNEL_1, CHANNEL_2, ... CHANNEL_N
        let mut ch_idx = 1;
        loop {
            let name_key = format!("CHANNEL_{}_NAME", ch_idx);
            let domain_key = format!("CHANNEL_{}_DOMAIN", ch_idx);
            let log_key = format!("CHANNEL_{}_LOG", ch_idx);

            match (
                env::var(&name_key),
                env::var(&domain_key),
                env::var(&log_key),
            ) {
                (Ok(name), Ok(domain), Ok(log_path)) if !name.trim().is_empty() => {
                    channels.push(ChannelTarget {
                        name,
                        domain,
                        log_path: PathBuf::from(log_path),
                    });
                    ch_idx += 1;
                }
                _ => break,
            }
        }

        // Optional Fallback global access.log
        if let Ok(global_log) = env::var("GLOBAL_FALLBACK_LOG") {
            if !global_log.trim().is_empty() {
                channels.push(ChannelTarget {
                    name: "global".to_string(),
                    domain: "omni-ingress".to_string(),
                    log_path: PathBuf::from(global_log),
                });
            }
        }

        let mut ip_whitelist = Vec::new();
        if let Ok(raw_whitelist) = env::var("IP_WHITELIST") {
            for entry in raw_whitelist.split(',') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }
                match netutil::parse_net(entry) {
                    Some(net) => ip_whitelist.push(net),
                    None => tracing::warn!("Ignoring invalid IP_WHITELIST entry: {}", entry),
                }
            }
        }

        let visitor_salt = match env::var("VISITOR_SALT") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => {
                tracing::warn!(
                    "VISITOR_SALT is not set; using an ephemeral random salt. Unique visitor counts will reset when the daemon restarts. Run scripts/setup.sh or set VISITOR_SALT in .env."
                );
                Self::generate_salt()
            }
        };

        let geoip_db_path = env::var("GEOIP_DB_PATH")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);

        Self {
            interface,
            server_public_ip,
            channels,
            syn_flood_threshold: env::var("SYN_FLOOD_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            syn_window_seconds: env::var("SYN_WINDOW_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            scan_404_threshold: env::var("SCAN_404_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15),
            scan_window_seconds: env::var("SCAN_WINDOW_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
            alert_cooldown_minutes: env::var("ALERT_COOLDOWN_MINUTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(15),

            discord_enabled: env::var("DISCORD_ENABLED")
                .map(|v| v == "true")
                .unwrap_or(false),
            discord_webhook_url: env::var("DISCORD_WEBHOOK_URL")
                .ok()
                .filter(|value| !value.trim().is_empty()),

            smtp_enabled: env::var("SMTP_ENABLED")
                .map(|v| v == "true")
                .unwrap_or(false),
            smtp_url: env::var("SMTP_URL").unwrap_or_default(),
            smtp_port: env::var("SMTP_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(465),
            smtp_user: env::var("SMTP_USER").unwrap_or_default(),
            smtp_pass: env::var("SMTP_PASS").unwrap_or_default(),
            alert_to: env::var("ALERT_TO").unwrap_or_default(),

            firewall_enabled: env::var("FIREWALL_ENABLED")
                .map(|v| v == "true")
                .unwrap_or(true),
            ban_duration_minutes: env::var("BAN_DURATION_MINUTES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            ip_whitelist,

            db_path: PathBuf::from(
                env::var("DB_PATH").unwrap_or_else(|_| "cyberbrain.db".to_string()),
            ),
            dashboard_port: env::var("DASHBOARD_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2501),
            dashboard_bind: env::var("DASHBOARD_BIND").unwrap_or_else(|_| "127.0.0.1".to_string()),

            visitor_salt,
            geoip_db_path,
        }
    }

    /// Check if an IP must never be treated as an attacker.
    ///
    /// Loopback, RFC1918/link-local addresses (including outgoing local traffic seen
    /// by the raw socket), the server's own public IP and every entry of
    /// `IP_WHITELIST` (single IP or CIDR) are protected.
    pub fn is_whitelisted(&self, ip: &str) -> bool {
        if netutil::is_internal_ip(ip) {
            return true;
        }

        if let (Some(candidate), Some(public)) = (
            netutil::parse_ip(ip),
            netutil::parse_ip(&self.server_public_ip),
        ) {
            if candidate == public {
                return true;
            }
        }

        netutil::ip_in_any_net(ip, &self.ip_whitelist)
    }

    fn generate_salt() -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
    }
}
