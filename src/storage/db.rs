// src/storage/db.rs
use crate::logwatch::ParsedChannelEvent;
use rusqlite::{params, Connection};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info};

#[derive(Debug, Clone, Serialize)]
pub struct PageStat {
    pub path: String,
    pub hits: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReferrerStat {
    pub domain: String,
    pub hits: u64,
    pub pct: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeoStat {
    pub country_code: String,
    pub country_name: String,
    pub hits: u64,
    pub pct: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatRecord {
    pub timestamp: i64,
    pub channel: String,
    pub domain: String,
    pub threat_type: String,
    pub source_ip: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BannedIpRecord {
    pub ip: String,
    pub channel: String,
    pub domain: String,
    pub country: String,
    pub reason: String,
    pub banned_at: i64,
    pub expires_at: i64,
    pub remaining_seconds: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyticsSummary {
    pub ingress_24h: u64,
    pub unique_visitors_24h: u64,
    pub active_visitors: u64,
    pub breaches_blocked: u64,
    pub active_bans_count: u64,
    pub top_pages: Vec<PageStat>,
    pub top_referrers: Vec<ReferrerStat>,
    pub geo_stats: Vec<GeoStat>,
    pub recent_threats: Vec<ThreatRecord>,
    pub banned_ips: Vec<BannedIpRecord>,
}

#[derive(Debug)]
pub enum StorageMessage {
    Hit {
        event: ParsedChannelEvent,
        visitor_hash: u64,
        country: (String, String), // (code, name)
    },
    Threat {
        channel: String,
        domain: String,
        threat_type: String,
        source_ip: String,
        details: String,
    },
    Ban {
        ip: String,
        channel: String,
        domain: String,
        country: String,
        reason: String,
        duration_secs: u64,
    },
}

#[derive(Clone)]
pub struct Database {
    db_path: PathBuf,
}

impl Database {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, rusqlite::Error> {
        let db_path = path.as_ref().to_path_buf();
        let conn = Connection::open(&db_path)?;

        // Optimize for concurrent low-overhead operations
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA temp_store = MEMORY;

            CREATE TABLE IF NOT EXISTS hourly_stats (
                hour_timestamp INTEGER NOT NULL,
                channel TEXT NOT NULL,
                domain TEXT NOT NULL,
                total_views INTEGER DEFAULT 0,
                unique_visitors INTEGER DEFAULT 0,
                bot_views INTEGER DEFAULT 0,
                PRIMARY KEY (hour_timestamp, channel)
            );

            CREATE TABLE IF NOT EXISTS page_views (
                hour_timestamp INTEGER NOT NULL,
                channel TEXT NOT NULL,
                path TEXT NOT NULL,
                view_count INTEGER DEFAULT 0,
                PRIMARY KEY (hour_timestamp, channel, path)
            );

            CREATE TABLE IF NOT EXISTS referrer_stats (
                hour_timestamp INTEGER NOT NULL,
                channel TEXT NOT NULL,
                referrer TEXT NOT NULL,
                hit_count INTEGER DEFAULT 0,
                PRIMARY KEY (hour_timestamp, channel, referrer)
            );

            CREATE TABLE IF NOT EXISTS geo_stats (
                hour_timestamp INTEGER NOT NULL,
                channel TEXT NOT NULL,
                country_code TEXT NOT NULL,
                country_name TEXT NOT NULL,
                hit_count INTEGER DEFAULT 0,
                PRIMARY KEY (hour_timestamp, channel, country_code)
            );

            CREATE TABLE IF NOT EXISTS threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                channel TEXT NOT NULL,
                domain TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                details TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_threat_timestamp ON threat_events(timestamp DESC);

            CREATE TABLE IF NOT EXISTS active_bans (
                ip TEXT PRIMARY KEY,
                channel TEXT NOT NULL,
                domain TEXT NOT NULL,
                country TEXT NOT NULL,
                reason TEXT NOT NULL,
                banned_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ban_expires ON active_bans(expires_at DESC);
        "#,
        )?;

        info!(
            "Cyberbrain storage database initialized at {}",
            db_path.display()
        );
        Ok(Self { db_path })
    }

    /// Remove an IP from the active bans table
    pub fn unban_ip(&self, ip: &str) -> Result<(), rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;
        conn.execute("DELETE FROM active_bans WHERE ip = ?1", params![ip])?;
        Ok(())
    }

    /// Active bans as `(ip, expires_at)` so the iptables backend can restore
    /// the remaining ban duration after a daemon restart.
    pub fn active_bans_for_restore(&self) -> Result<Vec<(String, i64)>, rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;
        let now = chrono::Utc::now().timestamp();
        let mut stmt =
            conn.prepare("SELECT ip, expires_at FROM active_bans WHERE expires_at > ?1")?;
        let rows = stmt.query_map(params![now], |row| Ok((row.get(0)?, row.get(1)?)))?;
        Ok(rows.flatten().collect())
    }

    /// Spawns a background task that buffers hits and flushes them to SQLite in transactions
    pub fn start_worker(self: Arc<Self>, mut rx: mpsc::Receiver<StorageMessage>) {
        let db_path = self.db_path.clone();

        tokio::spawn(async move {
            let mut conn = match Connection::open(&db_path) {
                Ok(c) => c,
                Err(e) => {
                    error!(
                        "Failed to open database connection for background writer: {}",
                        e
                    );
                    return;
                }
            };

            // In-memory buffer state
            let mut buffered_hits: Vec<(ParsedChannelEvent, u64, (String, String))> =
                Vec::with_capacity(128);
            let mut buffered_threats: Vec<StorageMessage> = Vec::with_capacity(32);
            let mut buffered_bans: Vec<StorageMessage> = Vec::with_capacity(16);
            // Visitor hashes already counted for the current hour, per channel.
            // Without this, every 5-second flush counted the same visitor again.
            let mut seen_visitors: HashMap<(i64, String), HashSet<u64>> = HashMap::new();
            let mut flush_interval = tokio::time::interval(Duration::from_secs(5));

            loop {
                tokio::select! {
                    Some(msg) = rx.recv() => {
                        match msg {
                            StorageMessage::Hit { event, visitor_hash, country } => {
                                buffered_hits.push((event, visitor_hash, country));
                            }
                            threat @ StorageMessage::Threat { .. } => {
                                buffered_threats.push(threat);
                            }
                            ban @ StorageMessage::Ban { .. } => {
                                buffered_bans.push(ban);
                            }
                        }

                        if buffered_hits.len() >= 100 {
                            Self::flush_batch(&mut conn, &mut buffered_hits, &mut buffered_threats, &mut buffered_bans, &mut seen_visitors);
                        }
                    }
                    _ = flush_interval.tick() => {
                        Self::flush_batch(&mut conn, &mut buffered_hits, &mut buffered_threats, &mut buffered_bans, &mut seen_visitors);
                    }
                    else => {
                        // Channel closed (daemon shutting down)
                        Self::flush_batch(&mut conn, &mut buffered_hits, &mut buffered_threats, &mut buffered_bans, &mut seen_visitors);
                        break;
                    }
                }
            }
        });
    }

    fn flush_batch(
        conn: &mut Connection,
        hits: &mut Vec<(ParsedChannelEvent, u64, (String, String))>,
        threats: &mut Vec<StorageMessage>,
        bans: &mut Vec<StorageMessage>,
        seen_visitors: &mut HashMap<(i64, String), HashSet<u64>>,
    ) {
        if hits.is_empty() && threats.is_empty() && bans.is_empty() {
            return;
        }

        let now_sec = chrono::Utc::now().timestamp();
        let hour_timestamp = (now_sec / 3600) * 3600;

        // Drop deduplication state from previous hours to bound memory usage.
        seen_visitors.retain(|(hour, _channel), _| *hour == hour_timestamp);

        // Aggregate hits by (channel, domain), (channel, path), (channel, referrer), (channel, country)
        let mut channel_views: HashMap<(String, String), (u64, u64)> = HashMap::new();
        let mut visitor_sets: HashMap<String, HashSet<u64>> = HashMap::new();
        let mut page_counts: HashMap<(String, String), u64> = HashMap::new();
        let mut referrer_counts: HashMap<(String, String), u64> = HashMap::new();
        let mut geo_counts: HashMap<(String, String, String), u64> = HashMap::new(); // ((channel, code, name), count)

        for (event, vhash, (ccode, cname)) in hits.drain(..) {
            let is_bot = Self::is_crawler(&event.entry.user_agent);
            let ch_key = (event.channel.clone(), event.domain.clone());
            let entry = channel_views.entry(ch_key).or_insert((0, 0));
            entry.0 += 1;
            if is_bot {
                entry.1 += 1;
            }

            visitor_sets
                .entry(event.channel.clone())
                .or_default()
                .insert(vhash);

            *page_counts
                .entry((event.channel.clone(), event.entry.path.clone()))
                .or_insert(0) += 1;

            let ref_cleaned = Self::clean_referrer(event.entry.referer.as_deref());
            *referrer_counts
                .entry((event.channel.clone(), ref_cleaned))
                .or_insert(0) += 1;

            *geo_counts.entry((event.channel, ccode, cname)).or_insert(0) += 1;
        }

        // Execute batch transaction
        let tx_result = conn.transaction();
        let tx = match tx_result {
            Ok(tx) => tx,
            Err(e) => {
                error!("Failed to begin SQLite transaction: {}", e);
                return;
            }
        };

        // 1. Flush hourly_stats
        for ((channel, domain), (total, bots)) in channel_views {
            // Only count hashes not already seen during this hour.
            let unique = visitor_sets
                .get(&channel)
                .map(|hashes| {
                    let seen = seen_visitors
                        .entry((hour_timestamp, channel.clone()))
                        .or_default();
                    hashes.iter().filter(|hash| seen.insert(**hash)).count() as u64
                })
                .unwrap_or(0);
            let _ = tx.execute(
                r#"
                INSERT INTO hourly_stats (hour_timestamp, channel, domain, total_views, unique_visitors, bot_views)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                ON CONFLICT(hour_timestamp, channel) DO UPDATE SET
                    total_views = total_views + excluded.total_views,
                    unique_visitors = unique_visitors + excluded.unique_visitors,
                    bot_views = bot_views + excluded.bot_views
                "#,
                params![hour_timestamp, channel, domain, total, unique, bots],
            );
        }

        // 2. Flush page_views
        for ((channel, path), count) in page_counts {
            let _ = tx.execute(
                r#"
                INSERT INTO page_views (hour_timestamp, channel, path, view_count)
                VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(hour_timestamp, channel, path) DO UPDATE SET
                    view_count = view_count + excluded.view_count
                "#,
                params![hour_timestamp, channel, path, count],
            );
        }

        // 3. Flush referrer_stats
        for ((channel, referrer), count) in referrer_counts {
            let _ = tx.execute(
                r#"
                INSERT INTO referrer_stats (hour_timestamp, channel, referrer, hit_count)
                VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(hour_timestamp, channel, referrer) DO UPDATE SET
                    hit_count = hit_count + excluded.hit_count
                "#,
                params![hour_timestamp, channel, referrer, count],
            );
        }

        // 4. Flush geo_stats
        for ((channel, ccode, cname), count) in geo_counts {
            let _ = tx.execute(
                r#"
                INSERT INTO geo_stats (hour_timestamp, channel, country_code, country_name, hit_count)
                VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(hour_timestamp, channel, country_code) DO UPDATE SET
                    hit_count = hit_count + excluded.hit_count
                "#,
                params![hour_timestamp, channel, ccode, cname, count],
            );
        }

        // 5. Flush threat_events
        for threat in threats.drain(..) {
            if let StorageMessage::Threat {
                channel,
                domain,
                threat_type,
                source_ip,
                details,
            } = threat
            {
                let _ = tx.execute(
                    r#"
                    INSERT INTO threat_events (timestamp, channel, domain, threat_type, source_ip, details)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                    "#,
                    params![now_sec, channel, domain, threat_type, source_ip, details],
                );
            }
        }

        // 6. Flush active_bans
        for ban in bans.drain(..) {
            if let StorageMessage::Ban {
                ip,
                channel,
                domain,
                country,
                reason,
                duration_secs,
            } = ban
            {
                let expires_at = now_sec + duration_secs as i64;
                let _ = tx.execute(
                    r#"
                    INSERT INTO active_bans (ip, channel, domain, country, reason, banned_at, expires_at)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                    ON CONFLICT(ip) DO UPDATE SET
                        reason = excluded.reason,
                        banned_at = excluded.banned_at,
                        expires_at = excluded.expires_at
                    "#,
                    params![ip, channel, domain, country, reason, now_sec, expires_at],
                );
            }
        }

        // 7. Cleanup expired bans
        let _ = tx.execute(
            "DELETE FROM active_bans WHERE expires_at <= ?1",
            params![now_sec],
        );

        if let Err(e) = tx.commit() {
            error!("Failed to commit SQLite storage batch: {}", e);
        }
    }

    /// Query 24h summary analytics for HUD
    pub fn get_analytics_summary(
        &self,
        channel: Option<&str>,
    ) -> Result<AnalyticsSummary, rusqlite::Error> {
        let conn = Connection::open(&self.db_path)?;
        let now_sec = chrono::Utc::now().timestamp();
        let cutoff_24h = now_sec - 86400;

        // 1. Total ingress and unique visitors (24h)
        let (ingress_24h, unique_visitors_24h): (u64, u64) = match channel {
            Some(ch) => conn
                .query_row(
                    "SELECT COALESCE(SUM(total_views), 0), COALESCE(SUM(unique_visitors), 0)
                 FROM hourly_stats WHERE hour_timestamp >= ?1 AND channel = ?2",
                    params![cutoff_24h, ch],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap_or((0, 0)),
            None => conn
                .query_row(
                    "SELECT COALESCE(SUM(total_views), 0), COALESCE(SUM(unique_visitors), 0)
                 FROM hourly_stats WHERE hour_timestamp >= ?1",
                    params![cutoff_24h],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap_or((0, 0)),
        };

        // 2. Breaches blocked (24h)
        let breaches_blocked: u64 = match channel {
            Some(ch) => conn
                .query_row(
                    "SELECT COUNT(*) FROM threat_events WHERE timestamp >= ?1 AND channel = ?2",
                    params![cutoff_24h, ch],
                    |r| r.get(0),
                )
                .unwrap_or(0),
            None => conn
                .query_row(
                    "SELECT COUNT(*) FROM threat_events WHERE timestamp >= ?1",
                    params![cutoff_24h],
                    |r| r.get(0),
                )
                .unwrap_or(0),
        };

        // 3. Active bans
        let mut banned_ips = Vec::new();
        if let Some(ch) = channel {
            let mut stmt = conn.prepare("SELECT ip, channel, domain, country, reason, banned_at, expires_at FROM active_bans WHERE channel = ?1 AND expires_at > ?2 ORDER BY banned_at DESC LIMIT 10")?;
            let rows = stmt.query_map(params![ch, now_sec], |r| {
                let expires_at: i64 = r.get(6)?;
                Ok(BannedIpRecord {
                    ip: r.get(0)?,
                    channel: r.get(1)?,
                    domain: r.get(2)?,
                    country: r.get(3)?,
                    reason: r.get(4)?,
                    banned_at: r.get(5)?,
                    expires_at,
                    remaining_seconds: (expires_at - now_sec).max(0),
                })
            })?;
            for r in rows.flatten() {
                banned_ips.push(r);
            }
        } else {
            let mut stmt = conn.prepare("SELECT ip, channel, domain, country, reason, banned_at, expires_at FROM active_bans WHERE expires_at > ?1 ORDER BY banned_at DESC LIMIT 10")?;
            let rows = stmt.query_map(params![now_sec], |r| {
                let expires_at: i64 = r.get(6)?;
                Ok(BannedIpRecord {
                    ip: r.get(0)?,
                    channel: r.get(1)?,
                    domain: r.get(2)?,
                    country: r.get(3)?,
                    reason: r.get(4)?,
                    banned_at: r.get(5)?,
                    expires_at,
                    remaining_seconds: (expires_at - now_sec).max(0),
                })
            })?;
            for r in rows.flatten() {
                banned_ips.push(r);
            }
        }
        // Count all active bans; the list above is intentionally limited to 10
        // rows, so using its length as the count was capped at 10.
        let active_bans_count: u64 = match channel {
            Some(ch) => conn
                .query_row(
                    "SELECT COUNT(*) FROM active_bans WHERE channel = ?1 AND expires_at > ?2",
                    params![ch, now_sec],
                    |row| row.get(0),
                )
                .unwrap_or(0),
            None => conn
                .query_row(
                    "SELECT COUNT(*) FROM active_bans WHERE expires_at > ?1",
                    params![now_sec],
                    |row| row.get(0),
                )
                .unwrap_or(0),
        };

        // 4. Top pages
        let mut top_pages = Vec::new();
        if let Some(ch) = channel {
            let mut stmt = conn.prepare("SELECT path, SUM(view_count) as hits FROM page_views WHERE hour_timestamp >= ?1 AND channel = ?2 GROUP BY path ORDER BY hits DESC LIMIT 6")?;
            let rows = stmt.query_map(params![cutoff_24h, ch], |r| {
                Ok(PageStat {
                    path: r.get(0)?,
                    hits: r.get(1)?,
                })
            })?;
            for r in rows.flatten() {
                top_pages.push(r);
            }
        } else {
            let mut stmt = conn.prepare("SELECT path, SUM(view_count) as hits FROM page_views WHERE hour_timestamp >= ?1 GROUP BY path ORDER BY hits DESC LIMIT 6")?;
            let rows = stmt.query_map(params![cutoff_24h], |r| {
                Ok(PageStat {
                    path: r.get(0)?,
                    hits: r.get(1)?,
                })
            })?;
            for r in rows.flatten() {
                top_pages.push(r);
            }
        }

        // 5. Top referrers
        let mut top_referrers = Vec::new();
        let mut raw_refs = Vec::new();
        let mut total_ref_hits = 0u64;

        if let Some(ch) = channel {
            let mut stmt = conn.prepare("SELECT referrer, SUM(hit_count) as hits FROM referrer_stats WHERE hour_timestamp >= ?1 AND channel = ?2 GROUP BY referrer ORDER BY hits DESC LIMIT 5")?;
            let rows = stmt.query_map(params![cutoff_24h, ch], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?))
            })?;
            for r in rows.flatten() {
                total_ref_hits += r.1;
                raw_refs.push(r);
            }
        } else {
            let mut stmt = conn.prepare("SELECT referrer, SUM(hit_count) as hits FROM referrer_stats WHERE hour_timestamp >= ?1 GROUP BY referrer ORDER BY hits DESC LIMIT 5")?;
            let rows = stmt.query_map(params![cutoff_24h], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?))
            })?;
            for r in rows.flatten() {
                total_ref_hits += r.1;
                raw_refs.push(r);
            }
        }

        for (domain, hits) in raw_refs {
            let pct = if total_ref_hits > 0 {
                (hits as f32 / total_ref_hits as f32) * 100.0
            } else {
                0.0
            };
            top_referrers.push(ReferrerStat { domain, hits, pct });
        }

        // 6. Geo-telemetry stats
        let mut geo_stats = Vec::new();
        let mut raw_geo = Vec::new();
        let mut total_geo_hits = 0u64;

        if let Some(ch) = channel {
            let mut stmt = conn.prepare("SELECT country_code, country_name, SUM(hit_count) as hits FROM geo_stats WHERE hour_timestamp >= ?1 AND channel = ?2 GROUP BY country_code ORDER BY hits DESC LIMIT 5")?;
            let rows = stmt.query_map(params![cutoff_24h, ch], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u64>(2)?,
                ))
            })?;
            for r in rows.flatten() {
                total_geo_hits += r.2;
                raw_geo.push(r);
            }
        } else {
            let mut stmt = conn.prepare("SELECT country_code, country_name, SUM(hit_count) as hits FROM geo_stats WHERE hour_timestamp >= ?1 GROUP BY country_code ORDER BY hits DESC LIMIT 5")?;
            let rows = stmt.query_map(params![cutoff_24h], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u64>(2)?,
                ))
            })?;
            for r in rows.flatten() {
                total_geo_hits += r.2;
                raw_geo.push(r);
            }
        }

        for (country_code, country_name, hits) in raw_geo {
            let pct = if total_geo_hits > 0 {
                (hits as f32 / total_geo_hits as f32) * 100.0
            } else {
                0.0
            };
            geo_stats.push(GeoStat {
                country_code,
                country_name,
                hits,
                pct,
            });
        }

        // 7. Recent threat events
        let mut recent_threats = Vec::new();
        if let Some(ch) = channel {
            let mut stmt = conn.prepare("SELECT timestamp, channel, domain, threat_type, source_ip, details FROM threat_events WHERE channel = ?1 ORDER BY timestamp DESC LIMIT 5")?;
            let rows = stmt.query_map(params![ch], |r| {
                Ok(ThreatRecord {
                    timestamp: r.get(0)?,
                    channel: r.get(1)?,
                    domain: r.get(2)?,
                    threat_type: r.get(3)?,
                    source_ip: r.get(4)?,
                    details: r.get(5)?,
                })
            })?;
            for r in rows.flatten() {
                recent_threats.push(r);
            }
        } else {
            let mut stmt = conn.prepare("SELECT timestamp, channel, domain, threat_type, source_ip, details FROM threat_events ORDER BY timestamp DESC LIMIT 5")?;
            let rows = stmt.query_map([], |r| {
                Ok(ThreatRecord {
                    timestamp: r.get(0)?,
                    channel: r.get(1)?,
                    domain: r.get(2)?,
                    threat_type: r.get(3)?,
                    source_ip: r.get(4)?,
                    details: r.get(5)?,
                })
            })?;
            for r in rows.flatten() {
                recent_threats.push(r);
            }
        }

        Ok(AnalyticsSummary {
            ingress_24h,
            unique_visitors_24h,
            active_visitors: 0,
            breaches_blocked,
            active_bans_count,
            top_pages,
            top_referrers,
            geo_stats,
            recent_threats,
            banned_ips,
        })
    }

    fn is_crawler(ua: &str) -> bool {
        let ua_lower = ua.to_lowercase();
        ua_lower.contains("bot")
            || ua_lower.contains("crawl")
            || ua_lower.contains("spider")
            || ua_lower.contains("slurp")
            || ua_lower.contains("google")
            || ua_lower.contains("bing")
            || ua_lower.contains("yandex")
            || ua_lower.contains("curl")
            || ua_lower.contains("python")
            || ua_lower.contains("wget")
    }

    fn clean_referrer(raw: Option<&str>) -> String {
        match raw {
            Some(s) if s == "-" || s.trim().is_empty() => "direct_neural".to_string(),
            Some(s) => {
                if let Some(host) = s
                    .strip_prefix("https://")
                    .or_else(|| s.strip_prefix("http://"))
                {
                    let domain = host.split('/').next().unwrap_or(host);
                    domain.split(':').next().unwrap_or(domain).to_string()
                } else {
                    s.to_string()
                }
            }
            None => "direct_neural".to_string(),
        }
    }
}
