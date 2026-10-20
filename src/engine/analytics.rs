use std::collections::HashMap;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

pub struct ActiveSessionPool {
    active_visitors: HashMap<u64, (String, Instant)>, // Hash -> (Channel, LastSeen)
    session_ttl: Duration,
}

impl ActiveSessionPool {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            active_visitors: HashMap::new(),
            session_ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Computes a privacy-respecting visitor identifier without storing raw PII.
    ///
    /// The hash mixes IP + User-Agent + a per-install secret salt + the current
    /// UTC day, using SHA-256. It is truncated to 64 bits for compact storage.
    pub fn compute_hash(ip: &str, user_agent: &str, salt: &str) -> u64 {
        let day = chrono::Utc::now().format("%Y-%m-%d").to_string();

        let mut hasher = Sha256::new();
        hasher.update(b"project2501\0");
        hasher.update(ip.as_bytes());
        hasher.update(b"\0");
        hasher.update(user_agent.as_bytes());
        hasher.update(b"\0");
        hasher.update(salt.as_bytes());
        hasher.update(b"\0");
        hasher.update(day.as_bytes());

        let digest = hasher.finalize();
        u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 digest is 32 bytes"))
    }

    /// Records visitor activity.
    pub fn record_hit(&mut self, visitor_hash: u64, channel: &str) {
        self.active_visitors
            .insert(visitor_hash, (channel.to_string(), Instant::now()));
    }

    /// Returns active count for a specific channel or for all channels.
    pub fn count_active(&mut self, channel: Option<&str>) -> usize {
        let now = Instant::now();
        self.active_visitors
            .retain(|_, (_, last)| now.duration_since(*last) <= self.session_ttl);

        match channel {
            Some(ch) => self
                .active_visitors
                .values()
                .filter(|(c, _)| c == ch)
                .count(),
            None => self.active_visitors.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_salt_sensitive() {
        let a = ActiveSessionPool::compute_hash("203.0.113.7", "Firefox", "salt-a");
        let b = ActiveSessionPool::compute_hash("203.0.113.7", "Firefox", "salt-a");
        let c = ActiveSessionPool::compute_hash("203.0.113.7", "Firefox", "salt-b");

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn counts_only_active_sessions() {
        let mut pool = ActiveSessionPool::new(300);
        pool.record_hit(1, "a");
        pool.record_hit(2, "a");
        pool.record_hit(3, "b");

        assert_eq!(pool.count_active(None), 3);
        assert_eq!(pool.count_active(Some("a")), 2);
        assert_eq!(pool.count_active(Some("b")), 1);
    }
}
