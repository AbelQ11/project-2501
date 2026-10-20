use crate::logwatch::ThreatLevel;
use std::collections::HashMap;
use std::time::{Duration, Instant};

struct IpTracker {
    recent_errors: Vec<Instant>,
    last_alert: Option<Instant>,
}

impl IpTracker {
    fn new() -> Self {
        Self {
            recent_errors: Vec::new(),
            last_alert: None,
        }
    }

    fn record_error(&mut self, now: Instant, window: Duration) -> usize {
        self.recent_errors
            .retain(|&t| now.duration_since(t) <= window);
        self.recent_errors.push(now);
        self.recent_errors.len()
    }

    fn can_alert(&mut self, now: Instant, cooldown: Duration) -> bool {
        if let Some(last) = self.last_alert {
            if now.duration_since(last) < cooldown {
                return false;
            }
        }
        self.last_alert = Some(now);
        true
    }
}

pub struct AnomalyEngine {
    trackers: HashMap<String, IpTracker>,
    scan_threshold: usize,
    window_duration: Duration,
    cooldown_duration: Duration,
}

impl AnomalyEngine {
    pub fn new(scan_threshold: usize, window_secs: u64, cooldown_mins: u64) -> Self {
        Self {
            trackers: HashMap::new(),
            scan_threshold,
            window_duration: Duration::from_secs(window_secs),
            cooldown_duration: Duration::from_secs(cooldown_mins * 60),
        }
    }

    /// Evaluates an event. Returns Some((ThreatLevel, String)) if an alert should be triggered.
    pub fn evaluate_event(
        &mut self,
        ip: &str,
        status: u16,
        direct_threat: &ThreatLevel,
    ) -> Option<(String, String)> {
        let now = Instant::now();
        let tracker = self
            .trackers
            .entry(ip.to_string())
            .or_insert_with(IpTracker::new);

        // 1. Direct Critical or Suspicious Hits (e.g. /.env, traversal)
        match direct_threat {
            ThreatLevel::Critical(desc) => {
                if tracker.can_alert(now, self.cooldown_duration) {
                    return Some(("CRITICAL // BREACH ATTEMPT".to_string(), desc.clone()));
                }
            }
            ThreatLevel::Suspicious(desc) => {
                if tracker.can_alert(now, self.cooldown_duration) {
                    return Some(("SUSPICIOUS // ASSET RECON".to_string(), desc.clone()));
                }
            }
            ThreatLevel::None => {}
        }

        // 2. Behavioral: 4xx Burst / Fuzzing Detection
        if (400..500).contains(&status) {
            let error_count = tracker.record_error(now, self.window_duration);
            if error_count >= self.scan_threshold && tracker.can_alert(now, self.cooldown_duration)
            {
                return Some((
                    "BEHAVIORAL // RAPID SCAN BURST".to_string(),
                    format!(
                        "Encountered {} HTTP 4xx error responses within {:?}",
                        error_count, self.window_duration
                    ),
                ));
            }
        }

        None
    }

    /// Periodically sweeps stale IP trackers to prevent memory leaks.
    ///
    /// A tracker is kept only if it has 4xx hits inside the current detection
    /// window or if it alerted recently. Previously, a tracker with a handful of
    /// old 4xx hits and no alert was kept forever.
    pub fn prune_stale(&mut self) {
        let now = Instant::now();
        let max_age = self.cooldown_duration * 2;
        let window = self.window_duration;

        self.trackers.retain(|_, tracker| {
            tracker
                .recent_errors
                .retain(|timestamp| now.duration_since(*timestamp) <= window);

            let has_recent_errors = !tracker.recent_errors.is_empty();
            let recently_alerted = tracker
                .last_alert
                .map(|last| now.duration_since(last) < max_age)
                .unwrap_or(false);

            has_recent_errors || recently_alerted
        });
    }
}
