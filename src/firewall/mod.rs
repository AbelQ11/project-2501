// src/firewall/mod.rs
use std::collections::HashMap;
use std::io;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::{error, info, warn};

use crate::netutil;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Nftables,
    Iptables,
    Disabled,
}

pub struct FirewallManager {
    backend: FirewallBackend,
    ban_duration_secs: u64,
    /// iptables has no native timeout support, so we track expirations here and
    /// remove the rules from the periodic maintenance tick in `main.rs`.
    iptables_bans: Mutex<HashMap<String, Instant>>,
}

impl FirewallManager {
    pub fn new(enabled: bool, ban_duration_minutes: u64) -> Self {
        let ban_duration_secs = ban_duration_minutes * 60;

        if !enabled {
            info!("Firewall active defense is DISABLED in configuration.");
            return Self {
                backend: FirewallBackend::Disabled,
                ban_duration_secs,
                iptables_bans: Mutex::new(HashMap::new()),
            };
        }

        // 1. Try initializing nftables (preferred: kernel handles ban timeouts).
        if Self::command_available("nft") {
            match Self::init_nftables() {
                Ok(()) => {
                    info!("Firewall Active Defense: initialized kernel nftables drop table 'project2501'.");
                    return Self {
                        backend: FirewallBackend::Nftables,
                        ban_duration_secs,
                        iptables_bans: Mutex::new(HashMap::new()),
                    };
                }
                Err(error) => {
                    warn!(
                        "nftables initialization failed ({}); trying iptables.",
                        error
                    );
                }
            }
        }

        // 2. Fallback to iptables.
        if Self::command_available("iptables") {
            info!("Firewall Active Defense: using iptables backend.");
            return Self {
                backend: FirewallBackend::Iptables,
                ban_duration_secs,
                iptables_bans: Mutex::new(HashMap::new()),
            };
        }

        warn!("Firewall Active Defense: neither nftables nor iptables available with required permissions.");
        Self {
            backend: FirewallBackend::Disabled,
            ban_duration_secs,
            iptables_bans: Mutex::new(HashMap::new()),
        }
    }

    fn command_available(command: &str) -> bool {
        Command::new(command)
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn run_nft(args: &[&str]) -> Result<(), io::Error> {
        let output = Command::new("nft").args(args).output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ))
        }
    }

    fn init_nftables() -> Result<(), io::Error> {
        // `nft add table` fails when the table already exists. Detect that case
        // and keep existing bans across daemon restarts.
        let already_exists = Command::new("nft")
            .args(["list", "table", "inet", "project2501"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);

        if already_exists {
            return Ok(());
        }

        Self::run_nft(&["add", "table", "inet", "project2501"])?;
        Self::run_nft(&[
            "add",
            "set",
            "inet",
            "project2501",
            "blacklist",
            "{ type ipv4_addr; flags timeout; }",
        ])?;
        Self::run_nft(&[
            "add",
            "chain",
            "inet",
            "project2501",
            "input",
            "{ type filter hook input priority -10; policy accept; }",
        ])?;
        Self::run_nft(&[
            "add",
            "rule",
            "inet",
            "project2501",
            "input",
            "ip",
            "saddr",
            "@blacklist",
            "drop",
        ])?;

        Ok(())
    }

    /// Ban an attacker IP for the configured duration.
    pub fn ban_ip(&self, ip: &str, reason: &str) -> bool {
        if self.backend == FirewallBackend::Disabled {
            return false;
        }

        if netutil::is_internal_ip(ip) {
            warn!(
                "[FIREWALL] Guard prevented banning internal address: {}",
                ip
            );
            return false;
        }

        match self.backend {
            FirewallBackend::Nftables => {
                // Remove a previous element so the timeout is refreshed.
                let _ = Self::run_nft(&[
                    "delete",
                    "element",
                    "inet",
                    "project2501",
                    "blacklist",
                    &format!("{{ {} }}", ip),
                ]);

                let element = format!("{{ {} timeout {}s }}", ip, self.ban_duration_secs);
                match Self::run_nft(&[
                    "add",
                    "element",
                    "inet",
                    "project2501",
                    "blacklist",
                    &element,
                ]) {
                    Ok(()) => {
                        warn!(
                            "[攻性防壁] ICE ACTIVATED: Banned IP {} via nftables for {}s (Reason: {})",
                            ip, self.ban_duration_secs, reason
                        );
                        true
                    }
                    Err(error) => {
                        error!("[FIREWALL] nftables ban failed for {}: {}", ip, error);
                        false
                    }
                }
            }
            FirewallBackend::Iptables => {
                if self.iptables_rule_exists(ip) {
                    self.track_iptables_ban(ip);
                    return true;
                }

                if self.insert_iptables_rule(ip) {
                    self.track_iptables_ban(ip);
                    warn!(
                        "[攻性防壁] ICE ACTIVATED: Banned IP {} via iptables for {}s (Reason: {})",
                        ip, self.ban_duration_secs, reason
                    );
                    true
                } else {
                    false
                }
            }
            FirewallBackend::Disabled => false,
        }
    }

    /// Remove expired iptables rules. nftables expires entries in the kernel and
    /// needs no maintenance. Called once per minute from the main loop.
    pub fn prune_expired(&self) {
        if self.backend != FirewallBackend::Iptables {
            return;
        }

        let now = Instant::now();
        let expired: Vec<String> = match self.iptables_bans.lock() {
            Ok(mut bans) => {
                let expired = bans
                    .iter()
                    .filter(|(_, expires_at)| **expires_at <= now)
                    .map(|(ip, _)| ip.clone())
                    .collect();
                bans.retain(|_, expires_at| *expires_at > now);
                expired
            }
            Err(_) => return,
        };

        for ip in expired {
            info!("[FIREWALL] Ban expired for {}; removing iptables rule.", ip);
            self.unban_ip(&ip);
        }
    }

    /// Unban an IP manually.
    pub fn unban_ip(&self, ip: &str) -> bool {
        if let Ok(mut bans) = self.iptables_bans.lock() {
            bans.remove(ip);
        }

        match self.backend {
            FirewallBackend::Nftables => Self::run_nft(&[
                "delete",
                "element",
                "inet",
                "project2501",
                "blacklist",
                &format!("{{ {} }}", ip),
            ])
            .is_ok(),
            FirewallBackend::Iptables => Command::new("iptables")
                .args([
                    "-D",
                    "INPUT",
                    "-s",
                    ip,
                    "-j",
                    "DROP",
                    "-m",
                    "comment",
                    "--comment",
                    "project2501",
                ])
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false),
            FirewallBackend::Disabled => false,
        }
    }

    /// Restore iptables rules after a daemon restart. The in-memory expiry map
    /// is lost on restart, so remaining durations are read back from SQLite.
    pub fn restore_bans(&self, bans: &[(String, i64)]) {
        if self.backend != FirewallBackend::Iptables {
            return;
        }

        let now = chrono::Utc::now().timestamp();
        let mut restored = 0usize;

        for (ip, expires_at) in bans {
            let remaining = *expires_at - now;
            if remaining <= 0 || netutil::is_internal_ip(ip) {
                continue;
            }

            if !self.iptables_rule_exists(ip) && !self.insert_iptables_rule(ip) {
                continue;
            }

            if let Ok(mut tracked) = self.iptables_bans.lock() {
                tracked.insert(
                    ip.clone(),
                    Instant::now() + Duration::from_secs(remaining as u64),
                );
                restored += 1;
            }
        }

        if restored > 0 {
            info!(
                "[FIREWALL] Restored {} active iptables ban(s) from the database.",
                restored
            );
        }
    }

    fn insert_iptables_rule(&self, ip: &str) -> bool {
        match Command::new("iptables")
            .args([
                "-I",
                "INPUT",
                "-s",
                ip,
                "-j",
                "DROP",
                "-m",
                "comment",
                "--comment",
                "project2501",
            ])
            .output()
        {
            Ok(output) if output.status.success() => true,
            Ok(output) => {
                error!(
                    "[FIREWALL] iptables ban failed for {}: {}",
                    ip,
                    String::from_utf8_lossy(&output.stderr)
                );
                false
            }
            Err(error) => {
                error!("[FIREWALL] Error invoking iptables: {}", error);
                false
            }
        }
    }

    fn iptables_rule_exists(&self, ip: &str) -> bool {
        Command::new("iptables")
            .args([
                "-C",
                "INPUT",
                "-s",
                ip,
                "-j",
                "DROP",
                "-m",
                "comment",
                "--comment",
                "project2501",
            ])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn track_iptables_ban(&self, ip: &str) {
        if let Ok(mut bans) = self.iptables_bans.lock() {
            bans.insert(
                ip.to_string(),
                Instant::now() + Duration::from_secs(self.ban_duration_secs),
            );
        }
    }
}
