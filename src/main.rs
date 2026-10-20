// src/main.rs
mod alerts;
mod config;
mod engine;
mod firewall;
mod logwatch;
mod netutil;
mod network;
mod server;
mod storage;

use alerts::AlertDispatcher;
use config::Config;
use engine::{ActiveSessionPool, AnomalyEngine, GeoResolver};
use firewall::FirewallManager;
use logwatch::LogWatcherSupervisor;
use network::{NetThreatEvent, PerimeterSentry};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::logwatch::ParsedChannelEvent;
use crate::server::routes::run_server;
use crate::storage::{Database, StorageMessage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize Structured Logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    // 2. Load Configuration
    let config = Config::load();

    println!(
        r#"
================================================================
  [公安9課] PUBLIC SECURITY SECTION 9 // PROJECT 2501 SENTINEL DAEMON
  INTERFACE: {} // PUBLIC ENDPOINT: {}
================================================================
"#,
        config.interface,
        if config.server_public_ip.trim().is_empty() {
            "not configured"
        } else {
            &config.server_public_ip
        }
    );
    info!(
        "Configuration loaded. Interface target: {}",
        config.interface
    );
    if config.channels.is_empty() {
        warn!("No log channels configured. Only the L3/L4 perimeter sentry will run; set CHANNEL_N_* in .env.");
    }
    if config.server_public_ip.trim().is_empty() {
        warn!("SERVER_PUBLIC_IP is empty; the server's own public IP will not be whitelisted automatically.");
    }
    info!(
        "Alert routing -> Recipient: {} | Sender: {} | Discord: {}",
        config.alert_to,
        config.smtp_user,
        if config.discord_enabled {
            "ENABLED"
        } else {
            "DISABLED"
        }
    );
    info!(
        "Firewall active defense: {} (Ban duration: {}m)",
        if config.firewall_enabled {
            "ENABLED"
        } else {
            "DISABLED"
        },
        config.ban_duration_minutes
    );

    // 3. Initialize Storage Engine, GeoIP & Firewall
    let db = Arc::new(Database::open(&config.db_path)?);
    let (storage_tx, storage_rx) = mpsc::channel::<StorageMessage>(2048);
    db.clone().start_worker(storage_rx);

    let geo_resolver = GeoResolver::new(config.geoip_db_path.as_deref());
    let firewall = Arc::new(FirewallManager::new(
        config.firewall_enabled,
        config.ban_duration_minutes,
    ));

    // iptables has no persistent timeout metadata; restore remaining bans from
    // SQLite so a daemon restart does not leave permanent DROP rules behind.
    match db.active_bans_for_restore() {
        Ok(bans) => firewall.restore_bans(&bans),
        Err(error) => warn!("Could not load active bans for firewall restore: {}", error),
    }

    // 4. Initialize Engines & Alert Dispatcher
    let alert_dispatcher = AlertDispatcher::new(&config);

    // CLI Flag: Test Alert Simulation
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--test-alerts") {
        info!("Initiating Section 9 tactical test alert dispatch to Discord and Email...");
        alert_dispatcher
            .dispatch_threat(
                "test-channel",
                "test.kiliotsu.eu",
                "CRITICAL // TACTICAL SIMULATION",
                "127.0.0.1",
                &format!(
                    "Testing Project 2501 Discord webhook & SMTP delivery to {}",
                    config.alert_to
                ),
            )
            .await;
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
        info!("Test simulation complete. Check Discord and your Proton Mail inbox.");
        return Ok(());
    }

    let mut anomaly_engine = AnomalyEngine::new(
        config.scan_404_threshold as usize,
        config.scan_window_seconds,
        config.alert_cooldown_minutes,
    );
    let session_pool = Arc::new(Mutex::new(ActiveSessionPool::new(300))); // 5-minute active window

    // 5. Start Module A: L3/L4 Perimeter Sentry (Raw Sockets)
    let perimeter_sentry = Arc::new(PerimeterSentry::new(
        config.interface.clone(),
        config.syn_flood_threshold,
        config.syn_window_seconds,
    ));
    let (net_threat_tx, mut net_threat_rx) = mpsc::channel::<NetThreatEvent>(128);
    perimeter_sentry.start(net_threat_tx);

    // 6. Start Module B: L7 Log Watcher Supervisor
    let supervisor = LogWatcherSupervisor::new(config.channels.clone());
    let mut event_rx = supervisor.start();

    // Broadcast channel for SSE (server side uses the sender)
    let (sse_tx, _sse_rx) = broadcast::channel::<ParsedChannelEvent>(1024);
    // Spawn the dashboard server (runs independently)
    tokio::spawn(run_server(
        config.clone(),
        sse_tx.clone(),
        db.clone(),
        firewall.clone(),
        session_pool.clone(),
        storage_tx.clone(),
    ));
    info!(
        "Section 9 Sentinel is armed and monitoring all target log channels & network raw sockets."
    );

    // 7. Main Event Loop
    let mut prune_interval = tokio::time::interval(std::time::Duration::from_secs(60));

    loop {
        tokio::select! {
            // L7 Web Sentry Ingress Event
            Some(event) = event_rx.recv() => {
                let visitor_hash = ActiveSessionPool::compute_hash(
                    &event.entry.remote_addr,
                    &event.entry.user_agent,
                    &config.visitor_salt,
                );
                if let Ok(mut pool) = session_pool.lock() {
                    pool.record_hit(visitor_hash, &event.channel);
                }

                // Resolve Geo-IP country
                let country = geo_resolver.resolve(&event.entry.remote_addr);

                // Queue to batched SQLite storage worker with country
                let _ = storage_tx.send(StorageMessage::Hit {
                    event: event.clone(),
                    visitor_hash,
                    country: country.clone(),
                }).await;

                // Broadcast the event to any connected HUD clients
                let _ = sse_tx.send(event.clone());

                // Evaluate threats & dispatch alerts (skip whitelisted IPs)
                if !config.is_whitelisted(&event.entry.remote_addr) {
                    if let Some((threat_type, details)) = anomaly_engine.evaluate_event(
                        &event.entry.remote_addr,
                        event.entry.status,
                        &event.threat,
                    ) {
                        warn!(
                            "[!] ALARM TRIPPED on [{}] from {}: {} - {}",
                            event.channel, event.entry.remote_addr, threat_type, details
                        );

                        // 1. Trigger automated kernel firewall ban
                        let banned = firewall.ban_ip(&event.entry.remote_addr, &details);
                        let action_details = if banned {
                            format!(
                                "{} [FIREWALL: BANNED {}m]",
                                details, config.ban_duration_minutes
                            )
                        } else {
                            details.clone()
                        };

                        // 2. Record threat to storage ledger
                        let _ = storage_tx
                            .send(StorageMessage::Threat {
                                channel: event.channel.clone(),
                                domain: event.domain.clone(),
                                threat_type: threat_type.clone(),
                                source_ip: event.entry.remote_addr.clone(),
                                details: action_details.clone(),
                            })
                            .await;

                        // 3. If banned, record to active_bans
                        if banned {
                            let _ = storage_tx
                                .send(StorageMessage::Ban {
                                    ip: event.entry.remote_addr.clone(),
                                    channel: event.channel.clone(),
                                    domain: event.domain.clone(),
                                    country: country.0.clone(),
                                    reason: format!("{}: {}", threat_type, details),
                                    duration_secs: config.ban_duration_minutes * 60,
                                })
                                .await;
                        }

                        // 4. Dispatch tactical email and Discord alerts
                        alert_dispatcher
                            .dispatch_threat(
                                &event.channel,
                                &event.domain,
                                &threat_type,
                                &event.entry.remote_addr,
                                &action_details,
                            )
                            .await;
                    }
                } // end whitelist guard
            }

            // L3/L4 Raw Socket Perimeter Network Threat
            Some(net_threat) = net_threat_rx.recv() => {
                // Skip whitelisted IPs at the perimeter level too
                if config.is_whitelisted(&net_threat.source_ip) {
                    continue;
                }
                warn!(
                    "[!] PERIMETER ALARM TRIPPED on L3/L4 from {}: {} - {}",
                    net_threat.source_ip, net_threat.threat_type, net_threat.details
                );

                let country = geo_resolver.resolve(&net_threat.source_ip);
                let banned = firewall.ban_ip(&net_threat.source_ip, &net_threat.details);
                let action_details = if banned {
                    format!("{} [FIREWALL: BANNED {}m]", net_threat.details, config.ban_duration_minutes)
                } else {
                    net_threat.details.clone()
                };

                let _ = storage_tx.send(StorageMessage::Threat {
                    channel: "perimeter".to_string(),
                    domain: config.interface.clone(),
                    threat_type: net_threat.threat_type.clone(),
                    source_ip: net_threat.source_ip.clone(),
                    details: action_details.clone(),
                }).await;

                if banned {
                    let _ = storage_tx.send(StorageMessage::Ban {
                        ip: net_threat.source_ip.clone(),
                        channel: "perimeter".to_string(),
                        domain: config.interface.clone(),
                        country: country.0.clone(),
                        reason: format!("{}: {}", net_threat.threat_type, net_threat.details),
                        duration_secs: config.ban_duration_minutes * 60,
                    }).await;
                }

                alert_dispatcher
                    .dispatch_threat(
                        "perimeter-l3-l4",
                        &config.interface,
                        &net_threat.threat_type,
                        &net_threat.source_ip,
                        &action_details,
                    )
                    .await;
            }

            _ = prune_interval.tick() => {
                anomaly_engine.prune_stale();
                firewall.prune_expired();
            }
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received. Shutting down Project 2501 Sentinel cleanly.");
                break;
            }
        }
    }

    Ok(())
}
