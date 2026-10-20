// src/server/routes.rs
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    serve, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::sync::{broadcast::Sender, mpsc};
use tower_http::services::ServeDir;

use crate::config::Config;
use crate::engine::ActiveSessionPool;
use crate::firewall::FirewallManager;
use crate::logwatch::{ChannelTarget, ParsedChannelEvent};
use crate::netutil;
use crate::server::sse::sse_handler;
use crate::storage::{AnalyticsSummary, Database, StorageMessage};

#[derive(Clone)]
pub struct AppState {
    pub sse_tx: Sender<ParsedChannelEvent>,
    pub db: Arc<Database>,
    pub firewall: Arc<FirewallManager>,
    pub sessions: Arc<Mutex<ActiveSessionPool>>,
    pub config: Config,
    pub storage_tx: mpsc::Sender<StorageMessage>,
}

#[derive(Debug, Deserialize)]
pub struct StatsQuery {
    pub channel: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UnbanRequest {
    pub ip: String,
}

#[derive(Debug, Serialize)]
pub struct UnbanResponse {
    pub status: String,
    pub ip: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct BanRequest {
    pub ip: String,
    pub reason: Option<String>,
    pub duration_minutes: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct BanResponse {
    pub status: String,
    pub ip: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct InfoResponse {
    pub interface: String,
    pub server_public_ip: String,
    pub dashboard_bind: String,
    pub dashboard_port: u16,
    pub firewall_enabled: bool,
    pub channels: Vec<ChannelTarget>,
}

pub async fn info_handler(State(state): State<AppState>) -> Json<InfoResponse> {
    Json(InfoResponse {
        interface: state.config.interface.clone(),
        server_public_ip: state.config.server_public_ip.clone(),
        dashboard_bind: state.config.dashboard_bind.clone(),
        dashboard_port: state.config.dashboard_port,
        firewall_enabled: state.config.firewall_enabled,
        channels: state.config.channels.clone(),
    })
}

pub async fn stats_handler(
    State(state): State<AppState>,
    Query(query): Query<StatsQuery>,
) -> Result<Json<AnalyticsSummary>, StatusCode> {
    let db = state.db.clone();
    let channel = query.channel;
    let channel_for_db = channel.clone();

    let mut summary =
        tokio::task::spawn_blocking(move || db.get_analytics_summary(channel_for_db.as_deref()))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    summary.active_visitors = state
        .sessions
        .lock()
        .map(|mut pool| pool.count_active(channel.as_deref()) as u64)
        .unwrap_or(0);

    Ok(Json(summary))
}

pub async fn unban_handler(
    State(state): State<AppState>,
    Json(payload): Json<UnbanRequest>,
) -> Result<Json<UnbanResponse>, StatusCode> {
    let ip = payload.ip.trim().to_string();
    if netutil::parse_ip(&ip).is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // 1. Unban from kernel firewall (nftables/iptables)
    let kernel_removed = state.firewall.unban_ip(&ip);

    // 2. Remove from SQLite active_bans
    let db = state.db.clone();
    let ip_clone = ip.clone();
    tokio::task::spawn_blocking(move || {
        let _ = db.unban_ip(&ip_clone);
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    tracing::info!("[攻性防壁] 1-Click Unban: lifted ban for IP {}", ip);

    let (status, message) = if kernel_removed {
        ("success", "Ban lifted from kernel firewall and ledger.")
    } else {
        (
            "ledger_only",
            "Removed from the ledger; no active kernel rule was found (firewall disabled or already expired).",
        )
    };

    Ok(Json(UnbanResponse {
        status: status.to_string(),
        ip,
        message: message.to_string(),
    }))
}

pub async fn ban_handler(
    State(state): State<AppState>,
    Json(payload): Json<BanRequest>,
) -> Result<Json<BanResponse>, StatusCode> {
    let ip = payload.ip.trim().to_string();
    if netutil::parse_ip(&ip).is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Guard: refuse to ban whitelisted IPs
    if state.config.is_whitelisted(&ip) {
        tracing::warn!("[攻性防壁] REFUSED manual ban on whitelisted IP: {}", ip);
        return Ok(Json(BanResponse {
            status: "rejected".to_string(),
            ip,
            message: "IP is whitelisted — cannot be banned.".to_string(),
        }));
    }

    let reason = payload
        .reason
        .clone()
        .unwrap_or_else(|| "MANUAL ICE BAN".to_string());
    let duration_min = payload
        .duration_minutes
        .unwrap_or(state.config.ban_duration_minutes);
    let duration_secs = duration_min * 60;

    // 1. Ban in kernel firewall
    let banned = state.firewall.ban_ip(&ip, &reason);
    if !banned {
        return Ok(Json(BanResponse {
            status: "failed".to_string(),
            ip,
            message: "Firewall backend rejected the ban (disabled or internal address guard)."
                .to_string(),
        }));
    }

    // 2. Record to active_bans via storage worker
    let _ = state
        .storage_tx
        .send(StorageMessage::Ban {
            ip: ip.clone(),
            channel: "manual".to_string(),
            domain: "HUD-operator".to_string(),
            country: "??".to_string(),
            reason: reason.clone(),
            duration_secs,
        })
        .await;

    // 3. Record as threat event
    let _ = state
        .storage_tx
        .send(StorageMessage::Threat {
            channel: "manual".to_string(),
            domain: "HUD-operator".to_string(),
            threat_type: "MANUAL_ICE_BAN".to_string(),
            source_ip: ip.clone(),
            details: format!("{} [FIREWALL: BANNED {}m]", reason, duration_min),
        })
        .await;

    tracing::warn!(
        "[攻性防壁] MANUAL ICE BAN ENGAGED: {} for {}m ({})",
        ip,
        duration_min,
        reason
    );

    Ok(Json(BanResponse {
        status: "success".to_string(),
        ip,
        message: format!("Kernel firewall DROP rule engaged for {}m.", duration_min),
    }))
}

/// Resolve the static web root without hardcoding a deployment path.
fn resolve_web_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("WEB_DIR") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }

    let direct = PathBuf::from("web");
    if direct.is_dir() {
        return direct;
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for candidate in [dir.join("web"), dir.join("../web"), dir.join("../../web")] {
                if candidate.is_dir() {
                    return candidate;
                }
            }
        }
    }

    direct
}

/// Build the Axum router that serves static assets, SSE, stats, info, ban and unban endpoints.
pub fn build_router(state: AppState) -> Router {
    let static_service = ServeDir::new(resolve_web_dir());

    Router::new()
        .route("/api/live", get(sse_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/info", get(info_handler))
        .route("/api/ban", post(ban_handler))
        .route("/api/unban", post(unban_handler))
        .fallback_service(static_service)
        .with_state(state)
}

/// Run the dashboard server on the address from the config.
pub async fn run_server(
    config: Config,
    sse_tx: Sender<ParsedChannelEvent>,
    db: Arc<Database>,
    firewall: Arc<FirewallManager>,
    sessions: Arc<Mutex<ActiveSessionPool>>,
    storage_tx: mpsc::Sender<StorageMessage>,
) {
    let state = AppState {
        sse_tx,
        db,
        firewall,
        sessions,
        config: config.clone(),
        storage_tx,
    };
    let router = build_router(state);
    let bind_addr: SocketAddr = format!("{}:{}", config.dashboard_bind, config.dashboard_port)
        .parse()
        .expect("Invalid dashboard bind address");
    // Create an asynchronous tokio TCP listener bound to the address
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("Failed to bind dashboard address");
    tracing::info!("Dashboard HUD server listening on http://{}", bind_addr);
    // Serve the router using axum::serve
    serve(listener, router)
        .await
        .expect("Failed to run dashboard server");
}
