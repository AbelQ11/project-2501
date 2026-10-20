# [公安9課] PROJECT 2501 // CYBERBRAIN NETWORK MONITOR & ANALYTICS DAEMON

> *"The Net is vast and infinite..."* — Motoko Kusanagi

An ultra-lightweight, high-performance Linux security daemon and privacy-respecting real-time web analytics engine written in **modern, memory-safe Rust**. Inspired by *Ghost in the Shell*, **Project 2501** merges low-level network perimeter defense (L3/L4 raw socket packet inspection), web application intrusion prevention (L7 Nginx log tailing & automated kernel firewall bans), and sub-millisecond real-time web analytics with a Public Security Section 9 cyberpunk tactical HUD.

---

## Key Capabilities

### 1. Fail2ban Active Defense (Kernel IPS)
- **Automated Kernel Drops:** Detects intrusion attempts (sensitive probes like `/.env`, `/wp-config.php`, SQL injections, directory traversal, rapid 404 scan bursts) and instantly triggers kernel-level drops via **`nftables`** (or `iptables`).
- **Automatic Expiration:** With the preferred `nftables` backend, kernel set timeouts (e.g. 60 minutes) lift expired rules automatically. The `iptables` fallback tracks expirations in memory and removes rules from the daemon's once-per-minute maintenance tick.
- **1-Click Unban:** Revoke any active ban directly from the Section 9 HUD terminal with a single click.
- **Anti-Lockout Protection:** Internal network ranges (`127.0.0.1`, `10.x.x.x`, `192.168.x.x`) are protected against accidental bans.

### 2. Privacy-First Web Analytics (Umami / Plausible Alternative)
- **Zero JavaScript Tracking Snippets:** No client-side script tag needed. Traffic is captured at the server level via inotify on Nginx logs.
- **100% Ad-Blocker Immune:** Cannot be blocked by uBlock, Brave, or Safari privacy protections.
- **GDPR & Privacy Compliant:** Raw IPs are never stored in analytics tables. Visitor sessions are tracked using SHA-256 hashes:
  $$\text{VisitorHash} = \text{SHA256}(\text{Client IP} + \text{User-Agent} + \text{Salt} + \text{UTC day})$$
- **Crawler & Bot Filtering:** Automatically classifies human visitors versus automated scrapers (`Googlebot`, `Bingbot`, `python-requests`, etc.).

### 3. L3/L4 Perimeter Sentry (Raw Sockets)
- **Raw Network Sniffing:** Captures raw IPv4 TCP packets on your network interface (e.g., `enp0s6`) using low-level sockets.
- **SYN Flood & Port Sweep Detection:** Detects SYN floods ($> 30$ SYN packets in 5s) and port scans ($> 10$ unique ports probed in 10s) before traffic even hits Nginx or user-space services.
- **Graceful Privilege Fallback:** Operates with Linux capability `CAP_NET_RAW` / `CAP_NET_ADMIN` without requiring full root access.

### 4. Storage Engine (`cyberbrain.db`)
- **WAL Mode SQLite:** Zero disk thrashing. Hits are buffered in memory and committed in batched transactions every 5 seconds or 100 hits.
- **Compact Rollups (< 50 MB / year):** Stores hourly aggregated rollups rather than infinite raw logs.
- **24-Hour Rolling Metrics:** Computes top visited paths, referrers, geo-distribution, and active bans dynamically.

### 5. Tactical Alerting
- **Discord Webhooks:** Rich tactical embeds (crimson for critical breaches, green for nominal operations).
- **Encrypted SMTP TLS Email:** RFC-5322 formatted emails sent to your secure inbox (e.g., Proton Mail) with anti-storm alert cooldowns.

### 6. Section 9 Cyberbrain Tactical HUD
- Authentically styled after *Ghost in the Shell* (1995) and *Stand Alone Complex*.
- **Ghost Line:** Real-time HTML5 Canvas EEG brainwave oscilloscope responding to traffic pulse.
- **Active ICE Barrier Grid:** Visual intrusion countermeasure hex cells.
- **Live Tail Stream:** Sub-millisecond Server-Sent Events (SSE) feed.
- **Active ICE Blacklist:** Live table displaying banned intruders, detection reasons, country tags, and remaining ban duration timers.

---

## Architecture

```text
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │                              PROJECT 2501 DAEMON (RUST)                               │
 │                                                                                        │
 │    ┌───────────────────────────────┐              ┌───────────────────────────────┐    │
 │    │       PERIMETER SENTRY        │              │          WEB SENTRY           │    │
 │    │  Raw Socket on `enp0s6`       │              │  Tailing Nginx Access Logs    │    │
 │    │  - TCP SYN flag inspection    │              │  - Zero-copy line parser      │    │
 │    │  - Port scan / flood checks   │              │  - 4xx bursts, .env, SQLi     │    │
 │    └───────────────┬───────────────┘              └───────────────┬───────────────┘    │
 │                    │                                              │                    │
 │                    ▼                                              ▼                    │
 │            ┌─────────────────────────────────┐                    │                    │
 │            │     ANOMALY & COOLDOWN CORE     │                    │                    │
 │            │  - Sliding window rate-limit    │                    │                    │
 │            │  - Anti-storm alert cooldowns   │                    │                    │
 │            └───────────────┬─────────────────┘                    │                    │
 │                            │                                      │                    │
 │                            ▼                                      ▼                    │
 │            ┌─────────────────────────────────┐   ┌─────────────────────────────────┐   │
 │            │   FIREWALL ACTIVE DEFENSE (IPS) │   │     ANALYTICS & STORAGE (WAL)   │   │
 │            │  - Kernel nftables drops        │   │  - Batched commits (every 5s)   │   │
 │            │  - Auto-expiration (60m)        │   │  - SQLite rollups & Geo-cache   │   │
 │            └───────────────┬─────────────────┘   └────────────────┬────────────────┘   │
 │                            │                                      │                    │
 │                            ▼                                      ▼                    │
 │            ┌─────────────────────────────────┐   ┌─────────────────────────────────┐   │
 │            │   TACTICAL ALERT DISPATCHER     │   │      AXUM HTTP & SSE SERVER     │   │
 │            │  - Discord Webhooks             │   │  - /api/live (SSE Stream)       │   │
 │            │  - Encrypted TLS SMTP Email     │   │  - /api/stats (24h Analytics)   │   │
 │            └─────────────────────────────────┘   │  - /api/unban (1-Click Action)  │   │
 │                                                  └────────────────┬────────────────┘   │
 └───────────────────────────────────────────────────────────────────┼────────────────────┘
                                                                     │ Loopback / Tunnel
                                                                     ▼
                                                    ┌─────────────────────────────────┐
                                                    │     SECTION 9 TACTICAL HUD      │
                                                    │  (HTML5 / Modular CSS & JS)     │
                                                    └─────────────────────────────────┘
```

---

## Quick Start & Installation

### 1. Automated Setup Wizard
Clone the repository and run the automated setup script on your server:

```bash
git clone https://github.com/kiliotsu/2501-project.git
cd 2501-project
sudo ./scripts/setup.sh
```

The wizard will:
1. Scan `/etc/nginx/sites-enabled/` and `/etc/nginx/conf.d/` for running websites.
2. Prompt you interactively to choose which sites to monitor.
3. Auto-detect your public IP and active network interface.
4. Ask for your Discord webhook URL and, if you want email alerts, your SMTP host, sender address, password and recipient address. Credentials are never hardcoded in the script.
5. Configure kernel firewall active defense (`nftables`), write `.env` with `600` permissions, and install the systemd service with required Linux capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW`).

---

### 2. Build & Run

To build the optimized release binary:
```bash
cargo build --release
```

To run manually:
```bash
./target/release/project-2501
```

To manage via systemd:
```bash
sudo systemctl enable --now project-2501.service
sudo systemctl status project-2501.service
```

---

##  Secure Dashboard Access via SSH Tunnel

For security, the dashboard listens on loopback (`127.0.0.1:2501`) and is accessed via an SSH local forward tunnel:

Add this to your local machine's `~/.ssh/config`:
```ssh
Host whatever-config-name
    HostName public-ip-of-your-server
    User whatever-is-the-username-on-server
    Port 22
    IdentityFile path/to/your/key
    LocalForward 2501 127.0.0.1:2501
```

1. Open the SSH connection:
   ```bash
   ssh config-name
   ```
2. Open your local browser and navigate to:
   ```
   http://localhost:2501/
   ```

---

##  API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/` | `GET` | Main Section 9 Cyberbrain HUD terminal |
| `/sites/free-game-deals.html` | `GET` | Channel 1 dedicated telemetry HUD |
| `/sites/sibyl-system.html` | `GET` | Channel 2 dedicated telemetry HUD |
| `/api/live` | `GET` | Real-time Server-Sent Events (SSE) log tail |
| `/api/stats` | `GET` | 24h rolling summary, active sessions, top pages, referrers, geo-stats, active bans (`?channel=` supported) |
| `/api/info` | `GET` | Interface, public endpoint, firewall state and configured channels (used by the HUD navigation) |
| `/api/ban` | `POST` | Manually ban an IP (`{"ip": "x.x.x.x", "reason": "...", "duration_minutes": 60}`) |
| `/api/unban` | `POST` | 1-Click unban an IP from kernel firewall & database (`{"ip": "x.x.x.x"}`) |

---

##  Configuration (`.env`)

```ini
# [NETWORK PERIMETER]
INTERFACE=enp0s6
SERVER_PUBLIC_IP=your-server-public-ip

# [CHANNEL 1: FREE GAME DEALS]
CHANNEL_1_NAME=free-game-deals
CHANNEL_1_DOMAIN=free-game-deals.kiliotsu.eu
CHANNEL_1_LOG=/var/log/nginx/free-game-deals.kiliotsu.eu_access.log

# [CHANNEL 2: SIBYL SYSTEM]
CHANNEL_2_NAME=sibyl-system
CHANNEL_2_DOMAIN=sibyl-system.kiliotsu.eu
CHANNEL_2_LOG=/var/log/nginx/sibyl-system.kiliotsu.eu_access.log

# [ANOMALY THRESHOLDS]
SYN_FLOOD_THRESHOLD=30
SYN_WINDOW_SECONDS=5
SCAN_404_THRESHOLD=15
SCAN_WINDOW_SECONDS=10
ALERT_COOLDOWN_MINUTES=15

# [FIREWALL ACTIVE DEFENSE (FAIL2BAN IPS)]
FIREWALL_ENABLED=true
BAN_DURATION_MINUTES=60
IP_WHITELIST=

# [SMTP TLS EMAIL ALERTING]
# 465 = implicit TLS (SMTPS), 587 = STARTTLS
SMTP_ENABLED=true
SMTP_URL=ssl0.ovh.net
SMTP_PORT=465
SMTP_USER=alerts@example.com
SMTP_PASS=your_password
ALERT_TO=admin@example.com

# [DISCORD WEBHOOK ALERTING]
DISCORD_ENABLED=true
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your/webhook/url

# [STORAGE & DASHBOARD SERVER]
DB_PATH=cyberbrain.db
DASHBOARD_PORT=2501
DASHBOARD_BIND=127.0.0.1

# [PRIVACY / GEOIP]
# Random per-install secret used for visitor hashing.
VISITOR_SALT=replace_with_a_random_hex_string
# Optional MaxMind GeoLite2/GeoIP2 Country database.
GEOIP_DB_PATH=
```

---

##  License

Designed with reverence for Masamune Shirow and Mamoru Oshii's *Ghost in the Shell* (1995).