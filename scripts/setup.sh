#!/usr/bin/env bash
# ==============================================================================
# PROJECT 2501 // SECTION 9 CYBERBRAIN TERMINAL - SETUP & DISCOVERY WIZARD
# Scans active Nginx websites, creates new webpages, and generates HUD pages
# ==============================================================================

set -euo pipefail

# ANSI Cyberpunk Terminal Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
AMBER='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

clear
echo -e "${GREEN}${BOLD}"
cat << "EOF"
================================================================================
  [公安9課] PUBLIC SECURITY SECTION 9 // PROJECT 2501 SENTINEL DAEMON SETUP
       AUTOMATED WEBSITE DISCOVERY & HUD WEBPAGE GENERATOR
================================================================================
EOF
echo -e "${NC}"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${PROJECT_DIR}/.env"
WEB_SITES_DIR="${PROJECT_DIR}/web/sites"
mkdir -p "${WEB_SITES_DIR}"

echo -e "${CYAN}[1/5] Inspecting host network perimeter...${NC}"

# Detect default network interface
DEFAULT_IFACE="$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' || echo 'eth0')"
echo -e "  * Detected Network Interface: ${BOLD}${DEFAULT_IFACE}${NC}"

# Detect Public IP
DETECTED_IP="$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || curl -s --max-time 3 https://ifconfig.me 2>/dev/null || ip -4 addr show "${DEFAULT_IFACE}" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1 || echo '')"
echo -e "  * Detected Public Gateway IP: ${BOLD}${DETECTED_IP}${NC}"

read -r -p "$(echo -e "${AMBER}[?] Confirm Network Interface [${DEFAULT_IFACE}]: ${NC}")" INPUT_IFACE
INTERFACE="${INPUT_IFACE:-$DEFAULT_IFACE}"

read -r -p "$(echo -e "${AMBER}[?] Confirm Server Public IP [${DETECTED_IP}]: ${NC}")" INPUT_IP
SERVER_PUBLIC_IP="${INPUT_IP:-$DETECTED_IP}"

echo -e "\n${CYAN}[2/5] Scanning local Nginx virtual hosts & access logs...${NC}"

DISCOVERED_SITES=()
NGINX_DIRS=("/etc/nginx/sites-enabled" "/etc/nginx/conf.d")

for dir in "${NGINX_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        for conf in "$dir"/*; do
            [ -f "$conf" ] || continue
            
            # Extract server_name
            SERVER_NAMES=$(grep -E '^\s*server_name\s+' "$conf" 2>/dev/null | sed -E 's/^\s*server_name\s+//; s/;//; s/\s+/\n/g' | grep -v -E '^(_|\*|localhost)$' || true)
            
            # Extract access_log
            ACCESS_LOG=$(grep -E '^\s*access_log\s+' "$conf" 2>/dev/null | head -n 1 | awk '{print $2}' | sed 's/;//' || true)
            
            if [ -n "$SERVER_NAMES" ]; then
                for domain in $SERVER_NAMES; do
                    if [ -z "$ACCESS_LOG" ] || [ "$ACCESS_LOG" = "off" ]; then
                        LOG_PATH="/var/log/nginx/access.log"
                    else
                        LOG_PATH="$ACCESS_LOG"
                    fi
                    
                    ENTRY="${domain}|${LOG_PATH}"
                    if [[ ! " ${DISCOVERED_SITES[*]} " =~ " ${ENTRY} " ]]; then
                        DISCOVERED_SITES+=("$ENTRY")
                    fi
                done
            fi
        done
    fi
done

SELECTED_CHANNELS=()

if [ ${#DISCOVERED_SITES[@]} -gt 0 ]; then
    echo -e "  Discovered ${BOLD}${#DISCOVERED_SITES[@]}${NC} website(s) in Nginx configuration:"
    for entry in "${DISCOVERED_SITES[@]}"; do
        domain="${entry%%|*}"
        logpath="${entry##*|}"
        
        echo -e "\n  --------------------------------------------------"
        echo -e "  ${BOLD}Domain:${NC}   ${GREEN}${domain}${NC}"
        echo -e "  ${BOLD}Log Path:${NC} ${AMBER}${logpath}${NC}"
        
        read -r -p "$(echo -e "  ${CYAN}[?] Monitor '${domain}' in Project 2501? [Y/n]: ${NC}")" CHOICE
        CHOICE="${CHOICE:-y}"
        if [[ "$CHOICE" =~ ^[Yy]$ ]]; then
            CH_NAME=$(echo "$domain" | tr '.' '-' | tr -cd 'a-zA-Z0-9-')
            SELECTED_CHANNELS+=("${CH_NAME}|${domain}|${logpath}")
            echo -e "    ${GREEN}✓ Added as channel: ${CH_NAME}${NC}"
        else
            echo -e "    ${RED}✗ Skipped${NC}"
        fi
    done
else
    echo -e "  ${AMBER}! No active Nginx virtual hosts found in standard directories.${NC}"
fi

# ==============================================================================
# CREATE DIRECTLY A NEW WEBPAGE / CHANNEL
# ==============================================================================
echo -e "\n  --------------------------------------------------"
read -r -p "$(echo -e "  ${BOLD}${CYAN}[?] Would you like to create or add a NEW webpage directly? [y/N]: ${NC}")" CREATE_NEW
if [[ "$CREATE_NEW" =~ ^[Yy]$ ]]; then
    while true; do
        echo -e "\n  ${BOLD}[+] Provisioning New Webpage & Telemetry Channel:${NC}"
        read -r -p "$(echo -e "  ${AMBER}» Enter domain name (e.g. status.kiliotsu.eu): ${NC}")" NEW_DOMAIN
        if [ -z "$NEW_DOMAIN" ]; then
            echo -e "  ${RED}! Domain name cannot be empty. Skipping.${NC}"
            break
        fi

        NEW_CH_NAME=$(echo "$NEW_DOMAIN" | tr '.' '-' | tr -cd 'a-zA-Z0-9-')
        DEFAULT_LOG="/var/log/nginx/${NEW_DOMAIN}_access.log"
        read -r -p "$(echo -e "  ${AMBER}» Access log path [${DEFAULT_LOG}]: ${NC}")" NEW_LOG
        NEW_LOG="${NEW_LOG:-$DEFAULT_LOG}"

        # Option: Generate Nginx server block
        read -r -p "$(echo -e "  ${CYAN}[?] Generate Nginx server block configuration for '${NEW_DOMAIN}'? [y/N]: ${NC}")" GEN_NGINX
        if [[ "$GEN_NGINX" =~ ^[Yy]$ ]]; then
            read -r -p "$(echo -e "  ${AMBER}» Upstream proxy target (e.g. 127.0.0.1:8080 or leave empty for static HTML): ${NC}")" UPSTREAM
            NGINX_AVAIL="/etc/nginx/sites-available/${NEW_DOMAIN}"
            NGINX_ENAB="/etc/nginx/sites-enabled/${NEW_DOMAIN}"
            
            mkdir -p /var/log/nginx
            touch "${NEW_LOG}" 2>/dev/null || true

            if [ -n "$UPSTREAM" ]; then
                CONF_CONTENT="server {
    listen 80;
    server_name ${NEW_DOMAIN};

    access_log ${NEW_LOG};
    error_log /var/log/nginx/${NEW_DOMAIN}_error.log;

    location / {
        proxy_pass http://${UPSTREAM};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}"
            else
                WEB_ROOT="/var/www/${NEW_DOMAIN}"
                mkdir -p "$WEB_ROOT" 2>/dev/null || true
                echo "<h1>Project 2501 // Secure Sector: ${NEW_DOMAIN}</h1>" > "${WEB_ROOT}/index.html" 2>/dev/null || true
                CONF_CONTENT="server {
    listen 80;
    server_name ${NEW_DOMAIN};
    root ${WEB_ROOT};
    index index.html;

    access_log ${NEW_LOG};
    error_log /var/log/nginx/${NEW_DOMAIN}_error.log;

    location / {
        try_files \$uri \$uri/ =404;
    }
}"
            fi

            if [ -w "/etc/nginx/sites-available" ] || [ "$EUID" -eq 0 ]; then
                echo "$CONF_CONTENT" > "$NGINX_AVAIL"
                ln -sf "$NGINX_AVAIL" "$NGINX_ENAB"
                nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true
                echo -e "    ${GREEN}✓ Nginx virtual host generated & reloaded: ${NGINX_AVAIL}${NC}"
            else
                echo -e "    ${AMBER}! Non-root user: writing Nginx config to ${PROJECT_DIR}/${NEW_DOMAIN}.conf${NC}"
                echo "$CONF_CONTENT" > "${PROJECT_DIR}/${NEW_DOMAIN}.conf"
            fi
        fi

        SELECTED_CHANNELS+=("${NEW_CH_NAME}|${NEW_DOMAIN}|${NEW_LOG}")
        echo -e "    ${GREEN}✓ Registered new webpage channel: ${NEW_CH_NAME}${NC}"

        read -r -p "$(echo -e "  ${CYAN}[?] Add another new webpage? [y/N]: ${NC}")" ANOTHER
        [[ "$ANOTHER" =~ ^[Yy]$ ]] || break
    done
fi

if [ ${#SELECTED_CHANNELS[@]} -eq 0 ]; then
    echo -e "  ${AMBER}! No channels selected. The daemon will start with the L3/L4 sentry only.${NC}"
fi

echo -e "\n${CYAN}[3/5] Generating dedicated HUD Webpages in web/sites/...${NC}"

# Function to generate an authentic Section 9 channel webpage
generate_channel_page() {
    local ch_name="$1"
    local ch_domain="$2"
    local ch_log="$3"
    local target_html="${WEB_SITES_DIR}/${ch_name}.html"
    local upper_name
    upper_name="$(echo "$ch_name" | tr '[:lower:]' '[:upper:]')"

    cat > "$target_html" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PROJECT 2501 // CHANNEL: ${upper_name}</title>
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
  <link rel="stylesheet" href="/styles/style.css">
  <script>
    // Channel filter for telemetry stream
    window.CHANNEL_FILTER = "${ch_name}";
  </script>
  <script type="module" src="/scripts/main.js"></script>
</head>
<body class="p-4 md:p-6 crt-flicker">
  <div class="crt-overlay"></div>

  <!-- Header Bar -->
  <header class="border-glow bg-[#06140a] p-4 mb-4 gits-panel flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
    <div>
      <div class="flex items-center gap-3">
        <span class="bg-[#00ff66] text-[#030a05] px-2 py-0.5 text-xs font-bold tracking-wider">公安9課</span>
        <h1 class="text-xl md:text-2xl font-bold tracking-widest glow-green">CHANNEL // ${upper_name}</h1>
      </div>
      <p class="text-xs text-[#00cc52] mt-1 tracking-wider">
        DOMAIN: <span class="text-white">${ch_domain}</span> ──► LOG: <span class="text-[#ff9900]">${ch_log}</span>
      </p>
    </div>

    <!-- Navigation Tabs -->
    <nav class="flex items-center gap-2 text-xs flex-wrap" id="nav-tabs">
      <a href="/" class="nav-tab px-3 py-1.5 border border-[#00ff66]/40 text-[#00ff66]">ALL CHANNELS</a>
      <a href="/sites/${ch_name}.html" class="nav-tab active px-3 py-1.5 border border-[#00ff66]">${upper_name}</a>
    </nav>

    <!-- Telemetry Status -->
    <div class="flex items-center gap-4 text-xs">
      <div class="border border-[#00ff66]/40 px-3 py-1.5 bg-[#030a05]"><span class="text-[#00aa44]">SECTOR:</span> <span class="text-[#00ff66] font-bold ml-1">${upper_name}-CORE</span></div>
      <div class="text-[#00ff66] text-sm font-bold font-mono" id="system-time">--:--:--</div>
    </div>
  </header>

  <!-- Metric Badges Row -->
  <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
    <div class="border-glow bg-[#06140a] p-3 gits-panel">
      <div class="text-[11px] text-[#00aa44] uppercase tracking-wider">[チャネル状態] CHANNEL STATUS</div>
      <div class="flex items-baseline gap-2 mt-1"><span class="text-3xl font-bold text-white glow-green">ONLINE</span><span class="text-xs text-[#00ff66]">INGRESS ACTIVE</span></div>
      <div class="text-[10px] text-[#00cc52]/60 mt-1 font-mono">TARGET: ${ch_domain}</div>
    </div>
    <div class="border-glow bg-[#06140a] p-3 gits-panel">
      <div class="text-[11px] text-[#00aa44] uppercase tracking-wider">[24H アクセス数] INGRESS 24H</div>
      <div class="flex items-baseline gap-2 mt-1"><span class="text-3xl font-bold text-white glow-green" id="ingress-24h">0</span><span class="text-xs text-[#00ff66]">HITS</span></div>
      <div class="text-[10px] text-[#00cc52]/60 mt-1 font-mono" id="feed-rate">STREAM: 0.0 msg/s</div>
    </div>
    <div class="border-glow-red bg-[#140508] p-3 gits-panel">
      <div class="text-[11px] text-[#ff003c] uppercase tracking-wider">[防御障壁] BREACH DETECTIONS</div>
      <div class="flex items-baseline gap-2 mt-1"><span class="text-3xl font-bold text-[#ff003c] glow-red" id="breach-count">0</span><span class="text-xs text-[#ff003c]">ANOMALIES</span></div>
      <div class="text-[10px] text-[#ff003c]/70 mt-1 font-mono">STATUS: SCANNER ACTIVE</div>
    </div>
  </div>

  <!-- Active ICE Blacklist / Banned IPs -->
  <div class="border-glow-red bg-[#0d0305] p-4 mb-4 gits-panel">
    <div class="flex justify-between items-center border-b border-[#ff003c]/30 pb-2 mb-3">
      <div class="flex items-center gap-2">
        <span class="w-2.5 h-2.5 rounded-full bg-[#ff003c] animate-ping"></span>
        <span class="font-bold text-sm tracking-wider glow-red">[攻性防壁] ACTIVE ICE BLACKLIST // CHANNEL-SPECIFIC DROP RULES</span>
      </div>
      <div class="text-xs font-mono text-[#ff003c]">
        ACTIVE DROP RULES: <span id="banned-count" class="font-bold text-white bg-[#ff003c]/30 px-1.5 py-0.5 rounded">0</span>
      </div>
    </div>
    <div class="overflow-x-auto">
      <table class="w-full text-left font-mono text-xs">
        <thead>
          <tr class="border-b border-[#ff003c]/30 text-[#ff003c]/70 text-[10px] uppercase">
            <th class="py-1 px-2">Attacker IP</th>
            <th class="py-1 px-2">Target Channel</th>
            <th class="py-1 px-2">Detection Reason</th>
            <th class="py-1 px-2">Time (UTC)</th>
            <th class="py-1 px-2 text-right">Defense Status</th>
          </tr>
        </thead>
        <tbody id="banned-ips-body">
          <tr>
            <td colspan="5" class="py-3 text-center text-[#00ff66]/60 font-mono text-xs">
              [✓] PERIMETER SECURE // NO ACTIVE ICE BANS
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Real-Time Telemetry Stream -->
  <div class="border-glow bg-[#06140a] p-4 gits-panel">
    <div class="flex justify-between items-center border-b border-[#00ff66]/20 pb-2 mb-2">
      <div class="flex items-center gap-2">
        <span class="text-xs font-bold tracking-wider glow-green">[情報ノ海] REAL-TIME INGRESS STREAM: ${upper_name}</span>
        <span class="text-[10px] text-[#00ff66]/60 font-mono">(Live Tail)</span>
      </div>
    </div>
    <div class="font-mono text-xs space-y-1 max-h-96 overflow-y-hidden text-[#00ff66]/90" id="telemetry-log"></div>
  </div>

  <footer class="mt-4 text-center text-[10px] text-[#00cc52]/40 font-mono tracking-widest">
    PUBLIC SECURITY SECTION 9 // PROTOCOL 2501 // TARGET: ${ch_domain}
  </footer>
</body>
</html>
EOF
    echo -e "  ${GREEN}✓ Generated HUD webpage: ${target_html}${NC}"
}

# Generate pages for all selected channels
if [ ${#SELECTED_CHANNELS[@]} -gt 0 ]; then
    for ch in "${SELECTED_CHANNELS[@]}"; do
        c_name=$(echo "$ch" | cut -d'|' -f1)
        c_domain=$(echo "$ch" | cut -d'|' -f2)
        c_log=$(echo "$ch" | cut -d'|' -f3)
        generate_channel_page "$c_name" "$c_domain" "$c_log"
    done
fi

# The global fallback log is always monitored, so give it a HUD page too.
generate_channel_page "global" "omni-ingress" "/var/log/nginx/access.log"

# Navigation tabs are built at runtime from /api/info, so no static rewrite is
# needed after adding or removing channels.

echo -e "\n${CYAN}[4/5] Configuring Firewall Active Defense (IPS) & Alerting...${NC}"

# Check for nftables
HAS_NFT=false
if command -v nft >/dev/null 2>&1; then
    HAS_NFT=true
    echo -e "  * Detected ${GREEN}nftables${NC} (Recommended kernel firewall engine)"
elif command -v iptables >/dev/null 2>&1; then
    echo -e "  * Detected ${AMBER}iptables${NC}"
else
    echo -e "  * ${RED}No firewall tool detected (nftables/iptables)${NC}"
fi

read -r -p "$(echo -e "${AMBER}[?] Enable automated kernel firewall ban on threat detection? [Y/n]: ${NC}")" ENABLE_FW
ENABLE_FW="${ENABLE_FW:-y}"
FIREWALL_ENABLED="false"
if [[ "$ENABLE_FW" =~ ^[Yy]$ ]]; then
    FIREWALL_ENABLED="true"
fi

read -r -p "$(echo -e "${AMBER}[?] Attacker IP Ban duration in minutes [60]: ${NC}")" BAN_MINS
BAN_DURATION_MINUTES="${BAN_MINS:-60}"

# Read a value from an existing .env without echoing secrets.
env_get() {
    local key="$1"
    if [ -f "$ENV_FILE" ]; then
        grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | head -n 1 | cut -d'=' -f2- || true
    fi
}

DISCORD_ENABLED="$(env_get DISCORD_ENABLED)"; DISCORD_ENABLED="${DISCORD_ENABLED:-false}"
DISCORD_WEBHOOK_URL="$(env_get DISCORD_WEBHOOK_URL)"
SMTP_ENABLED="$(env_get SMTP_ENABLED)"; SMTP_ENABLED="${SMTP_ENABLED:-false}"
SMTP_URL="$(env_get SMTP_URL)"
SMTP_PORT="$(env_get SMTP_PORT)"; SMTP_PORT="${SMTP_PORT:-465}"
SMTP_USER="$(env_get SMTP_USER)"
SMTP_PASS="$(env_get SMTP_PASS)"
ALERT_TO="$(env_get ALERT_TO)"
VISITOR_SALT="$(env_get VISITOR_SALT)"
GEOIP_DB_PATH="$(env_get GEOIP_DB_PATH)"
IP_WHITELIST="$(env_get IP_WHITELIST)"

echo -e "\n${CYAN}[+] Discord alerting${NC}"
read -r -p "$(echo -e "${AMBER}[?] Enable Discord alerts? [y/N]: ${NC}")" INPUT_DISCORD
if [[ "${INPUT_DISCORD:-n}" =~ ^[Yy]$ ]]; then
    DISCORD_ENABLED="true"
    read -r -p "$(echo -e "${AMBER}» Discord webhook URL (leave blank to keep the existing one): ${NC}")" INPUT_WEBHOOK
    if [ -n "$INPUT_WEBHOOK" ]; then
        DISCORD_WEBHOOK_URL="$INPUT_WEBHOOK"
    fi
    if [ -z "$DISCORD_WEBHOOK_URL" ]; then
        echo -e "  ${RED}! No webhook URL provided. Discord alerts disabled.${NC}"
        DISCORD_ENABLED="false"
    fi
else
    DISCORD_ENABLED="false"
fi

echo -e "\n${CYAN}[+] Email alerting${NC}"
read -r -p "$(echo -e "${AMBER}[?] Enable email alerts? [y/N]: ${NC}")" INPUT_EMAIL
if [[ "${INPUT_EMAIL:-n}" =~ ^[Yy]$ ]]; then
    SMTP_ENABLED="true"

    read -r -p "$(echo -e "${AMBER}» SMTP host [${SMTP_URL}]: ${NC}")" INPUT_SMTP_HOST
    SMTP_URL="${INPUT_SMTP_HOST:-$SMTP_URL}"

    read -r -p "$(echo -e "${AMBER}» SMTP port (465 = implicit TLS, 587 = STARTTLS) [${SMTP_PORT}]: ${NC}")" INPUT_SMTP_PORT
    SMTP_PORT="${INPUT_SMTP_PORT:-$SMTP_PORT}"

    read -r -p "$(echo -e "${AMBER}» Sender email address [${SMTP_USER}]: ${NC}")" INPUT_SMTP_USER
    SMTP_USER="${INPUT_SMTP_USER:-$SMTP_USER}"

    read -r -s -p "$(echo -e "${AMBER}» SMTP password (leave blank to keep existing): ${NC}")" INPUT_SMTP_PASS
    echo ""
    if [ -n "$INPUT_SMTP_PASS" ]; then
        SMTP_PASS="$INPUT_SMTP_PASS"
    fi

    read -r -p "$(echo -e "${AMBER}» Alert recipient email [${ALERT_TO:-$SMTP_USER}]: ${NC}")" INPUT_ALERT_TO
    ALERT_TO="${INPUT_ALERT_TO:-${ALERT_TO:-$SMTP_USER}}"

    if [ -z "$SMTP_USER" ] || [ -z "$SMTP_PASS" ] || [ -z "$ALERT_TO" ]; then
        echo -e "  ${RED}! Sender, password or recipient missing. Email alerts disabled.${NC}"
        SMTP_ENABLED="false"
    fi
else
    SMTP_ENABLED="false"
fi

if [ -z "$VISITOR_SALT" ]; then
    VISITOR_SALT="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi

read -r -p "$(echo -e "${AMBER}[?] GeoLite2 Country database path (optional, blank for heuristic): ${NC}")" INPUT_GEOIP
GEOIP_DB_PATH="${INPUT_GEOIP:-$GEOIP_DB_PATH}"

read -r -p "$(echo -e "${AMBER}[?] Extra whitelisted IP/CIDR (comma-separated, optional): ${NC}")" INPUT_WHITELIST
IP_WHITELIST="${INPUT_WHITELIST:-$IP_WHITELIST}"

echo -e "\n${CYAN}[5/5] Writing configuration to ${ENV_FILE}...${NC}"

cat > "$ENV_FILE" << EOF
# ==============================================================================
# PROJECT 2501 // CYBERBRAIN NETWORK MONITOR & ANALYTICS CONFIGURATION
# Generated on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# ==============================================================================

# [NETWORK PERIMETER]
INTERFACE=${INTERFACE}
SERVER_PUBLIC_IP=${SERVER_PUBLIC_IP}

EOF

CH_INDEX=1
if [ ${#SELECTED_CHANNELS[@]} -gt 0 ]; then
    for ch in "${SELECTED_CHANNELS[@]}"; do
        c_name=$(echo "$ch" | cut -d'|' -f1)
        c_domain=$(echo "$ch" | cut -d'|' -f2)
        c_log=$(echo "$ch" | cut -d'|' -f3)

        cat >> "$ENV_FILE" << EOF
# [CHANNEL ${CH_INDEX}: $(echo "$c_name" | tr '[:lower:]' '[:upper:]')]
CHANNEL_${CH_INDEX}_NAME=${c_name}
CHANNEL_${CH_INDEX}_DOMAIN=${c_domain}
CHANNEL_${CH_INDEX}_LOG=${c_log}

EOF
        CH_INDEX=$((CH_INDEX + 1))
    done
fi

cat >> "$ENV_FILE" << EOF
# [GLOBAL FALLBACK LOG]
GLOBAL_FALLBACK_LOG=/var/log/nginx/access.log

# [ANOMALY THRESHOLDS]
SYN_FLOOD_THRESHOLD=30
SYN_WINDOW_SECONDS=5
SCAN_404_THRESHOLD=15
SCAN_WINDOW_SECONDS=10
ALERT_COOLDOWN_MINUTES=15

# [FIREWALL ACTIVE DEFENSE (FAIL2BAN IPS)]
FIREWALL_ENABLED=${FIREWALL_ENABLED}
BAN_DURATION_MINUTES=${BAN_DURATION_MINUTES}
IP_WHITELIST=${IP_WHITELIST}

# [SMTP TLS EMAIL ALERTING]
SMTP_ENABLED=${SMTP_ENABLED}
SMTP_URL=${SMTP_URL}
SMTP_PORT=${SMTP_PORT}
SMTP_USER=${SMTP_USER}
SMTP_PASS=${SMTP_PASS}
ALERT_TO=${ALERT_TO}

# [DISCORD WEBHOOK ALERTING]
DISCORD_ENABLED=${DISCORD_ENABLED}
DISCORD_WEBHOOK_URL=${DISCORD_WEBHOOK_URL}

# [STORAGE & DASHBOARD SERVER]
DB_PATH=cyberbrain.db
DASHBOARD_PORT=2501
DASHBOARD_BIND=127.0.0.1

# [PRIVACY / GEOIP]
VISITOR_SALT=${VISITOR_SALT}
GEOIP_DB_PATH=${GEOIP_DB_PATH}
EOF

chmod 600 "$ENV_FILE"
echo -e "  ${GREEN}✓ Configuration saved to ${ENV_FILE} (permissions: 600)${NC}"

# Optional: configure systemd service
SERVICE_FILE="/etc/systemd/system/project-2501.service"
if [ -w "/etc/systemd/system" ] || [ "$EUID" -eq 0 ]; then
    echo -e "\n${CYAN}[+] Installing / Updating systemd unit file at ${SERVICE_FILE}...${NC}"
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Project 2501 Sentinel Daemon (Section 9 Cyberbrain IDS/IPS)
After=network.target

[Service]
Type=simple
User=${SUDO_USER:-$USER}
WorkingDirectory=${PROJECT_DIR}
ExecStart=${PROJECT_DIR}/target/release/project-2501
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    echo -e "  ${GREEN}✓ Systemd unit updated with CAP_NET_ADMIN & CAP_NET_RAW.${NC}"
fi

echo -e "\n${GREEN}${BOLD}================================================================================${NC}"
echo -e "${GREEN}${BOLD}  SETUP COMPLETE!${NC}"
echo -e "  Channels configured: ${BOLD}${#SELECTED_CHANNELS[@]}${NC}"
echo -e "  All HUD webpages generated in ${BOLD}web/sites/${NC}"
echo -e "  You can start or restart the service using:"
echo -e "    ${BOLD}sudo systemctl restart project-2501.service${NC}"
echo -e "  Or run directly:"
echo -e "    ${BOLD}cd ${PROJECT_DIR} && cargo run --release${NC}"
echo -e "${GREEN}${BOLD}================================================================================${NC}\n"
