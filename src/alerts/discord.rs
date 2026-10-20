use reqwest::Client;
use serde_json::json;
use tracing::{error, info};

pub struct DiscordAlerter {
    client: Client,
    webhook_url: Option<String>,
}

impl DiscordAlerter {
    pub fn new(webhook_url: Option<String>) -> Self {
        Self {
            client: Client::new(),
            webhook_url,
        }
    }

    pub async fn send_threat_alert(
        &self,
        channel: &str,
        domain: &str,
        threat_type: &str,
        offending_ip: &str,
        details: &str,
    ) {
        let url = match &self.webhook_url {
            Some(u) if !u.is_empty() => u,
            _ => return,
        };

        let color = if threat_type.to_ascii_lowercase().contains("critical") {
            0xFF003C // Cyber Crimson
        } else {
            0xFF9900 // Tactical Amber
        };

        let defense_action = if details.contains("[FIREWALL: BANNED") {
            "🚨 KERNEL DROP APPLIED: Offending IP dropped at firewall layer."
        } else {
            "IP throttled & logged to Section 9 ICE"
        };

        let payload = json!({
            "username": "PROJECT 2501 // SENTRY",
            "avatar_url": "https://raw.githubusercontent.com/kiliotsu/2501-project/main/assets/avatar.png",
            "embeds": [{
                "title": format!("🚨 Threat Detected on {} ({})", domain, channel),
                "color": color,
                "fields": [
                    { "name": "Threat Classification", "value": threat_type, "inline": true },
                    { "name": "Offending IP", "value": offending_ip, "inline": true },
                    { "name": "Details / Payload", "value": format!("`{}`", details), "inline": false },
                    { "name": "Defense Action", "value": defense_action, "inline": false }
                ],
                "footer": { "text": "Public Security Section 9 // Cyberbrain Network Monitor" },
                "timestamp": chrono::Utc::now().to_rfc3339()
            }]
        });

        match self.client.post(url).json(&payload).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!("Dispatched Discord threat alert for IP {}", offending_ip);
            }
            Ok(resp) => {
                error!(
                    "Discord webhook returned status {}: {:?}",
                    resp.status(),
                    resp.text().await
                );
            }
            Err(e) => error!("Failed to send Discord webhook: {}", e),
        }
    }
}
