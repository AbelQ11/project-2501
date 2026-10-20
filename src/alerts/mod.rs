pub mod discord;
pub mod smtp;

pub use discord::DiscordAlerter;
pub use smtp::SmtpAlerter;

use crate::config::Config;
use std::sync::Arc;
use tracing::info;

#[derive(Clone)]
pub struct AlertDispatcher {
    smtp: Arc<SmtpAlerter>,
    discord: Arc<DiscordAlerter>,
}

impl AlertDispatcher {
    pub fn new(config: &Config) -> Self {
        let smtp = SmtpAlerter::new(
            config.smtp_enabled,
            &config.smtp_url,
            config.smtp_port,
            &config.smtp_user,
            &config.smtp_pass,
            &config.alert_to,
        );
        let discord = DiscordAlerter::new(config.discord_webhook_url.clone());

        Self {
            smtp: Arc::new(smtp),
            discord: Arc::new(discord),
        }
    }

    pub async fn dispatch_threat(
        &self,
        channel: &str,
        domain: &str,
        threat_type: &str,
        offending_ip: &str,
        details: &str,
    ) {
        info!(
            "DISPATCHING ALERT: [{}] on {} ({}) from {}",
            threat_type, domain, channel, offending_ip
        );

        let smtp = self.smtp.clone();
        let discord = self.discord.clone();
        let ch1 = channel.to_string();
        let dom1 = domain.to_string();
        let tt1 = threat_type.to_string();
        let ip1 = offending_ip.to_string();
        let det1 = details.to_string();

        let ch2 = ch1.clone();
        let dom2 = dom1.clone();
        let tt2 = tt1.clone();
        let ip2 = ip1.clone();
        let det2 = det1.clone();

        tokio::spawn(async move {
            smtp.send_threat_alert(&ch1, &dom1, &tt1, &ip1, &det1).await;
        });

        tokio::spawn(async move {
            discord
                .send_threat_alert(&ch2, &dom2, &tt2, &ip2, &det2)
                .await;
        });
    }
}
