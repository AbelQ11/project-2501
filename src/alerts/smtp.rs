use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use tracing::{error, info};

pub struct SmtpAlerter {
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    from_addr: String,
    to_addr: String,
}

impl SmtpAlerter {
    pub fn new(
        enabled: bool,
        smtp_host: &str,
        port: u16,
        smtp_user: &str,
        smtp_pass: &str,
        to_addr: &str,
    ) -> Self {
        let host = Self::normalize_host(smtp_host);

        if !enabled
            || host.is_empty()
            || smtp_user.trim().is_empty()
            || to_addr.trim().is_empty()
            || smtp_pass.is_empty()
            || smtp_pass == "INSERT_YOUR_OVH_PASSWORD_HERE"
        {
            if enabled {
                info!("SMTP alerts enabled but host, sender, recipient or password is missing. Suppressing email.");
            }
            return Self {
                transport: None,
                from_addr: smtp_user.to_string(),
                to_addr: to_addr.to_string(),
            };
        }

        let credentials = Credentials::new(smtp_user.to_string(), smtp_pass.to_string());

        // Port 465 is implicit TLS (SMTPS); 587/25 use STARTTLS. Using the wrong
        // mode was the reason a 465 configuration could never connect.
        let builder = if port == 465 {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
        };

        let transport = builder.map(|builder| builder.port(port).credentials(credentials).build());

        match transport {
            Ok(transport) => Self {
                transport: Some(transport),
                from_addr: smtp_user.to_string(),
                to_addr: to_addr.to_string(),
            },
            Err(error) => {
                error!("Failed to initialize SMTP transport: {}", error);
                Self {
                    transport: None,
                    from_addr: smtp_user.to_string(),
                    to_addr: to_addr.to_string(),
                }
            }
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
        let transport = match &self.transport {
            Some(transport) => transport,
            None => {
                info!("SMTP alerts disabled or unconfigured. Suppressing email.");
                return;
            }
        };

        let from: Mailbox = match self.from_addr.parse() {
            Ok(from) => from,
            Err(error) => {
                error!(
                    "Invalid SMTP sender address '{}': {}",
                    self.from_addr, error
                );
                return;
            }
        };
        let to: Mailbox = match self.to_addr.parse() {
            Ok(to) => to,
            Err(error) => {
                error!(
                    "Invalid alert recipient address '{}': {}",
                    self.to_addr, error
                );
                return;
            }
        };

        let subject = format!(
            "[PROJECT 2501 // SEC_ALERT] Threat on {} [{}]",
            domain, channel
        );
        let body = format!(
            r#"================================================================================
PUBLIC SECURITY SECTION 9 // PROJECT 2501 SECURITY DISPATCH
================================================================================

[!] THREAT DETECTED ON TARGET CHANNEL:
--------------------------------------------------------------------------------
Channel Name  : {channel}
Target Domain : {domain}
Threat Level  : {threat_type}
Offending IP  : {offending_ip}
Details       : {details}
Time          : {time}

[+] DEFENSE ACTION:
--------------------------------------------------------------------------------
{action_summary}
Logged to cyberbrain.db with active cooldown for IP {offending_ip}.

"The Net is vast and infinite..."
================================================================================
"#,
            channel = channel,
            domain = domain,
            threat_type = threat_type,
            offending_ip = offending_ip,
            details = details,
            action_summary = if details.contains("[FIREWALL: BANNED") {
                "🚨 KERNEL DROP APPLIED: Offending IP has been added to kernel firewall blacklist."
            } else {
                "Threat flagged in anomaly engine and logged to Section 9 ICE."
            },
            time = chrono::Utc::now().to_rfc3339()
        );

        let email = match Message::builder()
            .from(from)
            .to(to)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body)
        {
            Ok(message) => message,
            Err(error) => {
                error!("Failed to build threat alert email: {}", error);
                return;
            }
        };

        match transport.send(email).await {
            Ok(_) => info!(
                "Successfully dispatched threat alert email to {} for IP {}",
                self.to_addr, offending_ip
            ),
            Err(error) => error!("Failed to send alert email via SMTP: {}", error),
        }
    }

    /// Accept either a plain host (`ssl0.ovh.net`) or a URL
    /// (`smtps://ssl0.ovh.net:465`). The transport builder expects a host only.
    fn normalize_host(raw: &str) -> String {
        let value = raw.trim();
        let value = value
            .strip_prefix("smtps://")
            .or_else(|| value.strip_prefix("smtp://"))
            .unwrap_or(value);
        let value = value.split('/').next().unwrap_or(value);
        value.split(':').next().unwrap_or(value).trim().to_string()
    }
}
