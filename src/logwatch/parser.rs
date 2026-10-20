use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub remote_addr: String,
    pub timestamp_str: String,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub status: u16,
    pub body_bytes_sent: u64,
    pub referer: Option<String>,
    pub user_agent: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ThreatLevel {
    None,
    Suspicious(String),
    Critical(String),
}

impl LogEntry {
    /// Zero-copy string parser for standard Nginx Combined log format:
    /// $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
    pub fn parse(line: &str) -> Option<Self> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        // 1. Remote address (ends at first space)
        let (remote_addr, rem) = trimmed.split_once(' ')?;

        // 2. Skip `- - ` (remote identity & user) up to `[`
        let time_start = rem.find('[')?;
        let time_end = rem[time_start..].find(']')? + time_start;
        let timestamp_str = &rem[time_start + 1..time_end];
        let rem = rem[time_end + 1..].trim_start();

        // 3. Request string in quotes: "GET /path HTTP/1.1"
        let req_start = rem.find('"')?;
        let req_end = rem[req_start + 1..].find('"')? + req_start + 1;
        let request_str = &rem[req_start + 1..req_end];
        let rem = rem[req_end + 1..].trim_start();

        // Split request string into METHOD, PATH, PROTOCOL
        let mut req_parts = request_str.split_whitespace();
        let method = req_parts.next().unwrap_or("-").to_string();
        let path = req_parts.next().unwrap_or("-").to_string();
        let protocol = req_parts.next().unwrap_or("-").to_string();

        // 4. Status code and body bytes sent
        let (status_str, rem) = rem.split_once(' ')?;
        let status = status_str.parse::<u16>().ok()?;

        let (bytes_str, rem) = rem.split_once(' ')?;
        let body_bytes_sent = bytes_str.parse::<u64>().unwrap_or(0);
        let rem = rem.trim_start();

        // 5. Referer (in quotes)
        let ref_start = rem.find('"')?;
        let ref_end = rem[ref_start + 1..].find('"')? + ref_start + 1;
        let referer_str = &rem[ref_start + 1..ref_end];
        let referer = if referer_str == "-" {
            None
        } else {
            Some(referer_str.to_string())
        };
        let rem = rem[ref_end + 1..].trim_start();

        // 6. User Agent (in quotes)
        let ua_start = rem.find('"')?;
        let ua_end = rem[ua_start + 1..].find('"')? + ua_start + 1;
        let user_agent = rem[ua_start + 1..ua_end].to_string();

        Some(LogEntry {
            remote_addr: remote_addr.to_string(),
            timestamp_str: timestamp_str.to_string(),
            method,
            path,
            protocol,
            status,
            body_bytes_sent,
            referer,
            user_agent,
        })
    }

    /// Evaluates if this individual log line triggers an immediate threat indicator.
    pub fn evaluate_threat(&self) -> ThreatLevel {
        let lower_path = self.path.to_ascii_lowercase();
        let lower_ua = self.user_agent.to_ascii_lowercase();

        // 1. Critical: Known Path Traversal
        if lower_path.contains("../")
            || lower_path.contains("..%2f")
            || lower_path.contains("/etc/passwd")
        {
            return ThreatLevel::Critical(format!(
                "Directory traversal attack payload: '{}'",
                self.path
            ));
        }

        // 2. Critical: SQL Injection Probe
        if lower_path.contains("union+select")
            || lower_path.contains("union%20select")
            || lower_path.contains("information_schema")
        {
            return ThreatLevel::Critical(format!(
                "SQL Injection payload detected: '{}'",
                self.path
            ));
        }

        // 3. Suspicious: Sensitive Files / Reconnaissance
        const SENSITIVE_PROBES: &[&str] = &[
            "/.env",
            "/.git",
            "/wp-config",
            "/wp-login",
            "/phpmyadmin",
            "/actuator",
            "/id_rsa",
            "/.aws",
            "/cgi-bin",
            "/config.json",
        ];

        for probe in SENSITIVE_PROBES {
            if lower_path.contains(probe) {
                return ThreatLevel::Suspicious(format!("Probed sensitive asset: '{}'", probe));
            }
        }

        // 4. Suspicious: Malicious Scanners / Exploit Tools
        const SCANNER_AGENTS: &[&str] = &[
            "sqlmap",
            "nikto",
            "masscan",
            "gobuster",
            "dirbuster",
            "zgrab",
            "nuclei",
        ];

        for scanner in SCANNER_AGENTS {
            if lower_ua.contains(scanner) {
                return ThreatLevel::Suspicious(format!(
                    "Known automated exploit agent: '{}'",
                    scanner
                ));
            }
        }

        ThreatLevel::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_real_nginx_line() {
        let line = r#"130.180.218.58 - - [12/Oct/2026:11:26:41 +0000] "GET /api/games HTTP/1.1" 200 2217 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0""#;
        let entry = LogEntry::parse(line).expect("Should parse standard line");

        assert_eq!(entry.remote_addr, "130.180.218.58");
        assert_eq!(entry.timestamp_str, "12/Oct/2026:11:26:41 +0000");
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.path, "/api/games");
        assert_eq!(entry.protocol, "HTTP/1.1");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.body_bytes_sent, 2217);
        assert_eq!(entry.referer, None);
        assert!(entry.user_agent.contains("Firefox/157.0"));
        assert_eq!(entry.evaluate_threat(), ThreatLevel::None);
    }

    #[test]
    fn test_detect_env_probe() {
        let line = r#"45.133.1.82 - - [12/Oct/2026:11:30:00 +0000] "GET /.env HTTP/1.1" 404 162 "-" "curl/7.81.0""#;
        let entry = LogEntry::parse(line).expect("Should parse probe line");

        match entry.evaluate_threat() {
            ThreatLevel::Suspicious(msg) => assert!(msg.contains("/.env")),
            _ => panic!("Expected suspicious threat for .env probe"),
        }
    }

    #[test]
    fn test_detect_traversal() {
        let line = r#"194.26.29.1 - - [12/Oct/2026:11:35:12 +0000] "GET /static/../../etc/passwd HTTP/1.1" 403 0 "-" "sqlmap/1.5""#;
        let entry = LogEntry::parse(line).expect("Should parse traversal");

        match entry.evaluate_threat() {
            ThreatLevel::Critical(msg) => assert!(msg.contains("Directory traversal")),
            _ => panic!("Expected critical threat for traversal"),
        }
    }
}
