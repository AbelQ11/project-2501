// src/network/raw_socket.rs
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub struct NetThreatEvent {
    pub threat_type: String,
    pub source_ip: String,
    pub details: String,
}

pub struct PerimeterSentry {
    interface: String,
    syn_threshold: u32,
    syn_window: Duration,
}

impl PerimeterSentry {
    pub fn new(interface: String, syn_threshold: u32, syn_window_seconds: u64) -> Self {
        Self {
            interface,
            syn_threshold,
            syn_window: Duration::from_secs(syn_window_seconds),
        }
    }

    /// Spawns raw socket sniffer on dedicated blocking thread
    pub fn start(self: Arc<Self>, threat_tx: mpsc::Sender<NetThreatEvent>) {
        let iface = self.interface.clone();
        let syn_threshold = self.syn_threshold;
        let syn_window = self.syn_window;

        tokio::task::spawn_blocking(move || {
            // Attempt opening raw socket for IPv4 TCP packets
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                warn!(
                    "Perimeter Sentry: raw socket on '{}' unavailable ({}). \
                    Ensure daemon runs with CAP_NET_RAW capability. Continuing with L7 Web Sentry.",
                    iface, err
                );
                return;
            }

            // Bind explicitly to network device on Linux
            #[cfg(target_os = "linux")]
            if let Ok(iface_c) = std::ffi::CString::new(iface.as_str()) {
                let res = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_BINDTODEVICE,
                        iface_c.as_ptr() as *const libc::c_void,
                        iface_c.as_bytes_with_nul().len() as libc::socklen_t,
                    )
                };
                if res < 0 {
                    let err = std::io::Error::last_os_error();
                    warn!(
                        "Perimeter Sentry: SO_BINDTODEVICE notice for '{}': {}",
                        iface, err
                    );
                }
            }

            info!(
                "Perimeter Sentry [L3/L4]: armed on interface '{}' (SYN Flood Threshold: {} in {:?})",
                iface, syn_threshold, syn_window
            );

            let mut buf = [0u8; 1500];
            let mut syn_tracker: HashMap<String, Vec<Instant>> = HashMap::new();
            let mut port_tracker: HashMap<String, (HashSet<u16>, Instant)> = HashMap::new();
            let mut last_cleanup = Instant::now();

            loop {
                let n =
                    unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };

                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    error!("Perimeter Sentry recv error: {}", err);
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }

                let n = n as usize;
                if n < 40 {
                    continue; // Incomplete IP + TCP headers
                }

                // 1. Parse IPv4 Header. `ihl` is expressed in 32-bit words and
                // must be at least 5 (20 bytes); otherwise the TCP offset below
                // would point into the middle of the IP header.
                let ihl = ((buf[0] & 0x0F) * 4) as usize;
                if ihl < 20 || n < ihl + 20 {
                    continue;
                }

                let src_ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]).to_string();

                // 2. Parse TCP Header
                let tcp_slice = &buf[ihl..];
                let dst_port = u16::from_be_bytes([tcp_slice[2], tcp_slice[3]]);
                let flags = tcp_slice[13];

                let is_syn = (flags & 0x02) != 0;
                let is_ack = (flags & 0x10) != 0;

                // Inspect TCP SYN handshakes (SYN=1, ACK=0)
                if is_syn && !is_ack {
                    let now = Instant::now();

                    // Check A: SYN Flood
                    let syn_history = syn_tracker.entry(src_ip.clone()).or_default();
                    syn_history.retain(|t| now.duration_since(*t) <= syn_window);
                    syn_history.push(now);

                    if syn_history.len() >= syn_threshold as usize {
                        let count = syn_history.len();
                        syn_history.clear(); // Reset burst window
                        let _ = threat_tx.blocking_send(NetThreatEvent {
                            threat_type: "L3_SYN_FLOOD".to_string(),
                            source_ip: src_ip.clone(),
                            details: format!(
                                "Excessive TCP SYN burst: {} packets in {:?}",
                                count, syn_window
                            ),
                        });
                    }

                    // Check B: Port Scan (>10 ports in 10s)
                    let port_entry = port_tracker
                        .entry(src_ip.clone())
                        .or_insert_with(|| (HashSet::new(), now));
                    if now.duration_since(port_entry.1) > Duration::from_secs(10) {
                        port_entry.0.clear();
                        port_entry.1 = now;
                    }
                    port_entry.0.insert(dst_port);

                    if port_entry.0.len() >= 10 {
                        let count = port_entry.0.len();
                        port_entry.0.clear();
                        let _ = threat_tx.blocking_send(NetThreatEvent {
                            threat_type: "L4_PORT_SCAN".to_string(),
                            source_ip: src_ip,
                            details: format!(
                                "Port sweep detected: {} unique destination ports probed in 10s",
                                count
                            ),
                        });
                    }
                }

                // Periodic prune of idle IPs every 60s
                if last_cleanup.elapsed() >= Duration::from_secs(60) {
                    let now = Instant::now();
                    syn_tracker
                        .retain(|_, v| v.iter().any(|t| now.duration_since(*t) <= syn_window));
                    port_tracker.retain(|_, (_, start)| {
                        now.duration_since(*start) <= Duration::from_secs(10)
                    });
                    last_cleanup = now;
                }
            }
        });
    }
}
