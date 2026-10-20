pub mod parser;
pub mod tailer;

pub use parser::{LogEntry, ThreatLevel};
pub use tailer::FileTailer;

use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::info;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChannelTarget {
    pub name: String,
    pub domain: String,
    pub log_path: PathBuf,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ParsedChannelEvent {
    pub channel: String,
    pub domain: String,
    pub entry: LogEntry,
    pub threat: ThreatLevel,
}

pub struct LogWatcherSupervisor {
    channels: Vec<ChannelTarget>,
}

impl LogWatcherSupervisor {
    pub fn new(channels: Vec<ChannelTarget>) -> Self {
        Self { channels }
    }

    /// Launches tailing threads for all configured channels and returns an async receiver
    /// yielding parsed log events with threat evaluations.
    pub fn start(self) -> mpsc::Receiver<ParsedChannelEvent> {
        let (raw_tx, mut raw_rx) = mpsc::channel::<(String, String)>(1024);
        let (out_tx, out_rx) = mpsc::channel::<ParsedChannelEvent>(1024);

        let domain_map: HashMap<String, String> = self
            .channels
            .iter()
            .map(|c| (c.name.clone(), c.domain.clone()))
            .collect();

        for channel in self.channels {
            info!(
                "Initializing sentinel for channel '{}' ({}) -> {}",
                channel.name,
                channel.domain,
                channel.log_path.display()
            );
            let tailer = FileTailer::new(&channel.log_path, &channel.name);
            tailer.spawn(raw_tx.clone());
        }

        tokio::spawn(async move {
            while let Some((channel_name, raw_line)) = raw_rx.recv().await {
                if let Some(entry) = LogEntry::parse(&raw_line) {
                    let threat = entry.evaluate_threat();
                    let domain = domain_map
                        .get(&channel_name)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());

                    let event = ParsedChannelEvent {
                        channel: channel_name,
                        domain,
                        entry,
                        threat,
                    };

                    if out_tx.send(event).await.is_err() {
                        break;
                    }
                }
            }
        });

        out_rx
    }
}
