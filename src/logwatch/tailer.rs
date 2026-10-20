use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub struct FileTailer {
    path: PathBuf,
    channel_name: String,
}

impl FileTailer {
    pub fn new(path: impl AsRef<Path>, channel_name: impl Into<String>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            channel_name: channel_name.into(),
        }
    }

    /// Spawns an async worker that tails the log file, handles logrotate,
    /// and streams new lines into the provided Tokio channel.
    pub fn spawn(self, tx: mpsc::Sender<(String, String)>) -> tokio::task::JoinHandle<()> {
        tokio::task::spawn_blocking(move || {
            let mut current_offset = 0u64;
            // `started` distinguishes the very first open (skip existing history)
            // from later reopens after rotation/truncation (read from the start).
            let mut started = false;

            loop {
                // 1. Attempt to open file
                let file = match std::fs::File::open(&self.path) {
                    Ok(f) => f,
                    Err(e) => {
                        warn!(
                            "[{}] Waiting for log file '{}': {}",
                            self.channel_name,
                            self.path.display(),
                            e
                        );
                        std::thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };

                let mut reader = BufReader::new(file);

                // On the very first open, seek to EOF so past history is not
                // replayed. After a rotation/truncation, `started` is already
                // true and we intentionally read the new file from byte 0.
                if !started {
                    if let Ok(end_pos) = reader.seek(SeekFrom::End(0)) {
                        current_offset = end_pos;
                        started = true;
                        info!(
                            "[{}] Tailing started at EOF (offset: {} bytes)",
                            self.channel_name, current_offset
                        );
                    }
                } else if let Err(e) = reader.seek(SeekFrom::Start(current_offset)) {
                    warn!(
                        "[{}] Failed to seek to offset {}: {}. Resetting to start.",
                        self.channel_name, current_offset, e
                    );
                    current_offset = 0;
                    let _ = reader.seek(SeekFrom::Start(0));
                }

                // Initial inode/metadata check for logrotate
                let initial_meta = match std::fs::metadata(&self.path) {
                    Ok(m) => m,
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(500));
                        continue;
                    }
                };

                // Read loop
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => {
                            // EOF reached. Check for logrotate or truncation.
                            match std::fs::metadata(&self.path) {
                                Ok(curr_meta) => {
                                    #[cfg(unix)]
                                    {
                                        use std::os::unix::fs::MetadataExt;
                                        // If inode changed, file was rotated!
                                        if curr_meta.ino() != initial_meta.ino() {
                                            info!(
                                                "[{}] Inode changed ({} -> {}), logrotate detected. Re-opening.",
                                                self.channel_name,
                                                initial_meta.ino(),
                                                curr_meta.ino()
                                            );
                                            current_offset = 0;
                                            break;
                                        }
                                    }

                                    // If file size shrunk (copytruncate), reset to start
                                    if curr_meta.len() < current_offset {
                                        info!(
                                            "[{}] Log truncation detected (len: {} < offset: {}). Resetting.",
                                            self.channel_name,
                                            curr_meta.len(),
                                            current_offset
                                        );
                                        current_offset = 0;
                                        break;
                                    }
                                }
                                Err(_) => {
                                    // File might be temporarily moved/renamed during logrotate.
                                    // Reopen from the beginning in case a new file appears.
                                    current_offset = 0;
                                    std::thread::sleep(Duration::from_millis(500));
                                    break;
                                }
                            }

                            // Sleep briefly before polling for more lines
                            std::thread::sleep(Duration::from_millis(150));
                        }
                        Ok(bytes_read) => {
                            current_offset += bytes_read as u64;
                            let trimmed = line.trim_end_matches(['\r', '\n']);
                            if !trimmed.is_empty()
                                && tx
                                    .blocking_send((self.channel_name.clone(), trimmed.to_string()))
                                    .is_err()
                            {
                                error!(
                                    "[{}] Receiver dropped. Stopping tailer.",
                                    self.channel_name
                                );
                                return;
                            }
                        }
                        Err(e) => {
                            warn!(
                                "[{}] Error reading line: {}. Retrying.",
                                self.channel_name, e
                            );
                            std::thread::sleep(Duration::from_millis(500));
                        }
                    }
                }
            }
        })
    }
}
