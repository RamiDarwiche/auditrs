//! # LogReplayer
//!
//! Utility for replaying audit log files with original timing preserved.
//! Once started, it opens a new thread that will send
//!
//!
//! ## Usage
//!
//! ```rust
//! use std::time::Duration;
//!
//! // Load audit logs from file
//! let mut replayer = LogReplayer::from_file("/var/log/audit/audit.log")?;
//!
//! // Start replaying in background thread
//! replayer.start();
//!
//! // Read messages as they arrive with original timing
//! loop {
//!     match replayer.read_message() {
//!         Some(message_bytes) => {
//!             let message = String::from_utf8_lossy(&message_bytes);
//!             println!("Audit message: {}", message);
//!             // Process your audit message here
//!         }
//!         None => {
//!             // No message ready yet, could sleep briefly
//!             std::thread::sleep(Duration::from_millis(10));
//!         }
//!     }
//! }
//! ```

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use super::traits::AuditSource;

pub struct LogReplayer {
    receiver: Receiver<Vec<u8>>,
    logs: Vec<(Duration, String)>,
}

pub enum ReplayTiming {
    Fast,                       // No delays
    Original,                   // Use original timestamps
    Burst(Duration),            // Fixed interval between messages
    //Random(Duration, Duration), // Random interval between min/max
}

impl LogReplayer {
    pub fn from_file(path: &str) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut logs = Vec::new();
        let mut base_timestamp = None;

        for line in reader.lines() {
            let line = line?;
            if let Some(timestamp) = extract_timestamp(&line) {
                if base_timestamp.is_none() {
                    base_timestamp = Some(timestamp);
                }
                let relative_time = Duration::from_secs(timestamp - base_timestamp.unwrap());
                logs.push((relative_time, line));
            }
        }
        // this is stupid. need to implement some kind of type state system.
        let (sender, receiver) = mpsc::channel();

        Ok(Self { receiver, logs })
    }

    pub fn start_with_timing(&mut self, timing: ReplayTiming) {
        let (sender, receiver) = mpsc::channel();
        self.receiver = receiver;
        let logs = self.logs.clone();

        thread::spawn(move || {
            let start_time = Instant::now();

            for (original_time, message) in logs.into_iter() {
                // Calculate delay based on timing strategy
                let delay = match timing {
                    ReplayTiming::Fast => Duration::ZERO,
                    ReplayTiming::Original => {
                        let elapsed = start_time.elapsed();
                        if elapsed < original_time {
                            original_time - elapsed
                        } else {
                            Duration::ZERO
                        }
                    }
                    ReplayTiming::Burst(interval) => interval,
                    // ReplayTiming::Random(min, max) => {
                    //     let range = max.as_millis() - min.as_millis();
                    //     let random_ms = min.as_millis() + (rand::random::<u64>() % range as u64);
                    //     Duration::from_millis(random_ms)
                    // }
                };

                if delay > Duration::ZERO {
                    thread::sleep(delay);
                }

                if sender.send(message.into_bytes()).is_err() {
                    break;
                }
            }
        });
    }

    pub fn start_fast(&mut self) {
        self.start_with_timing(ReplayTiming::Fast);
    }
}

impl AuditSource for LogReplayer {
    fn start(&mut self) {
        self.start_with_timing(ReplayTiming::Original);
    }
    
    fn read_message(&self) -> Option<Vec<u8>> {
        self.receiver.try_recv().ok()
    }

}

fn extract_timestamp(log_line: &str) -> Option<u64> {
    let start = log_line.find("msg=audit(")?;
    let dot_pos = log_line.find('.')?;
    log_line[start + 10..dot_pos].parse().ok()
}

