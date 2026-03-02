use super::{AuditLogWriter, OutputFormat, WriteError, DEFAULT_DESTINATION, DEFAULT_OUTPUT_FORMAT, DEFAULT_LOG_SIZE};
use crate::correlator::AuditEvent;
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;

impl AuditLogWriter {
    pub fn new() -> Self {
        let path = PathBuf::from(DEFAULT_DESTINATION);
        create_dir_all(&path).unwrap();
        let file_handle = OpenOptions::new()
            .create(true)
            .append(true)
            .open(DEFAULT_DESTINATION.to_string() + "auditrs.log")
            .unwrap();
        Self {
            output_format: DEFAULT_OUTPUT_FORMAT,
            destination: path,
            log_size: DEFAULT_LOG_SIZE,
            file_handle,
        }
    }

    pub fn write_event(&mut self, event: AuditEvent) -> Result<(), WriteError> {
        match self.output_format {
            OutputFormat::Legacy => self.write_event_legacy(event),
            OutputFormat::Simple => self.write_event_simple(event),
            OutputFormat::JSON => self.write_event_json(event),
        }
    }

    fn write_event_legacy(&mut self, _event: AuditEvent) -> Result<(), WriteError> {
        todo!()
    }

    fn write_event_simple(&mut self, event: AuditEvent) -> Result<(), WriteError> {
        writeln!(self.file_handle, "{}", event).map_err(|_| WriteError::Unknown)?;
        Ok(())
    }

    fn write_event_json(&mut self, _event: AuditEvent) -> Result<(), WriteError> {
        todo!()
    }
}