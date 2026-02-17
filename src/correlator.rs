use crate::record::AuditRecord;
use crate::event::AuditEvent;

pub struct AuditRecordCorrelator { }

impl AuditRecordCorrelator {
    pub fn new() -> Self {
        todo!()
    }
    fn correlate_records(record_buffer: Vec<AuditRecord>) -> Vec<AuditEvent> {
        todo!()
    }
}