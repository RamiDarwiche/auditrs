use crate::audit_sources::AuditSource;

pub struct MockSocketReader;

impl AuditSource for MockSocketReader {
    fn read_message(&self) -> Option<Vec<u8>> {
        todo!()
    }
}