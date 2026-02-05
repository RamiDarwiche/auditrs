pub trait AuditSource {
    fn read_message(&self) -> Option<Vec<u8>>;
    fn start(&mut self);
}