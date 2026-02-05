use super::*;
pub struct NetlinkSocketReader {
    // evil evil evil evil
}

impl AuditSource for NetlinkSocketReader {
    fn read_message(&self) -> Option<Vec<u8>> {
        todo!()
    }
    fn start(&mut self) {
        todo!()
    }
}