// Audit record parsing. Converts raw socket data into a parsed AuditRecord

use crate::record::*;

type RawAudit = Vec<u8>; // Type to be decided when we figure out what the socket gives us.

fn parse_audit_record(data: RawAudit) -> Result<AuditRecord, ParseError> {
    todo!()
}

enum ParseError {
    // Add in what can go wrong.
}
