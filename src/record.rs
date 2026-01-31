/*
    Definition of an Audit Record. This corresponds to a single line in an audit log file,
    which may contain multiple fields. Original implementation uses key/value string pairs
    stored in a HashMap, but could be extended to a more strongly typed structure in the
    future.

    Relevant documentation:
    https://github.com/linux-audit/audit-documentation/blob/main/specs/fields/field-dictionary.csv

    Very curious how feasible it is to have a fully typed Record struct, given the wide variety of
    fields that can appear in an audit log line. An incremental approach would be putting everything
    in a HashMap for now, then gradually converting known fields to typed members of the Record struct.
*/

use std::collections::HashMap;

use strum_macros::EnumString;

#[derive(Debug, PartialEq)]
pub struct Record {
    fields: HashMap<String, String>, // identical to RecordFields for now.
}

pub struct RecordFields {
    pub fields: HashMap<String, String>,
}

/// This is a good starting point for typed records. Just read the 'TYPE' field and kaboom.
/// Using strum allows us to automatically convert log types like NETFILTER_CFG and SYSCALL
/// to their enum equivalent by calling RecordType::from_str(<type_string>) on the type that
/// we wish to translate.
#[derive(EnumString, PartialEq, Debug)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum RecordType {
    NetfilterCfg,
    Syscall,
    UserStart,
    CryptoKeyUser,
    CredRefr,
    SystemShutdown,
    CredAcq,
    SystemRunlevel,
    ServiceStop,
    AnomAbend,
    UserCmd,
    Path,
    DaemonStart,
    Proctitle,
    ServiceStart,
    ConfigChange,
    Cwd,
    UserEnd,
    UserAuth,
    DaemonEnd,
    Sockaddr,
    SystemBoot,
    Login,
    UserAcct,
    CredDisp,
    // ... there are loads more.
}

// TODO: Consider auto-generating types from the field dictionary.
// Could use serde, strum, or similar crates for automatic string-to-typed conversion.
// Alternative: Large match statement to convert string type names to RecordType enum variants.
// Evaluate if the complexity is justified for this use case.

impl Record {
    pub fn new(fields: HashMap<String, String>) -> Self {
        Record { fields }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_string_to_enum() {
        assert_eq!(RecordType::from_str("SYSCALL").unwrap(), RecordType::Syscall);
        assert_eq!(RecordType::from_str("NETFILTER_CFG").unwrap(), RecordType::NetfilterCfg);
        assert_eq!(RecordType::from_str("CRED_DISP").unwrap(), RecordType::CredDisp);
        assert_eq!(RecordType::from_str("CRYPTO_KEY_USER").unwrap(), RecordType::CryptoKeyUser);
    }
}