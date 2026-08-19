//! DNS wire-format types: header, question/records, error definitions.

pub mod error;
pub mod header;
pub mod question;
pub mod record;

// Convenient re-exports so callers can write `dns::Header` instead of
// `dns::header::Header`, and share one error/Result type across the crate.
pub use error::{DnsError, Result};
pub use header::Header;
pub use question::{parse_domain_name, write_domain_name, Question, ResourceRecord};
pub use record::{RData, RecordType};