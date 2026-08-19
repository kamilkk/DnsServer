pub mod buffer;
pub mod dns;
pub mod recursive;
pub mod resolver;
pub mod server;

pub use dns::error::{DnsError, Result};
pub use recursive::recursive_resolve;