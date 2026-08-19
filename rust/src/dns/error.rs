use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("Buffer too small: need {need}, have {have}")]
    BufferTooSmall { need: usize, have: usize },

    #[error("Invalid domain name")]
    InvalidDomainName,

    #[error("Compression pointer loop detected")]
    CompressionLoop,

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Network error: {0}")]
    NetworkError(String),
}

pub type Result<T> = std::result::Result<T, DnsError>;