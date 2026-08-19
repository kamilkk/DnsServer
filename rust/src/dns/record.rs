use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub enum RecordType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    MX = 15,
    TXT = 16,
    AAAA = 28,
}

impl RecordType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(RecordType::A),
            2 => Some(RecordType::NS),
            5 => Some(RecordType::CNAME),
            6 => Some(RecordType::SOA),
            15 => Some(RecordType::MX),
            16 => Some(RecordType::TXT),
            28 => Some(RecordType::AAAA),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    NS(String),
    MX { preference: u16, exchange: String },
    TXT(String),
    Unknown(Vec<u8>),
}

impl RData {
    pub fn parse(rtype: u16, data: &[u8]) -> crate::dns::error::Result<Self> {
        match RecordType::from_u16(rtype) {
            Some(RecordType::A) => {
                if data.len() != 4 {
                    return Err(crate::dns::error::DnsError::InvalidDomainName);
                }
                let addr = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
                Ok(RData::A(addr))
            }
            Some(RecordType::AAAA) => {
                if data.len() != 16 {
                    return Err(crate::dns::error::DnsError::InvalidDomainName);
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                let addr = Ipv6Addr::from(octets);
                Ok(RData::AAAA(addr))
            }
            _ => Ok(RData::Unknown(data.to_vec())),
        }
    }
}
