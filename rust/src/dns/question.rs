use crate::buffer::{ByteBuffer, ByteWriter};
use crate::dns::error::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl Question {
    pub fn new(name: impl Into<String>, qtype: u16, qclass: u16) -> Self {
        Self {
            name: name.into(),
            qtype,
            qclass,
        }
    }

    pub fn parse(buffer: &mut ByteBuffer) -> Result<Self> {
        let name = parse_domain_name(buffer, 0)?;
        let qtype = buffer.read_u16()?;
        let qclass = buffer.read_u16()?;

        Ok(Self { name, qtype, qclass })
    }

    pub fn write_to(&self, writer: &mut ByteWriter) -> Result<()> {
        write_domain_name(writer, &self.name);
        writer.write_u16(self.qtype);
        writer.write_u16(self.qclass);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl ResourceRecord {
    pub fn parse(buffer: &mut ByteBuffer) -> Result<Self> {
        let name = parse_domain_name(buffer, 0)?;
        let rtype = buffer.read_u16()?;
        let rclass = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let rdlen = buffer.read_u16()? as usize;

        if buffer.remaining() < rdlen {
            return Err(crate::dns::error::DnsError::BufferTooSmall {
                need: rdlen,
                have: buffer.remaining(),
            });
        }

        let mut rdata = vec![0u8; rdlen];
        for i in 0..rdlen {
            rdata[i] = buffer.read_u8()?;
        }

        Ok(Self {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        })
    }
}

/// Parse a DNS domain name with support for compression pointers
/// Compression is indicated by the two high bits being set (11xxxxxx)
pub fn parse_domain_name(buffer: &mut ByteBuffer, jumps: usize) -> Result<String> {
    let mut name = String::new();
    const MAX_JUMPS: usize = 5;

    loop {
        let len = buffer.peek_u8()?;

        // Check for compression pointer (high 2 bits = 11)
        if (len & 0xC0) == 0xC0 {
            if jumps >= MAX_JUMPS {
                return Err(crate::dns::error::DnsError::CompressionLoop);
            }

            buffer.read_u8()?; // Consume first byte
            let second = buffer.read_u8()?;

            // Calculate offset
            let offset = (((len & 0x3F) as u16) << 8) | second as u16;
            let offset = offset as usize;

            // Jump to pointer location
            let saved_pos = buffer.position();
            buffer.set_position(offset);

            // Recursively parse from pointer
            name.push_str(&parse_domain_name(buffer, jumps + 1)?);

            // Restore position
            buffer.set_position(saved_pos);
            break;
        }

        // End of name
        if len == 0 {
            buffer.read_u8()?; // Consume zero byte
            break;
        }

        // Read label
        buffer.read_u8()?; // Consume length byte
        let mut label = vec![0u8; len as usize];
        for i in 0..len as usize {
            label[i] = buffer.read_u8()?;
        }

        if !name.is_empty() {
            name.push('.');
        }

        name.push_str(&String::from_utf8_lossy(&label));
    }

    Ok(name)
}

/// Write a domain name to the buffer.
/// Empty labels are skipped so a trailing dot ("example.com.") does not emit a
/// premature zero-length label that would truncate the encoded name.
pub fn write_domain_name(writer: &mut ByteWriter, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue; // skip empty labels (e.g. a trailing dot in "example.com.")
        }
        writer.write_u8(label.len() as u8);
        writer.write_bytes(label.as_bytes());
    }
    writer.write_u8(0); // root label / null terminator
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_name_parsing() {
        let data = b"\x07example\x03com\x00";
        let mut buf = ByteBuffer::new(data.to_vec());
        let name = parse_domain_name(&mut buf, 0).unwrap();
        assert_eq!(name, "example.com");
    }

    #[test]
    fn test_domain_name_writing() {
        let mut writer = ByteWriter::new();
        write_domain_name(&mut writer, "example.com");
        let bytes = writer.into_vec();
        assert_eq!(bytes, b"\x07example\x03com\x00");
    }
}