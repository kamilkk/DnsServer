use crate::dns::error::Result;

/// DNS Header structure (12 bytes fixed)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub id: u16,                    // Query identifier
    pub query_response: bool,       // Query (false) or Response (true)
    pub opcode: u8,                 // Operation code (0-15)
    pub authoritative_answer: bool, // Authoritative Answer flag
    pub truncation: bool,           // Truncation flag
    pub recursion_desired: bool,    // Recursion Desired
    pub recursion_available: bool,  // Recursion Available
    pub z: u8,                      // Reserved (must be 0)
    pub response_code: u8,          // Response code (0-15)
    pub question_count: u16,        // Number of questions
    pub answer_count: u16,          // Number of answer RRs
    pub nameserver_count: u16,      // Number of authority RRs
    pub additional_count: u16,      // Number of additional RRs
}

impl Header {
    pub const SIZE: usize = 12;

    pub fn new() -> Self {
        Self {
            id: 0,
            query_response: false,
            opcode: 0,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: false,
            recursion_available: false,
            z: 0,
            response_code: 0,
            question_count: 0,
            answer_count: 0,
            nameserver_count: 0,
            additional_count: 0,
        }
    }

    /// Serialize header to binary format (12 bytes)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZE);

        // ID (2 bytes, big-endian)
        buf.extend_from_slice(&self.id.to_be_bytes());

        // Flags (2 bytes)
        let flags = self.encode_flags();
        buf.extend_from_slice(&flags.to_be_bytes());

        // Counts (8 bytes)
        buf.extend_from_slice(&self.question_count.to_be_bytes());
        buf.extend_from_slice(&self.answer_count.to_be_bytes());
        buf.extend_from_slice(&self.nameserver_count.to_be_bytes());
        buf.extend_from_slice(&self.additional_count.to_be_bytes());

        buf
    }

    /// Parse header from binary buffer
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(crate::dns::error::DnsError::BufferTooSmall {
                need: Self::SIZE,
                have: buf.len(),
            });
        }

        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let question_count = u16::from_be_bytes([buf[4], buf[5]]);
        let answer_count = u16::from_be_bytes([buf[6], buf[7]]);
        let nameserver_count = u16::from_be_bytes([buf[8], buf[9]]);
        let additional_count = u16::from_be_bytes([buf[10], buf[11]]);

        let (
            query_response,
            opcode,
            authoritative_answer,
            truncation,
            recursion_desired,
            recursion_available,
            z,
            response_code,
        ) = Self::decode_flags(flags);

        Ok(Self {
            id,
            query_response,
            opcode,
            authoritative_answer,
            truncation,
            recursion_desired,
            recursion_available,
            z,
            response_code,
            question_count,
            answer_count,
            nameserver_count,
            additional_count,
        })
    }

    /// Encode flags into 16-bit field
    /// Format: [QR | Opcode(4) | AA | TC | RD | RA | Z(3) | RCODE(4)]
    fn encode_flags(&self) -> u16 {
        let mut flags = 0u16;

        flags |= (self.query_response as u16) << 15;
        flags |= (self.opcode as u16) << 11;
        flags |= (self.authoritative_answer as u16) << 10;
        flags |= (self.truncation as u16) << 9;
        flags |= (self.recursion_desired as u16) << 8;
        flags |= (self.recursion_available as u16) << 7;
        flags |= (self.z as u16) << 4;
        flags |= self.response_code as u16;

        flags
    }

    /// Decode 16-bit flags field
    fn decode_flags(flags: u16) -> (bool, u8, bool, bool, bool, bool, u8, u8) {
        let query_response = (flags >> 15) & 1 != 0;
        let opcode = ((flags >> 11) & 0xF) as u8;
        let authoritative_answer = (flags >> 10) & 1 != 0;
        let truncation = (flags >> 9) & 1 != 0;
        let recursion_desired = (flags >> 8) & 1 != 0;
        let recursion_available = (flags >> 7) & 1 != 0;
        let z = ((flags >> 4) & 0x7) as u8;
        let response_code = (flags & 0xF) as u8;

        (
            query_response,
            opcode,
            authoritative_answer,
            truncation,
            recursion_desired,
            recursion_available,
            z,
            response_code,
        )
    }
}

impl Default for Header {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let mut header = Header::new();
        header.id = 12345;
        header.query_response = true;
        header.recursion_desired = true;
        header.question_count = 1;
        header.answer_count = 2;

        let bytes = header.to_bytes();
        let parsed = Header::from_bytes(&bytes).unwrap();

        assert_eq!(parsed, header);
    }

    #[test]
    fn test_header_serialization() {
        let header = Header {
            id: 0x1234,
            recursion_desired: true,
            question_count: 1,
            ..Header::new()
        };

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 12);
        assert_eq!(bytes[0], 0x12);
        assert_eq!(bytes[1], 0x34);
    }
}