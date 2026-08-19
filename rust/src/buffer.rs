use crate::dns::error::{DnsError, Result};

/// A buffer for reading DNS packets with compression pointer support
pub struct ByteBuffer {
    data: Vec<u8>,
    position: usize,
}

impl ByteBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, position: 0 }
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        if self.position >= self.data.len() {
            return Err(DnsError::BufferTooSmall {
                need: self.position + 1,
                have: self.data.len(),
            });
        }
        let byte = self.data[self.position];
        self.position += 1;
        Ok(byte)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        if self.position + 2 > self.data.len() {
            return Err(DnsError::BufferTooSmall {
                need: self.position + 2,
                have: self.data.len(),
            });
        }
        let bytes = [self.data[self.position], self.data[self.position + 1]];
        self.position += 2;
        Ok(u16::from_be_bytes(bytes))
    }

    pub fn read_u32(&mut self) -> Result<u32> {
        if self.position + 4 > self.data.len() {
            return Err(DnsError::BufferTooSmall {
                need: self.position + 4,
                have: self.data.len(),
            });
        }
        let bytes = [
            self.data[self.position],
            self.data[self.position + 1],
            self.data[self.position + 2],
            self.data[self.position + 3],
        ];
        self.position += 4;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn skip(&mut self, count: usize) -> Result<()> {
        if self.position + count > self.data.len() {
            return Err(DnsError::BufferTooSmall {
                need: self.position + count,
                have: self.data.len(),
            });
        }
        self.position += count;
        Ok(())
    }

    pub fn peek_u8(&self) -> Result<u8> {
        if self.position >= self.data.len() {
            return Err(DnsError::BufferTooSmall {
                need: self.position + 1,
                have: self.data.len(),
            });
        }
        Ok(self.data[self.position])
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn set_position(&mut self, position: usize) {
        self.position = position;
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.position
    }
}

/// Writer for building DNS packets
pub struct ByteWriter {
    data: Vec<u8>,
}

impl ByteWriter {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn write_u8(&mut self, value: u8) {
        self.data.push(value);
    }

    pub fn write_u16(&mut self, value: u16) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_u32(&mut self, value: u32) {
        self.data.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Default for ByteWriter {
    fn default() -> Self {
        Self::new()
    }
}