use crate::buffer::{ByteBuffer, ByteWriter};
use crate::dns::error::Result;
use crate::dns::header::Header;
use crate::dns::question::{Question, ResourceRecord};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

pub struct StubResolver {
    upstream: String,
    port: u16,
    timeout: Duration,
    recursion_desired: bool,
}

impl StubResolver {
    /// Create a resolver that sets the Recursion Desired bit (for upstream
    /// resolvers like 8.8.8.8 that will do the recursion for you).
    pub fn new(upstream: impl Into<String>, port: u16) -> Self {
        Self {
            upstream: upstream.into(),
            port,
            timeout: Duration::from_secs(5),
            recursion_desired: true,
        }
    }

    /// Create a resolver with RD cleared, for talking directly to
    /// authoritative/root servers that answer with referrals, not recursion.
    pub fn new_iterative(upstream: impl Into<String>, port: u16) -> Self {
        Self {
            upstream: upstream.into(),
            port,
            timeout: Duration::from_secs(5),
            recursion_desired: false,
        }
    }

    pub async fn query(&self, domain: &str, qtype: u16) -> Result<QueryResponse> {
        // Build query header
        let mut header = Header::new();
        header.id = rand::random();
        header.recursion_desired = self.recursion_desired;
        header.question_count = 1;

        // Build question
        let question = Question::new(domain, qtype, 1);

        // Serialize query
        let mut writer = ByteWriter::new();
        writer.write_bytes(&header.to_bytes());
        question.write_to(&mut writer)?;
        let query_packet = writer.into_vec();

        // Send query
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addr: SocketAddr = format!("{}:{}", self.upstream, self.port)
            .parse()
            .map_err(|_| crate::dns::error::DnsError::NetworkError("Invalid address".into()))?;
        socket.send_to(&query_packet, addr).await?;

        // Receive response with timeout
        let mut response_buf = vec![0u8; 512];
        let receive_future = socket.recv_from(&mut response_buf);
        let (n, _) = timeout(self.timeout, receive_future)
            .await
            .map_err(|_| crate::dns::error::DnsError::NetworkError("Timeout".into()))??;
        response_buf.truncate(n);

        // Parse response
        self.parse_response(&response_buf)
    }

    fn parse_response(&self, data: &[u8]) -> Result<QueryResponse> {
        let mut buf = ByteBuffer::new(data.to_vec());

        let header = Header::from_bytes(data)?;
        buf.skip(Header::SIZE)?;

        // Questions
        let mut questions = Vec::new();
        for _ in 0..header.question_count {
            questions.push(Question::parse(&mut buf)?);
        }

        // Answer section
        let mut answers = Vec::new();
        for _ in 0..header.answer_count {
            answers.push(ResourceRecord::parse(&mut buf)?);
        }

        // Authority section (NS referrals live here)
        let mut authorities = Vec::new();
        for _ in 0..header.nameserver_count {
            authorities.push(ResourceRecord::parse(&mut buf)?);
        }

        // Additional section (glue A/AAAA records for the referral live here)
        let mut additionals = Vec::new();
        for _ in 0..header.additional_count {
            additionals.push(ResourceRecord::parse(&mut buf)?);
        }

        Ok(QueryResponse {
            header,
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

#[derive(Debug)]
pub struct QueryResponse {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}