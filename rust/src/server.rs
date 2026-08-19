use crate::buffer::{ByteBuffer, ByteWriter};
use crate::dns::error::Result;
use crate::dns::header::Header;
use crate::dns::question::{write_domain_name, Question};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{info, warn};

pub struct DnsServer {
    socket: Arc<UdpSocket>,
    records: Arc<HashMap<String, String>>,
}

impl DnsServer {
    pub async fn bind(addr: &str) -> Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        info!("DNS server listening on {}", addr);

        Ok(Self {
            socket: Arc::new(socket),
            records: Arc::new(HashMap::new()),
        })
    }

    pub fn with_records(mut self, records: HashMap<String, String>) -> Self {
        self.records = Arc::new(records);
        self
    }

    pub async fn run(self) -> Result<()> {
        let mut buf = vec![0u8; 512];

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    let data = buf[..len].to_vec();
                    let socket = Arc::clone(&self.socket);
                    let records = Arc::clone(&self.records);

                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_query(socket, peer_addr, &data, &records).await
                        {
                            warn!("Error handling query: {}", e);
                        }
                    });
                }
                Err(e) => {
                    warn!("Error receiving data: {}", e);
                }
            }
        }
    }

    async fn handle_query(
        socket: Arc<UdpSocket>,
        peer_addr: std::net::SocketAddr,
        data: &[u8],
        records: &HashMap<String, String>,
    ) -> Result<()> {
        // Parse query header
        let header = Header::from_bytes(data)?;
        let mut buf = ByteBuffer::new(data.to_vec());
        buf.skip(Header::SIZE)?;

        // Parse questions
        let mut questions = Vec::new();
        for _ in 0..header.question_count {
            questions.push(Question::parse(&mut buf)?);
        }

        // Build response
        let mut response_header = Header::new();
        response_header.id = header.id;
        response_header.query_response = true;
        response_header.recursion_desired = header.recursion_desired;
        response_header.question_count = questions.len() as u16;

        let mut writer = ByteWriter::new();
        writer.write_bytes(&response_header.to_bytes());

        // Write questions
        for q in &questions {
            q.write_to(&mut writer)?;
        }

        // Find answers
        for q in &questions {
            if q.qtype == 1 {
                // A record query
                let domain = q.name.trim_end_matches('.');
                if let Some(ip) = records.get(domain) {
                    let octets: Vec<u8> = ip
                        .split('.')
                        .map(|s| s.parse::<u8>().unwrap_or(0))
                        .collect();

                    // Write answer RR
                    write_domain_name(&mut writer, &q.name);
                    writer.write_u16(1); // Type A
                    writer.write_u16(1); // Class IN
                    writer.write_u32(300); // TTL
                    writer.write_u16(4); // RData length
                    writer.write_bytes(&octets);

                    response_header.answer_count = 1;
                }
            }
        }

        let response = writer.into_vec();
        socket.send_to(&response, peer_addr).await?;

        info!(
            "Responded to {} with {} answers",
            peer_addr, response_header.answer_count
        );

        Ok(())
    }
}