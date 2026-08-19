use dns_server::server::DnsServer;
use dns_server::Result;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut records = HashMap::new();
    records.insert("example.local".to_string(), "192.168.1.10".to_string());
    records.insert("test.local".to_string(), "127.0.0.1".to_string());

    let server = DnsServer::bind("127.0.0.1:15353")
        .await?
        .with_records(records);

    server.run().await?;

    Ok(())
}
