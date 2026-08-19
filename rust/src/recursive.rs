//! Iterative/recursive resolver: walk the DNS hierarchy from the root down,
//! following delegations via glue records in the additional section.

use crate::dns::error::{DnsError, Result};
use crate::resolver::{QueryResponse, StubResolver};

/// A small, well-known set of root servers to seed resolution.
const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4",   // a.root-servers.net
    "199.9.14.201", // b.root-servers.net
    "192.33.4.12",  // c.root-servers.net
];

/// Pull the first usable IPv4 glue address out of a referral's additional
/// section, so we know which nameserver to query next.
fn next_hop_from_glue(response: &QueryResponse) -> Option<String> {
    response
        .additionals
        .iter()
        .find(|r| r.rtype == 1 && r.rdata.len() == 4) // A record, 4 raw bytes
        .map(|r| format!("{}.{}.{}.{}", r.rdata[0], r.rdata[1], r.rdata[2], r.rdata[3]))
}

/// Resolve `domain`/`qtype` starting from the root servers, following
/// delegations until we reach a server that answers authoritatively.
pub async fn recursive_resolve(domain: &str, qtype: u16) -> Result<Vec<String>> {
    let mut nameserver = ROOT_SERVERS[0].to_string();
    let mut depth = 0;

    loop {
        if depth > 16 {
            return Err(DnsError::NetworkError("Max recursion depth exceeded".into()));
        }

        // Talk to authoritative/root servers iteratively (RD cleared): they
        // hand back referrals rather than resolving on our behalf.
        let resolver = StubResolver::new_iterative(&nameserver, 53);
        let response = resolver.query(domain, qtype).await?;

        // Got a direct answer — we're done.
        if !response.answers.is_empty() {
            return Ok(response
                .answers
                .iter()
                .map(|r| format!("{:?}", r.rdata))
                .collect());
        }

        // Otherwise this was a referral: follow the glue to the next server.
        match next_hop_from_glue(&response) {
            Some(next) => nameserver = next,
            None => {
                // A glue-less referral would require resolving the NS hostname
                // itself first — left as an exercise (see notes below).
                return Err(DnsError::NetworkError(
                    "Referral had no glue records to follow".into(),
                ));
            }
        }

        depth += 1;
    }
}