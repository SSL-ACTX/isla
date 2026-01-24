// src/dns.rs
use byteorder::{ByteOrder, NetworkEndian};
use alloc::vec::Vec;
use alloc::string::String;

pub struct DnsQuery {
    pub transaction_id: u16,
}

impl DnsQuery {
    pub fn new(id: u16) -> Self {
        Self { transaction_id: id }
    }

    /// Encodes a domain name into DNS format (e.g., "google.com" -> "\x06google\x03com\x00")
    fn encode_name(name: &str) -> Vec<u8> {
        let mut encoded = Vec::new();
        for part in name.split('.') {
            encoded.push(part.len() as u8);
            encoded.extend_from_slice(part.as_bytes());
        }
        encoded.push(0); // Null terminator
        encoded
    }

    /// Builds a standard DNS A-Record Query
    pub fn build_query(&self, domain: &str) -> Vec<u8> {
        let mut packet = Vec::new();

        // --- Header (12 bytes) ---
        // Transaction ID (2 bytes)
        let mut buf_u16 = [0u8; 2];
        NetworkEndian::write_u16(&mut buf_u16, self.transaction_id);
        packet.extend_from_slice(&buf_u16);

        // Flags: 0x0100 (Standard Query, Recursion Desired)
        NetworkEndian::write_u16(&mut buf_u16, 0x0100);
        packet.extend_from_slice(&buf_u16);

        // Questions Count: 1
        NetworkEndian::write_u16(&mut buf_u16, 1);
        packet.extend_from_slice(&buf_u16);

        // Answer RRs: 0
        NetworkEndian::write_u16(&mut buf_u16, 0);
        packet.extend_from_slice(&buf_u16);

        // Authority RRs: 0
        NetworkEndian::write_u16(&mut buf_u16, 0);
        packet.extend_from_slice(&buf_u16);

        // Additional RRs: 0
        NetworkEndian::write_u16(&mut buf_u16, 0);
        packet.extend_from_slice(&buf_u16);

        // --- Question Section ---
        // QNAME
        packet.extend(Self::encode_name(domain));

        // QTYPE: A (Host Address) = 1
        NetworkEndian::write_u16(&mut buf_u16, 1);
        packet.extend_from_slice(&buf_u16);

        // QCLASS: IN (Internet) = 1
        NetworkEndian::write_u16(&mut buf_u16, 1);
        packet.extend_from_slice(&buf_u16);

        packet
    }
}

pub fn parse_response(data: &[u8]) -> Option<String> {
    // Very naive parser. Just checks if it's a response to us.
    if data.len() < 12 { return None; }

    // Check if it's a response (QR bit set)
    // Flags are at bytes 2..4
    let flags = NetworkEndian::read_u16(&data[2..4]);
    if (flags & 0x8000) != 0 {
        return Some(String::from("DNS Response Received!"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_encoding() {
        let name = "google.com";
        let encoded = DnsQuery::encode_name(name);
        assert_eq!(encoded, b"\x06google\x03com\x00");
    }

    #[test]
    fn test_dns_query_build() {
        let query = DnsQuery::new(0x1234);
        let packet = query.build_query("example.com");
        assert_eq!(NetworkEndian::read_u16(&packet[0..2]), 0x1234);
        assert_eq!(NetworkEndian::read_u16(&packet[2..4]), 0x0100);
    }
}
