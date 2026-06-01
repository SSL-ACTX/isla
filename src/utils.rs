// src/utils.rs
use byteorder::{ByteOrder, NetworkEndian};
use core::hash::Hasher;
use core::net::Ipv4Addr;

// In a real stack, this should be a random value generated at startup.
const SECRET_KEY: u64 = 0xDEAD_BEEF_CAFE_BABE;

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let len = data.len();
    let mut i = 0;

    while i < len - 1 {
        let word = NetworkEndian::read_u16(&data[i..i + 2]);
        sum += word as u32;
        i += 2;
    }

    if len % 2 != 0 {
        sum += (data[len - 1] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// TCP Checksum includes a "pseudo-header" of IP addresses
pub fn tcp_checksum(src_ip: Ipv4Addr, dest_ip: Ipv4Addr, tcp_data: &[u8]) -> u16 {
    let mut pseudo_header = alloc::vec::Vec::with_capacity(12 + tcp_data.len());

    pseudo_header.extend_from_slice(&src_ip.octets());
    pseudo_header.extend_from_slice(&dest_ip.octets());
    pseudo_header.push(0); // Reserved
    pseudo_header.push(6); // Protocol TCP

    let mut len_buf = [0u8; 2];
    NetworkEndian::write_u16(&mut len_buf, tcp_data.len() as u16);
    pseudo_header.extend_from_slice(&len_buf);

    pseudo_header.extend_from_slice(tcp_data);

    checksum(&pseudo_header)
}

/// A simple Jenkins Hash implementation
/// This allows us to hash without OS dependency.
struct JenkinsHasher {
    hash: u64,
}

impl JenkinsHasher {
    fn new() -> Self {
        Self { hash: 0 }
    }
}

impl Hasher for JenkinsHasher {
    fn finish(&self) -> u64 {
        let mut h = self.hash;
        h = h.wrapping_add(h << 3);
        h ^= h >> 11;
        h = h.wrapping_add(h << 15);
        h
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.hash = self.hash.wrapping_add(byte as u64);
            self.hash = self.hash.wrapping_add(self.hash << 10);
            self.hash ^= self.hash >> 6;
        }
    }
}

/// Generates a stateless TCP Sequence Number (SYN Cookie)
/// Hash(SrcIP, SrcPort, DstIP, DstPort, Secret, ClientISN)
pub fn generate_syn_cookie(
    src_ip: Ipv4Addr,
    src_port: u16,
    dest_ip: Ipv4Addr,
    dest_port: u16,
    client_isn: u32,
) -> u32 {
    let mut hasher = JenkinsHasher::new();
    hasher.write(&src_ip.octets());
    hasher.write_u16(src_port);
    hasher.write(&dest_ip.octets());
    hasher.write_u16(dest_port);
    hasher.write_u32(client_isn);
    hasher.write_u64(SECRET_KEY);

    // We truncate the 64-bit hash to 32 bits for the Sequence Number
    hasher.finish() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        let data = [
            0x45, 0x00, 0x00, 0x3d, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0xc0, 0xa8,
            0x01, 0x01, 0xc0, 0xa8, 0x01, 0x02,
        ];
        let csum = checksum(&data);
        assert_ne!(csum, 0);

        // If we write the checksum back, the new checksum should be 0 (RFC 1071)
        // Note: checksum returns the one's complement.
        let mut data_with_csum = data;
        NetworkEndian::write_u16(&mut data_with_csum[10..12], csum);
        assert_eq!(checksum(&data_with_csum), 0);
    }

    #[test]
    fn test_jenkins_hash() {
        let mut h1 = JenkinsHasher::new();
        h1.write(b"isla");
        let res1 = h1.finish();

        let mut h2 = JenkinsHasher::new();
        h2.write(b"isla");
        let res2 = h2.finish();

        assert_eq!(res1, res2);

        let mut h3 = JenkinsHasher::new();
        h3.write(b"other");
        assert_ne!(res1, h3.finish());
    }
}
