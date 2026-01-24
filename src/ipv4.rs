// src/ipv4.rs
use crate::utils::checksum;
use byteorder::{ByteOrder, NetworkEndian};
use core::net::Ipv4Addr;

pub const IPV4_HDR_LEN: usize = 20;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum IpProtocol {
    ICMP,
    TCP,
    UDP,
    Unknown(u8),
}

impl From<u8> for IpProtocol {
    fn from(val: u8) -> Self {
        match val {
            1 => IpProtocol::ICMP,
            6 => IpProtocol::TCP,
            17 => IpProtocol::UDP,
            other => IpProtocol::Unknown(other),
        }
    }
}

pub struct Ipv4Packet<'a> {
    pub data: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < IPV4_HDR_LEN {
            return None;
        }
        Some(Self { data })
    }

    pub fn header_length(&self) -> usize {
        ((self.data[0] & 0x0F) as usize) * 4
    }

    pub fn protocol(&self) -> IpProtocol {
        IpProtocol::from(self.data[9])
    }

    pub fn source_ip(&self) -> Ipv4Addr {
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&self.data[12..16]);
        Ipv4Addr::from(addr)
    }

    pub fn dest_ip(&self) -> Ipv4Addr {
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&self.data[16..20]);
        Ipv4Addr::from(addr)
    }

    pub fn payload(&self) -> &[u8] {
        &self.data[self.header_length()..]
    }

    /// Writes an IPv4 header into the buffer
    pub fn write_header(
        buf: &mut [u8],
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        protocol: IpProtocol,
        payload_len: usize,
    ) {
        buf[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        buf[1] = 0;    // DSCP/ECN
        NetworkEndian::write_u16(&mut buf[2..4], (IPV4_HDR_LEN + payload_len) as u16);
        NetworkEndian::write_u16(&mut buf[4..6], 0); // Identification
        NetworkEndian::write_u16(&mut buf[6..8], 0x4000); // Flags: Don't Fragment
        buf[8] = 64;   // TTL
        buf[9] = match protocol {
            IpProtocol::ICMP => 1,
            IpProtocol::TCP => 6,
            IpProtocol::UDP => 17,
            IpProtocol::Unknown(p) => p,
        };
        buf[10] = 0;   // Checksum placeholder
        buf[11] = 0;   // Checksum placeholder
        buf[12..16].copy_from_slice(&src_ip.octets());
        buf[16..20].copy_from_slice(&dest_ip.octets());

        let csum = checksum(&buf[0..IPV4_HDR_LEN]);
        NetworkEndian::write_u16(&mut buf[10..12], csum);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_parsing() {
        let mut data = [0u8; 20];
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dest = Ipv4Addr::new(192, 168, 1, 2);
        Ipv4Packet::write_header(&mut data, src, dest, IpProtocol::TCP, 100);

        let packet = Ipv4Packet::new(&data).unwrap();
        assert_eq!(packet.source_ip(), src);
        assert_eq!(packet.dest_ip(), dest);
        assert_eq!(packet.protocol(), IpProtocol::TCP);
        assert_eq!(packet.header_length(), 20);
    }
}
