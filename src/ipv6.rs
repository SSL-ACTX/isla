// src/ipv6.rs
use byteorder::{ByteOrder, NetworkEndian};
use core::net::Ipv6Addr;

pub const IPV6_HDR_LEN: usize = 40;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Ipv6NextHeader {
    ICMPv6,
    TCP,
    UDP,
    Unknown(u8),
}

impl From<u8> for Ipv6NextHeader {
    fn from(val: u8) -> Self {
        match val {
            58 => Ipv6NextHeader::ICMPv6,
            6 => Ipv6NextHeader::TCP,
            17 => Ipv6NextHeader::UDP,
            other => Ipv6NextHeader::Unknown(other),
        }
    }
}

pub struct Ipv6Packet<'a> {
    pub data: &'a [u8],
}

impl<'a> Ipv6Packet<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < IPV6_HDR_LEN {
            return None;
        }
        let version = data[0] >> 4;
        if version != 6 {
            return None;
        }
        Some(Self { data })
    }

    pub fn payload_length(&self) -> u16 {
        NetworkEndian::read_u16(&self.data[4..6])
    }

    pub fn next_header(&self) -> Ipv6NextHeader {
        Ipv6NextHeader::from(self.data[6])
    }

    pub fn hop_limit(&self) -> u8 {
        self.data[7]
    }

    pub fn source_ip(&self) -> Ipv6Addr {
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&self.data[8..24]);
        Ipv6Addr::from(addr)
    }

    pub fn dest_ip(&self) -> Ipv6Addr {
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&self.data[24..40]);
        Ipv6Addr::from(addr)
    }

    pub fn payload(&self) -> &[u8] {
        let len = self.payload_length() as usize;
        let end = IPV6_HDR_LEN + len;
        if end > self.data.len() {
            &self.data[IPV6_HDR_LEN..]
        } else {
            &self.data[IPV6_HDR_LEN..end]
        }
    }

    pub fn write_header(
        buf: &mut [u8],
        src_ip: Ipv6Addr,
        dest_ip: Ipv6Addr,
        next_header: Ipv6NextHeader,
        payload_len: u16,
    ) {
        // Version 6, Traffic Class 0, Flow Label 0
        buf[0] = 0x60;
        buf[1] = 0x00;
        buf[2] = 0x00;
        buf[3] = 0x00;

        NetworkEndian::write_u16(&mut buf[4..6], payload_len);
        buf[6] = match next_header {
            Ipv6NextHeader::ICMPv6 => 58,
            Ipv6NextHeader::TCP => 6,
            Ipv6NextHeader::UDP => 17,
            Ipv6NextHeader::Unknown(p) => p,
        };
        buf[7] = 64; // Hop Limit

        buf[8..24].copy_from_slice(&src_ip.octets());
        buf[24..40].copy_from_slice(&dest_ip.octets());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_parsing() {
        let mut data = [0u8; 40];
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let dest = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        Ipv6Packet::write_header(&mut data, src, dest, Ipv6NextHeader::TCP, 100);

        let packet = Ipv6Packet::new(&data).unwrap();
        assert_eq!(packet.source_ip(), src);
        assert_eq!(packet.dest_ip(), dest);
        assert_eq!(packet.next_header(), Ipv6NextHeader::TCP);
        assert_eq!(packet.payload_length(), 100);
    }
}
