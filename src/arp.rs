// src/arp.rs
use crate::ethernet::MacAddress;
use byteorder::{ByteOrder, NetworkEndian};
use core::net::Ipv4Addr;

pub const ARP_HDR_LEN: usize = 28;

#[derive(Debug, PartialEq, Eq)]
pub enum ArpOp {
    Request,
    Reply,
    Unknown(u16),
}

impl From<u16> for ArpOp {
    fn from(val: u16) -> Self {
        match val {
            1 => ArpOp::Request,
            2 => ArpOp::Reply,
            other => ArpOp::Unknown(other),
        }
    }
}

pub struct ArpPacket<'a> {
    pub data: &'a [u8],
}

impl<'a> ArpPacket<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < ARP_HDR_LEN {
            return None;
        }
        Some(Self { data })
    }

    pub fn operation(&self) -> ArpOp {
        ArpOp::from(NetworkEndian::read_u16(&self.data[6..8]))
    }

    pub fn sender_mac(&self) -> MacAddress {
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&self.data[8..14]);
        MacAddress(addr)
    }

    pub fn sender_ip(&self) -> Ipv4Addr {
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&self.data[14..18]);
        Ipv4Addr::from(addr)
    }

    pub fn target_mac(&self) -> MacAddress {
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&self.data[18..24]);
        MacAddress(addr)
    }

    pub fn target_ip(&self) -> Ipv4Addr {
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&self.data[24..28]);
        Ipv4Addr::from(addr)
    }

    /// Constructs an ARP Reply packet in the provided buffer
    pub fn write_reply(
        buf: &mut [u8],
        sender_mac: MacAddress,
        sender_ip: Ipv4Addr,
        target_mac: MacAddress,
        target_ip: Ipv4Addr,
    ) {
        // Hardware Type: Ethernet (1)
        NetworkEndian::write_u16(&mut buf[0..2], 1);
        // Protocol Type: IPv4 (0x0800)
        NetworkEndian::write_u16(&mut buf[2..4], 0x0800);
        // Hardware Size (6), Protocol Size (4)
        buf[4] = 6;
        buf[5] = 4;
        // Operation: Reply (2)
        NetworkEndian::write_u16(&mut buf[6..8], 2);

        buf[8..14].copy_from_slice(&sender_mac.0);
        buf[14..18].copy_from_slice(&sender_ip.octets());
        buf[18..24].copy_from_slice(&target_mac.0);
        buf[24..28].copy_from_slice(&target_ip.octets());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_parsing() {
        let mut data = [0u8; 28];
        let sender_mac = MacAddress([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let sender_ip = Ipv4Addr::new(192, 168, 1, 1);
        let target_mac = MacAddress([0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]);
        let target_ip = Ipv4Addr::new(192, 168, 1, 2);

        ArpPacket::write_reply(&mut data, sender_mac, sender_ip, target_mac, target_ip);

        let packet = ArpPacket::new(&data).unwrap();
        assert_eq!(packet.operation(), ArpOp::Reply);
        assert_eq!(packet.sender_mac(), sender_mac);
        assert_eq!(packet.sender_ip(), sender_ip);
        assert_eq!(packet.target_mac(), target_mac);
        assert_eq!(packet.target_ip(), target_ip);
    }
}
