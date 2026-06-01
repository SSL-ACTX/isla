// src/icmpv6.rs
use crate::ethernet::MacAddress;
use byteorder::{ByteOrder, NetworkEndian};
use core::net::Ipv6Addr;

pub const ICMPV6_HDR_LEN: usize = 8;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Icmpv6Type {
    DestinationUnreachable,
    PacketTooBig,
    TimeExceeded,
    ParameterProblem,
    EchoRequest,
    EchoReply,
    NeighborSolicitation,
    NeighborAdvertisement,
    Unknown(u8),
}

impl From<u8> for Icmpv6Type {
    fn from(val: u8) -> Self {
        match val {
            1 => Icmpv6Type::DestinationUnreachable,
            2 => Icmpv6Type::PacketTooBig,
            3 => Icmpv6Type::TimeExceeded,
            4 => Icmpv6Type::ParameterProblem,
            128 => Icmpv6Type::EchoRequest,
            129 => Icmpv6Type::EchoReply,
            135 => Icmpv6Type::NeighborSolicitation,
            136 => Icmpv6Type::NeighborAdvertisement,
            other => Icmpv6Type::Unknown(other),
        }
    }
}

pub struct Icmpv6Packet<'a> {
    pub data: &'a [u8],
}

impl<'a> Icmpv6Packet<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < ICMPV6_HDR_LEN {
            return None;
        }
        Some(Self { data })
    }

    pub fn icmpv6_type(&self) -> Icmpv6Type {
        Icmpv6Type::from(self.data[0])
    }

    pub fn code(&self) -> u8 {
        self.data[1]
    }

    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.data[2..4])
    }

    pub fn payload(&self) -> &[u8] {
        &self.data[8..]
    }

    pub fn write_echo_reply(
        buf: &mut [u8],
        src_ip: Ipv6Addr,
        dest_ip: Ipv6Addr,
        identifier: u16,
        seq_num: u16,
        payload: &[u8],
    ) {
        buf[0] = 129; // Type: Echo Reply
        buf[1] = 0; // Code: 0
        buf[2] = 0; // Checksum placeholder
        buf[3] = 0; // Checksum placeholder
        NetworkEndian::write_u16(&mut buf[4..6], identifier);
        NetworkEndian::write_u16(&mut buf[6..8], seq_num);
        buf[8..8 + payload.len()].copy_from_slice(payload);

        let csum = calculate_icmpv6_checksum(&src_ip, &dest_ip, &buf[0..8 + payload.len()]);
        NetworkEndian::write_u16(&mut buf[2..4], csum);
    }

    /// Writes a Neighbor Advertisement responding to a solicitation
    pub fn write_neighbor_advertisement(
        buf: &mut [u8],
        src_ip: Ipv6Addr,
        dest_ip: Ipv6Addr,
        target_ip: Ipv6Addr,
        target_mac: MacAddress,
    ) {
        buf[0] = 136; // Type: Neighbor Advertisement
        buf[1] = 0; // Code
        buf[2] = 0; // Checksum
        buf[3] = 0; // Checksum

        // Flags: Router=0, Solicited=1, Override=1 (0x60)
        buf[4] = 0x60;
        buf[5] = 0;
        buf[6] = 0;
        buf[7] = 0;

        buf[8..24].copy_from_slice(&target_ip.octets());

        // Option: Target Link-Layer Address (Type 2, Length 1 (8 bytes))
        buf[24] = 2;
        buf[25] = 1;
        buf[26..32].copy_from_slice(&target_mac.0);

        let csum = calculate_icmpv6_checksum(&src_ip, &dest_ip, &buf[0..32]);
        NetworkEndian::write_u16(&mut buf[2..4], csum);
    }
}

pub fn calculate_icmpv6_checksum(src_ip: &Ipv6Addr, dest_ip: &Ipv6Addr, icmp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    for word in src_ip.segments() {
        sum += word as u32;
    }
    for word in dest_ip.segments() {
        sum += word as u32;
    }

    sum += icmp_data.len() as u32;
    sum += 58u32; // Next Header (ICMPv6)

    // ICMPv6 Data
    let mut i = 0;
    while i < icmp_data.len() - 1 {
        let word = NetworkEndian::read_u16(&icmp_data[i..i + 2]);
        sum += word as u32;
        i += 2;
    }

    if icmp_data.len() % 2 != 0 {
        sum += (icmp_data[icmp_data.len() - 1] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmpv6_echo_reply() {
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let dest = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let mut buf = [0u8; 12];
        Icmpv6Packet::write_echo_reply(&mut buf, src, dest, 0x1234, 0x5678, b"ping");

        let packet = Icmpv6Packet::new(&buf).unwrap();
        assert_eq!(packet.icmpv6_type(), Icmpv6Type::EchoReply);
        assert_eq!(NetworkEndian::read_u16(&packet.data[4..6]), 0x1234);
        assert_eq!(NetworkEndian::read_u16(&packet.data[6..8]), 0x5678);
        assert_eq!(packet.payload(), b"ping");
    }

    #[test]
    fn test_icmpv6_neighbor_advertisement() {
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let dest = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let mac = MacAddress([1, 2, 3, 4, 5, 6]);
        let mut buf = [0u8; 32];
        Icmpv6Packet::write_neighbor_advertisement(&mut buf, src, dest, target, mac);

        let packet = Icmpv6Packet::new(&buf).unwrap();
        assert_eq!(packet.icmpv6_type(), Icmpv6Type::NeighborAdvertisement);
        assert_eq!(packet.data[4], 0x60); // Flags
        let mut target_bytes = [0u8; 16];
        target_bytes.copy_from_slice(&packet.data[8..24]);
        assert_eq!(Ipv6Addr::from(target_bytes), target);
        assert_eq!(packet.data[24], 2); // Option Type: Target Link-Layer Address
        assert_eq!(&packet.data[26..32], &mac.0);
    }
}
