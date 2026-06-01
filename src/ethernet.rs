// src/ethernet.rs
use byteorder::{ByteOrder, NetworkEndian};
use core::fmt;

pub const ETH_ADDR_LEN: usize = 6;
pub const ETH_HDR_LEN: usize = 14;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct MacAddress(pub [u8; ETH_ADDR_LEN]);

impl MacAddress {
    pub const BROADCAST: Self = MacAddress([0xff; 6]);
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EtherType {
    IPv4,
    ARP,
    IPv6,
    Unknown(u16),
}

impl From<u16> for EtherType {
    fn from(val: u16) -> Self {
        match val {
            0x0800 => EtherType::IPv4,
            0x0806 => EtherType::ARP,
            0x86DD => EtherType::IPv6,
            other => EtherType::Unknown(other),
        }
    }
}

impl Into<u16> for EtherType {
    fn into(self) -> u16 {
        match self {
            EtherType::IPv4 => 0x0800,
            EtherType::ARP => 0x0806,
            EtherType::IPv6 => 0x86DD,
            EtherType::Unknown(val) => val,
        }
    }
}

pub struct EthernetFrame<'a> {
    pub data: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < ETH_HDR_LEN {
            return None;
        }
        Some(Self { data })
    }

    pub fn destination(&self) -> MacAddress {
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&self.data[0..6]);
        MacAddress(addr)
    }

    pub fn source(&self) -> MacAddress {
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&self.data[6..12]);
        MacAddress(addr)
    }

    pub fn ether_type(&self) -> EtherType {
        let val = NetworkEndian::read_u16(&self.data[12..14]);
        EtherType::from(val)
    }

    pub fn payload(&self) -> &[u8] {
        &self.data[ETH_HDR_LEN..]
    }

    /// Helper to write an ethernet header into a buffer
    pub fn write_header(buf: &mut [u8], dest: MacAddress, src: MacAddress, eth_type: EtherType) {
        buf[0..6].copy_from_slice(&dest.0);
        buf[6..12].copy_from_slice(&src.0);
        NetworkEndian::write_u16(&mut buf[12..14], eth_type.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_parsing() {
        let mut data = [0u8; 14];
        let dest = MacAddress([0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);
        let src = MacAddress([0xcd, 0xef, 0x01, 0x23, 0x45, 0x67]);
        EthernetFrame::write_header(&mut data, dest, src, EtherType::IPv4);

        let frame = EthernetFrame::new(&data).unwrap();
        assert_eq!(frame.destination(), dest);
        assert_eq!(frame.source(), src);
        assert_eq!(frame.ether_type(), EtherType::IPv4);
    }
}
