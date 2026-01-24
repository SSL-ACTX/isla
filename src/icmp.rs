// src/icmp.rs
use crate::utils::checksum;
use byteorder::{ByteOrder, NetworkEndian};

pub const ICMP_HDR_LEN: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply,
    EchoRequest,
    Unknown(u8),
}

impl From<u8> for IcmpType {
    fn from(val: u8) -> Self {
        match val {
            0 => IcmpType::EchoReply,
            8 => IcmpType::EchoRequest,
            other => IcmpType::Unknown(other),
        }
    }
}

pub struct IcmpPacket<'a> {
    pub data: &'a [u8],
}

impl<'a> IcmpPacket<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < ICMP_HDR_LEN {
            return None;
        }
        Some(Self { data })
    }

    pub fn icmp_type(&self) -> IcmpType {
        IcmpType::from(self.data[0])
    }

    pub fn payload(&self) -> &[u8] {
        &self.data[ICMP_HDR_LEN..]
    }

    /// Writes an ICMP Echo Reply into the buffer
    pub fn write_echo_reply(buf: &mut [u8], identifier: u16, seq_num: u16, payload: &[u8]) {
        buf[0] = 0; // Type: Echo Reply
        buf[1] = 0; // Code: 0
        buf[2] = 0; // Checksum placeholder
        buf[3] = 0; // Checksum placeholder
        NetworkEndian::write_u16(&mut buf[4..6], identifier);
        NetworkEndian::write_u16(&mut buf[6..8], seq_num);
        buf[8..8 + payload.len()].copy_from_slice(payload);

        let csum = checksum(&buf[0..8 + payload.len()]);
        NetworkEndian::write_u16(&mut buf[2..4], csum);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_parsing() {
        let mut data = [0u8; 12];
        let payload = b"ping";
        IcmpPacket::write_echo_reply(&mut data, 0x1234, 0x5678, payload);

        let packet = IcmpPacket::new(&data).unwrap();
        assert_eq!(packet.icmp_type(), IcmpType::EchoReply);
        assert_eq!(packet.payload(), payload);
    }
}
