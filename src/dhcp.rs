// src/dhcp.rs
use byteorder::{ByteOrder, NetworkEndian};
use core::net::Ipv4Addr;
use crate::ethernet::MacAddress;

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const MAGIC_COOKIE: u32 = 0x63825363;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Ack = 5,
    Unknown = 0,
}

pub struct DhcpPacket<'a> {
    pub data: &'a [u8],
}

impl<'a> DhcpPacket<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        // Minimum size of fixed header
        if data.len() < 240 { return None; }
        Some(Self { data })
    }

    pub fn op(&self) -> u8 { self.data[0] }
    pub fn xid(&self) -> u32 { NetworkEndian::read_u32(&self.data[4..8]) }
    pub fn your_ip(&self) -> Ipv4Addr {
        let mut oct = [0u8; 4];
        oct.copy_from_slice(&self.data[16..20]);
        Ipv4Addr::from(oct)
    }

    pub fn message_type(&self) -> DhcpMessageType {
        // Parse Options to find Message Type (53)
        let mut idx = 240; // Skip header + cookie
        while idx < self.data.len() {
            let tag = self.data[idx];
            if tag == 255 { break; } // End option
            if tag == 0 { idx += 1; continue; } // Pad option

            let len = self.data[idx+1] as usize;
            if tag == 53 && len == 1 {
                return match self.data[idx+2] {
                    1 => DhcpMessageType::Discover,
                    2 => DhcpMessageType::Offer,
                    3 => DhcpMessageType::Request,
                    5 => DhcpMessageType::Ack,
                    _ => DhcpMessageType::Unknown,
                };
            }
            idx += 2 + len;
        }
        DhcpMessageType::Unknown
    }

    /// Helper to write a DHCP Header + Options
    pub fn build_packet(
        buf: &mut [u8],
        op: u8,            // 1 = Request, 2 = Reply
        xid: u32,          // Transaction ID
        mac: MacAddress,
        msg_type: DhcpMessageType,
        req_ip: Option<Ipv4Addr>, // If requesting a specific IP
    ) -> usize {
        buf[0] = op;
        buf[1] = 1; // Hardware Type: Ethernet
        buf[2] = 6; // Hardware Addr Len
        buf[3] = 0; // Hops

        NetworkEndian::write_u32(&mut buf[4..8], xid);
        NetworkEndian::write_u16(&mut buf[8..10], 0); // Secs
        NetworkEndian::write_u16(&mut buf[10..12], 0x8000); // Flags: Broadcast (so relay agents can return replies)

        // Client IP, Your IP, Server IP, Gateway IP all 0 for Discover
        // Client Hardware Address (CHADDR)
        buf[28..34].copy_from_slice(&mac.0);

        // Magic Cookie
        NetworkEndian::write_u32(&mut buf[236..240], MAGIC_COOKIE);

        // --- Options ---
        let mut idx = 240;

        // Option 53: Message Type
        buf[idx] = 53; buf[idx+1] = 1; buf[idx+2] = msg_type as u8;
        idx += 3;

        // Option 50: Requested IP (used in Request)
        if let Some(ip) = req_ip {
            buf[idx] = 50; buf[idx+1] = 4;
            buf[idx+2..idx+6].copy_from_slice(&ip.octets());
            idx += 6;
        }

        // Option 55: Parameter Request List (Subnet Mask, Router, DNS)
        buf[idx] = 55; buf[idx+1] = 3;
        buf[idx+2] = 1;  // Subnet Mask
        buf[idx+3] = 3;  // Router
        buf[idx+4] = 6;  // DNS Server
        idx += 5;

        // Option 255: End
        buf[idx] = 255;
        idx += 1;

        idx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_build_and_parse() {
        let mut buf = [0u8; 512];
        let mac = MacAddress([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let xid = 0x12345678;
        let len = DhcpPacket::build_packet(&mut buf, 1, xid, mac, DhcpMessageType::Discover, None);

        let packet = DhcpPacket::new(&buf[..len]).unwrap();
        assert_eq!(packet.op(), 1);
        assert_eq!(packet.xid(), xid);
        assert_eq!(packet.message_type(), DhcpMessageType::Discover);
    }
}
