// src/udp.rs
use crate::utils::checksum;
use alloc::vec::Vec;
use byteorder::{ByteOrder, NetworkEndian};
use core::net::Ipv4Addr;

pub const UDP_HDR_LEN: usize = 8;

pub struct UdpHeader<'a> {
    pub data: &'a [u8],
}

impl<'a> UdpHeader<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < UDP_HDR_LEN {
            return None;
        }
        Some(Self { data })
    }

    pub fn src_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.data[0..2])
    }

    pub fn dest_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.data[2..4])
    }

    pub fn length(&self) -> u16 {
        NetworkEndian::read_u16(&self.data[4..6])
    }

    pub fn payload(&self) -> &[u8] {
        let len = self.length() as usize;
        if len >= UDP_HDR_LEN && len <= self.data.len() {
            &self.data[UDP_HDR_LEN..len]
        } else {
            &self.data[UDP_HDR_LEN..]
        }
    }

    pub fn write_header(
        buf: &mut [u8],
        src_port: u16,
        dest_port: u16,
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        payload: &[u8],
    ) {
        let total_len = UDP_HDR_LEN + payload.len();

        NetworkEndian::write_u16(&mut buf[0..2], src_port);
        NetworkEndian::write_u16(&mut buf[2..4], dest_port);
        NetworkEndian::write_u16(&mut buf[4..6], total_len as u16);
        buf[6] = 0; // Checksum placeholder
        buf[7] = 0;

        // Copy payload immediately so checksum covers it
        buf[8..8 + payload.len()].copy_from_slice(payload);

        // Calculate UDP Pseudo-Header Checksum
        let mut pseudo_header = Vec::with_capacity(12 + total_len);
        pseudo_header.extend_from_slice(&src_ip.octets());
        pseudo_header.extend_from_slice(&dest_ip.octets());
        pseudo_header.push(0);
        pseudo_header.push(17); // Protocol UDP
        let mut len_buf = [0u8; 2];
        NetworkEndian::write_u16(&mut len_buf, total_len as u16);
        pseudo_header.extend_from_slice(&len_buf);
        pseudo_header.extend_from_slice(&buf[0..total_len]);

        let csum = checksum(&pseudo_header);
        // UDP Checksum of 0 means "no checksum", so if calc yields 0, use 0xFFFF
        let final_csum = if csum == 0 { 0xFFFF } else { csum };

        NetworkEndian::write_u16(&mut buf[6..8], final_csum);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_parsing() {
        let mut data = [0u8; 16];
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dest_ip = Ipv4Addr::new(192, 168, 1, 2);
        let payload = b"hello!";
        UdpHeader::write_header(&mut data, 1234, 5678, src_ip, dest_ip, payload);

        let udp = UdpHeader::new(&data[..14]).unwrap();
        assert_eq!(udp.src_port(), 1234);
        assert_eq!(udp.dest_port(), 5678);
        assert_eq!(udp.length(), 14);
        assert_eq!(udp.payload(), payload);
    }
}
