// src/tcp.rs
use crate::utils::tcp_checksum;
use byteorder::{ByteOrder, NetworkEndian};
use core::net::Ipv4Addr;

pub const TCP_HDR_LEN: usize = 20;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TcpState {
    Listen,
    SynReceived,
    Established,
    Closed,
}

pub struct TcpFlags;
impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

pub struct TcpHeader<'a> {
    pub data: &'a [u8],
}

impl<'a> TcpHeader<'a> {
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < TCP_HDR_LEN { return None; }
        Some(Self { data })
    }

    pub fn src_port(&self) -> u16 { NetworkEndian::read_u16(&self.data[0..2]) }
    pub fn dest_port(&self) -> u16 { NetworkEndian::read_u16(&self.data[2..4]) }
    pub fn seq_num(&self) -> u32 { NetworkEndian::read_u32(&self.data[4..8]) }
    pub fn ack_num(&self) -> u32 { NetworkEndian::read_u32(&self.data[8..12]) }
    pub fn flags(&self) -> u8 { self.data[13] }

    pub fn data_offset(&self) -> usize {
        ((self.data[12] >> 4) as usize) * 4
    }

    pub fn payload(&self) -> &[u8] {
        let offset = self.data_offset();
        if self.data.len() > offset {
            &self.data[offset..]
        } else {
            &[]
        }
    }

    pub fn write_header(
        buf: &mut [u8],
        src_port: u16,
        dest_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        payload_len: usize,
    ) {
        // Basic Header construction
        NetworkEndian::write_u16(&mut buf[0..2], src_port);
        NetworkEndian::write_u16(&mut buf[2..4], dest_port);
        NetworkEndian::write_u32(&mut buf[4..8], seq);
        NetworkEndian::write_u32(&mut buf[8..12], ack);
        buf[12] = 5 << 4; // 20 byte header (5 * 32-bit words)
        buf[13] = flags;
        NetworkEndian::write_u16(&mut buf[14..16], 64240); // Window size
        buf[16] = 0; // Checksum placeholder
        buf[17] = 0;
        buf[18] = 0; // Urgent
        buf[19] = 0;

        // Calculate checksum over the Pseudo-header + Header + Payload
        let total_tcp_len = TCP_HDR_LEN + payload_len;
        let csum = tcp_checksum(src_ip, dest_ip, &buf[..total_tcp_len]);
        NetworkEndian::write_u16(&mut buf[16..18], csum);
    }
}

pub struct TcpConnection {
    pub state: TcpState,
    pub local_seq: u32,
    pub remote_seq: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_parsing() {
        let mut data = [0u8; 20];
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dest_ip = Ipv4Addr::new(192, 168, 1, 2);
        TcpHeader::write_header(&mut data, 1234, 5678, 100, 200, TcpFlags::SYN | TcpFlags::ACK, src_ip, dest_ip, 0);

        let tcp = TcpHeader::new(&data).unwrap();
        assert_eq!(tcp.src_port(), 1234);
        assert_eq!(tcp.dest_port(), 5678);
        assert_eq!(tcp.seq_num(), 100);
        assert_eq!(tcp.ack_num(), 200);
        assert_eq!(tcp.flags(), TcpFlags::SYN | TcpFlags::ACK);
    }
}
