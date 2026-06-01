// src/lib.rs
#![no_std]
extern crate alloc;

pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod ethernet;
pub mod http;
pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;
pub mod utils;
