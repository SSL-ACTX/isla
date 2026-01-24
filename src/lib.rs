// src/lib.rs
#![no_std]
extern crate alloc;

pub mod ethernet;
pub mod arp;
pub mod ipv4;
pub mod ipv6;
pub mod icmp;
pub mod icmpv6;
pub mod tcp;
pub mod udp;
pub mod dns;
pub mod dhcp;
pub mod utils;
pub mod http;
