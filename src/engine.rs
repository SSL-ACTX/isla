// src/engine.rs
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Instant, Duration};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::hint;
use crate::tap::TapDevice;
use crate::Packet;
use crate::{process_packet, ActiveConnection, BATCH_SIZE, MTU, GC_INTERVAL, TCP_TIMEOUT, log, STACK_IP6};
use aether::ethernet::{EthernetFrame, EtherType};
use aether::ipv4::Ipv4Packet;
use aether::ipv6::Ipv6Packet;
use aether::ipv4::IpProtocol;
use byteorder::{ByteOrder, NetworkEndian};

pub struct AdaptiveBackoff {
    idle_cycles: u32,
    current_sleep: Duration,
    min_sleep: Duration,
    max_sleep: Duration,
}

impl AdaptiveBackoff {
    pub fn new() -> Self {
        Self {
            idle_cycles: 0,
            current_sleep: Duration::from_micros(100),
            min_sleep: Duration::from_micros(100),
            max_sleep: Duration::from_millis(50),
        }
    }

    pub fn step(&mut self, activity: bool) {
        if activity {
            self.idle_cycles = 0;
            self.current_sleep = self.min_sleep;
        } else {
            self.idle_cycles += 1;
            if self.idle_cycles < 100 {
                hint::spin_loop();
            } else if self.idle_cycles < 500 {
                thread::yield_now();
            } else {
                thread::sleep(self.current_sleep);
                self.current_sleep = (self.current_sleep * 2).min(self.max_sleep);
            }
        }
    }
}

pub fn run_single_threaded(mut tap: TapDevice, my_ip: Ipv4Addr) -> std::io::Result<()> {
    log!("[ENGINE] Mode: SINGLE-THREADED (Adaptive Backoff Enabled)");

    let mut rx_batch: [[u8; MTU]; BATCH_SIZE] = [[0u8; MTU]; BATCH_SIZE];
    let mut connections: HashMap<(Ipv4Addr, u16, u16), ActiveConnection> = HashMap::with_capacity(1024);
    let mut temp_tx_buf = [0u8; MTU];
    let mut tx_queue: Vec<Packet> = vec![Packet::new(); BATCH_SIZE];
    let mut last_gc = Instant::now();
    let mut backoff = AdaptiveBackoff::new();

    loop {
        let mut packets_processed = 0;
        let mut tx_count = 0;

        for i in 0..BATCH_SIZE {
            match tap.read(&mut rx_batch[i]) {
                Ok(n) => {
                    let len = process_packet(my_ip, STACK_IP6, &rx_batch[i][..n], &mut connections, &mut temp_tx_buf);
                    if len > 0 {
                        tx_queue[tx_count].len = len;
                        tx_queue[tx_count].data[..len].copy_from_slice(&temp_tx_buf[..len]);
                        tx_count += 1;
                    }
                    packets_processed += 1;
                },
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        if tx_count > 0 {
            for i in 0..tx_count {
                let pkt = &tx_queue[i];
                let _ = tap.write(&pkt.data[..pkt.len]);
            }
        }

        backoff.step(packets_processed > 0);

        if last_gc.elapsed() > Duration::from_secs(GC_INTERVAL) {
            connections.retain(|_, v| v.last_seen.elapsed() < Duration::from_secs(TCP_TIMEOUT));
            last_gc = Instant::now();
        }
    }
}

pub fn run_multi_threaded(mut tap: TapDevice, my_ip: Ipv4Addr, num_workers: usize) -> std::io::Result<()> {
    log!("[ENGINE] Mode: MULTI-THREADED (Workers: {})", num_workers);

    let (tx_collector, rx_collector) = mpsc::channel::<Packet>();
    let mut worker_senders = Vec::with_capacity(num_workers);

    for _i in 0..num_workers {
        let (tx_dispatch, rx_dispatch) = mpsc::channel::<Packet>();
        worker_senders.push(tx_dispatch);
        let tx_out = tx_collector.clone();

        thread::spawn(move || {
            let mut connections = HashMap::with_capacity(4096);
            let mut out_buf = [0u8; MTU];
            let mut last_gc = Instant::now();

            loop {
                match rx_dispatch.recv() {
                    Ok(pkt) => {
                        let len = process_packet(my_ip, STACK_IP6, &pkt.data[..pkt.len], &mut connections, &mut out_buf);
                        if len > 0 {
                            let mut resp = Packet::new();
                            resp.len = len;
                            resp.data[..len].copy_from_slice(&out_buf[..len]);
                            let _ = tx_out.send(resp);
                        }
                        if last_gc.elapsed() > Duration::from_secs(GC_INTERVAL) {
                            connections.retain(|_, v| v.last_seen.elapsed() < Duration::from_secs(TCP_TIMEOUT));
                            last_gc = Instant::now();
                        }
                    },
                    Err(_) => break,
                }
            }
        });
    }
    drop(tx_collector);

    let mut rx_batch: [[u8; MTU]; BATCH_SIZE] = [[0u8; MTU]; BATCH_SIZE];
    let mut backoff = AdaptiveBackoff::new();

    loop {
        let mut packets_processed = 0;

        for i in 0..BATCH_SIZE {
            match tap.read(&mut rx_batch[i]) {
                Ok(n) => {
                    let pkt_data = &rx_batch[i][..n];
                    let mut worker_id = 0;

                    if let Some(frame) = EthernetFrame::new(pkt_data) {
                        match frame.ether_type() {
                            EtherType::IPv4 => {
                                if let Some(ip) = Ipv4Packet::new(frame.payload()) {
                                    let src = ip.source_ip().octets();
                                    let mut hash: usize = (src[3] as usize) << 8 | (src[2] as usize);
                                    if ip.protocol() == IpProtocol::TCP && ip.payload().len() >= 2 {
                                        hash ^= NetworkEndian::read_u16(&ip.payload()[0..2]) as usize;
                                    }
                                    worker_id = hash % num_workers;
                                }
                            }
                            EtherType::IPv6 => {
                                if let Some(ip) = Ipv6Packet::new(frame.payload()) {
                                    let src = ip.source_ip().octets();
                                    let hash: usize = src.iter().fold(0usize, |acc, &x| acc.wrapping_add(x as usize));
                                    worker_id = hash % num_workers;
                                }
                            }
                            _ => {}
                        }
                    }

                    let _ = worker_senders[worker_id].send(Packet::from_slice(pkt_data));
                    packets_processed += 1;
                },
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        loop {
            match rx_collector.try_recv() {
                Ok(resp) => {
                    let _ = tap.write(&resp.data[..resp.len]);
                    packets_processed += 1;
                },
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }

        backoff.step(packets_processed > 0);
    }
}
