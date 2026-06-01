# Isla

**An Experimental Rust TCP/IP Stack**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Language](https://img.shields.io/badge/Rust-Latest-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/Status-Experimental-red.svg)]()
[![IPv6](https://img.shields.io/badge/IPv6-Supported-green.svg)]()

> [!WARNING]
> Project Isla is an experimental learning project, not a production-ready network stack. It is not suitable for general internet use.

---

Project Isla is a custom, `no_std`-compatible TCP/IP implementation developed in Rust. It operates by bypassing the Linux kernel networking stack to communicate directly with a TAP interface using raw Ethernet frames.

The objective of this project is to explore the mechanics of the TCP 3-way handshake, zero-copy packet processing, and custom concurrency models.

## Table of Contents
- [Architecture](#architecture)
- [Feature Support](#feature-support)
- [Performance Benchmarks](#performance-benchmarks)
- [Testing](#testing)
- [Installation and Usage](#installation-and-usage)

---

## Architecture

Isla utilizes a custom event loop designed for specific CPU topologies, bypassing generic async runtimes.

### Hybrid Engine (Auto-Scaling)
* **Single-Threaded Mode:** On single-core hardware, it executes a zero-copy spin-loop to eliminate synchronization overhead.
* **Sharded Multi-Threaded Mode:** On multi-core systems, it spawns worker threads, distributing traffic based on a 2-tuple hash `(SrcIP, SrcPort) % workers`.

### Adaptive Backoff
To manage CPU utilization, the main loop implements a state machine:
1. **Spin:** Polling for high-load bursts.
2. **Yield:** Relinquishing CPU time.
3. **Sleep:** Micro-sleep (50µs) during low activity.

---

## Feature Support

| Layer | Protocol | Status |
| :--- | :--- | :--- |
| L2 | Ethernet | Implemented |
| L2 | ARP | Implemented |
| L3 | IPv4 | Header validation only |
| L3 | IPv6 | Core parsing, Hop Limits |
| L3 | ICMP | Echo Request/Reply |
| L3 | ICMPv6 | Echo Reply, NDP |
| L4 | TCP | 3-Way Handshake, PSH, FIN, RST |
| L4 | UDP | Pseudo-header checksum |
| L7 | DHCP | DORA Sequence |
| L7 | DNS | Basic A-Record Query |
| L7 | HTTP | Static HTML responder |

---

## Performance Benchmarks

*Note: Results obtained on an Intel Celeron 900 (2.2GHz, 2009) using a local TAP interface.*

| Metric | Result |
| :--- | :--- |
| Throughput | 3,109 Req/Sec |
| Latency | < 1ms |
| Concurrency | 100 Concurrent |

---

## Testing

Isla maintains a rigorous testing suite:
* **Unit Tests:** Integrated unit tests for all modules (`arp`, `ipv6`, `tcp`, `udp`, etc.).
* **Integration Testing:** A Python-based suite (`test_stack.py`) validates the stack against real-world scenarios.

---

## Installation and Usage

### Prerequisites
* Linux Kernel (TAP device creation required)
* Rust (Cargo)
* Root/Sudo privileges

### Quick Start

1. **Build:**
    ```bash
    cargo build --release
    ```

2. **Setup:**
    ```bash
    sudo ip tuntap add mode tap user $USER name isla0
    sudo ip link set isla0 up
    sudo ip addr add 192.168.1.1/24 dev isla0
    ```

3. **Run:**
    ```bash
    ./target/release/isla
    ```

---

<div align="center">

Built with 🦀 & 🐍 by [Seuriin](https://github.com/SSL-ACTX)

</div>
