<div align="center">

![Aether Banner](https://capsule-render.vercel.app/api?type=waving&color=0:121212,100:00ff&height=220&section=header&text=Project%20Aether&fontSize=80&fontColor=FFFFFF&animation=fadeIn&fontAlignY=35&desc=Experimental%20Rust%20TCP/IP%20Stack&descSize=20&descAlignY=55)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge&logo=open-source-initiative)](https://opensource.org/licenses/MIT)
[![Language](https://img.shields.io/badge/Rust-Latest-orange.svg?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/Status-Experimental%20Prototype-red.svg?style=for-the-badge)]()
[![IPv6](https://img.shields.io/badge/IPv6-Supported-green.svg?style=for-the-badge)]()

</div>

---

> [!WARNING]
> **🚧 EXPERIMENTAL / EDUCATIONAL ONLY 🚧**
>
> **Project Aether is a learning experiment, not a production network stack.**
>
> Unlike mature user-space stacks (e.g., *smoltcp*, *VPP*, or *lwIP*) or the standard Linux kernel, Aether prioritizes code simplicity and raw throughput over correctness, reliability, and standards compliance. It is **not** suitable for general internet use.

---

## ⚡ Overview

**Project Aether** is a custom, `no_std`-compatible TCP/IP implementation written from scratch in Rust. It bypasses the Linux kernel networking stack (`netfilter`, routing tables, etc.) to communicate directly with a **TAP interface** via raw Ethernet frames.

The goal of this project was to explore the mechanics of the TCP 3-way handshake, zero-copy packet processing, and custom concurrency models without the overhead of an operating system's full network subsystem.

## 🛑 Scope & Limitations

If you are looking for a usable TCP/IP stack for your Rust OS or embedded project, **this is probably not it**. Aether takes significant shortcuts to achieve high "benchmark" numbers on local connections:

### 1. IPv6 Support
Aether now supports **IPv6 core logic**, including ICMPv6 and the Neighbor Discovery Protocol (NDP). This allows the stack to resolve Layer 2 addresses and respond to pings in modern IPv6-enabled environments.

### 2. Zero Reliability Mechanisms
To keep the engine extremely fast, we stripped out the safety features that make TCP "reliable":
* **No Retransmission:** If a packet is dropped, the connection stalls and eventually times out. Aether never resends data.
* **No Out-of-Order Handling:** Packets must arrive in perfect sequence. If packet 5 arrives before packet 4, packet 5 is dropped.
* **No Fragmentation:** IP packets larger than the MTU (1514 bytes) are dropped.

### 3. Missing Congestion Control
* **No Flow Control:** It sends data as fast as the wire allows. There is no "Slow Start," "Congestion Avoidance," or dynamic Window Scaling.
* **Fixed Window:** The TCP Window size is hardcoded.

### 4. Basic Security
* While it implements **SYN Cookies** to prevent basic flood attacks, it lacks randomness in sequence number generation (predictable ISNs) and does not support TLS/SSL.

---

## 🏗 Architecture

Aether abandons generic async runtimes (Tokio/Async-std) for a custom, purpose-built event loop designed for specific CPU topologies.

### 1. Hybrid Engine (Auto-Scaling)
At startup, Aether detects the available CPU cores:
* **Single-Threaded Mode:** On single-core VMs or legacy hardware, it runs a zero-copy spin-loop. This eliminates context switching and synchronization overhead.
* **Sharded Multi-Threaded Mode:** On multi-core systems, it spawns worker threads and distributes traffic using a 2-tuple hash `(SrcIP, SrcPort) % workers`.

### 2. Adaptive Backoff
To prevent the stack from burning 100% CPU while waiting for packets (a common issue in naive DPDK/kernel-bypass apps), the main loop implements a state machine:
1.  **Spin:** Nanosecond polling for high-load bursts.
2.  **Yield:** Relinquishes CPU time slice.
3.  **Sleep:** Micro-sleep (50µs) during total silence.

---

## 🛠 Feature Support

Despite its limitations, Aether successfully implements enough of the protocol suite to serve a basic webpage and negotiate an IP address.

| Layer | Protocol | Status | Notes |
| :--- | :--- | :--- | :--- |
| **L2** | **Ethernet** | ✅ | Frame parsing, broadcast handling |
| **L2** | **ARP** | ✅ | Request & Reply (IPv4 L2 resolution) |
| **L3** | **IPv4** | ⚠️ | Header validation only (No frag/options) |
| **L3** | **IPv6** | ✅ | Core parsing, Hop Limits, Multicast-aware |
| **L3** | **ICMP** | ✅ | Echo Request/Reply (Ping) |
| **L3** | **ICMPv6** | ✅ | Echo Reply, NDP (Neighbor Solicitation/Adv) |
| **L4** | **TCP** | ⚠️ | 3-Way Handshake, PSH, FIN, RST (No Re-Tx) |
| **L4** | **UDP** | ✅ | Pseudo-header checksum validation |
| **L7** | **DHCP** | ✅ | DORA Sequence (Discover, Offer, Request, Ack) |
| **L7** | **DNS** | ✅ | Basic A-Record Query building & parsing |
| **L7** | **HTTP** | ⚠️ | Static HTML responder (GET / only) |

---

## 🚀 Performance Benchmark

Running on a single-core **Intel Celeron 900 (2.2GHz, 2009)** context:

| Metric | Result | Context |
| :--- | :--- | :--- |
| **Throughput** | **3,109 Req/Sec** | Local TAP interface, HTTP Keep-Alive disabled |
| **Latency** | < 1ms | Local loopback equivalent |
| **Concurrency** | 100 Concurrent | Validated with Python stress script |

*Note: These numbers represent raw packet processing speed in a controlled environment. Real-world performance over a physical NIC would be significantly lower due to the lack of congestion control.*

---

## 🧪 Testing & Reliability

To ensure correctness in a `no_std` environment, Aether maintains a strict testing suite:

*   **Comprehensive Unit Tests:** Every module (`arp`, `ipv6`, `icmpv6`, `tcp`, `udp`, `dhcp`, `dns`, etc.) features integrated unit tests covering packet parsing, checksum calculation, and state transitions.
*   **Integration Testing:** A custom Python suite (`test_stack.py`) validates the stack against real-world scenarios including HTTP compliance, UDP integrity, and concurrent stress.
*   **Zero-Allocation Paths:** Critical packet processing paths are optimized for zero `alloc` usage when possible.

---

## 📦 Installation & Usage

### Prerequisites
* Linux Kernel (Required for `TAP` device creation)
* Rust (Cargo)
* Root/Sudo privileges (to configure the network interface)

### Quick Start

1.  **Build the Project:**
    ```bash
    cargo build --release
    ```

2.  **Setup the TAP Interface:**
    You need to create a persistent TAP device and assign it an IP.
    ```bash
    sudo ip tuntap add mode tap user $USER name aether0
    sudo ip link set aether0 up
    sudo ip addr add 192.168.1.1/24 dev aether0
    ```

3.  **Run Aether:**
    ```bash
    # Must run with access to the TAP device
    ./target/release/aether
    ```

4.  **Test Connectivity:**
    ```bash
    # Ping the stack
    ping 192.168.1.2

    # HTTP Request
    curl http://192.168.1.2/
    ```

---

<div align="center">

**Built with 🦀 and ☕ by [Seuriin](https://github.com/SSL-ACTX)**

</div>
