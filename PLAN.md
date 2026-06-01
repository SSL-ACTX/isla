# Project Isla: A High-Performance User-Space TCP/IP Stack

**Objective:** To bypass the Linux kernel's networking stack by implementing a custom Layer 2-4 protocol suite in Rust, utilizing a TAP interface to process raw Ethernet frames.

---

## 🛠 The Toolbox

- **Language:** Rust (Latest Stable).
- **Interface:** `TUN/TAP` (Specifically **TAP** for Layer 2 access).
- **Analysis:** **Wireshark** (Essential. If you don't see the bytes, they don't exist).
- **Crates to use:**
  - `libc`: For low-level `ioctl` calls to create the interface.
  - `nix`: Friendly Rust wrappers for Unix primitives.
  - `bitflags`: For handling TCP flags (SYN, ACK, etc.).
  - `byteorder`: For handling Network Byte Order (Big Endian).
  - `smoltcp`: (Optional, for reference only).
- **OS Tools:** `iproute2` (`ip link`, `ip addr`).

---

## 📈 Phase 1: The Plumbing (L2 - Data Link)

Before you can process data, you need to trick your OS into sending raw Ethernet frames to your Rust program instead of the Kernel.

1.  **TAP Interface Setup:** Write a Rust module that uses `ioctl` to open `/dev/net/tun` and create a persistent `TAP` device (e.g., `isla0`).
2.  **The Main Loop:** Create a high-performance loop that reads from the TAP file descriptor into a pre-allocated `[u8; 1514]` buffer (the standard MTU).
3.  **Frame Parsing:**
    - Identify the **Ethernet Header** (Destination MAC, Source MAC, EtherType).
    - Discard anything that isn't **ARP** or **IPv4**.
4.  **ARP Implementation:** This is your first "Stateful" challenge. When you `ping` your stack's IP, the OS will first send an ARP request: _"Who has IP 192.168.1.2?"_. You must reply with a fake MAC address.
    - **Goal:** Successfully respond to an ARP request so the OS populates its ARP table.

---

## ⚡ Phase 2: The Foundation (L3 - Network)

Now that the Kernel knows how to reach your MAC address, you need to handle IP packets.

1.  **IPv4 Header Parsing:** Implement a struct with `#[repr(C, packed)]` to map the 20-byte IP header.
2.  **Checksum Calculation:** Implement the Internet Checksum algorithm (ones-complement sum). If the checksum is wrong, drop the packet.
3.  **ICMP (Ping):** Implement an ICMP Echo responder.
    - **The Test:** You should be able to run `ping 192.168.1.2` in your terminal, and your Rust program should receive the IP packet, wrap it in an ICMP Echo Reply, and send it back.
    - **Success:** A stable ping response with <1ms latency.

---

## 🧠 Phase 3: The "Hard" Part (L4 - TCP State Machine)

TCP is a massive Finite State Machine. This is where your VortexJS experience with FSMs will shine.

1.  **The TCB (Transmission Control Block):** Create a struct that stores the state of a single connection:
    - `State` (LISTEN, SYN_SENT, ESTABLISHED, etc.).
    - `Sequence Number` (Your current byte count).
    - `Acknowledgement Number` (The bytes you've received).
    - `Window Size` (Flow control).
2.  **The 3-Way Handshake:**
    - Handle `SYN` -> Send `SYN-ACK` -> Receive `ACK`.
    - **Test:** Use `telnet 192.168.1.2 80`. If telnet says "Connected," your state machine works.
3.  **Port Demultiplexing:** Create a `HashMap` that maps `(Source IP, Source Port, Dest Port)` to a specific `TCB`.

---

## 🌊 Phase 4: Data Flow & Reliability

TCP is "Reliable." If a packet is lost, you must re-send it. This is the hardest logic to write.

1.  **Segment Reassembly:** If packets arrive out of order (Seq 100, then Seq 300, then Seq 200), your stack must buffer them and present them to the "application" in order.
2.  **The Retransmission Timer:** For every packet sent, start a timer. If an `ACK` doesn't come back in X milliseconds, send it again.
3.  **Sliding Window:** Implement flow control. If your stack is slow, tell the sender to slow down by decreasing the `Window` value in your TCP header.

---

## 🚀 Phase 5: Zero-Copy & Async (Optimization)

Now make it fast enough to rival the Kernel.

1.  **Buffer Management:** Instead of copying bytes from the TAP buffer to the TCP buffer to the Application buffer, use **Ownership**. Use `Bytes` or `Arc<[u8]>` to pass data through the stack without copying.
2.  **Async/Await Integration:** Wrap your stack in a `Future` so users can write `isla_socket.read().await`.
3.  **The "Web Server" Test:** Serve a small static file over your stack.
    - **The Final Boss:** Point Firefox at `http://192.168.1.2/hello.html`. Firefox is aggressive—it will open multiple connections and request headers. If your stack doesn't crash, you've won.

---

## 🚩 Setup Instructions for your Ubuntu Sway Machine

To run a user-space stack, you need to give your binary permission to touch the network without being `root` all the time.

1.  **Create the TAP device:**

    ```bash
    sudo ip tuntap add mode tap name isla0
    sudo ip addr add 192.168.1.1/24 dev isla0
    sudo ip link set dev isla0 up
    ```

2.  **Rust Permissions:**
    After building your binary, give it the capability to open raw sockets:

    ```bash
    sudo setcap cap_net_admin,cap_net_raw+eip ./target/debug/isla
    ```

3.  **The "Wireshark" Setup:**
    Open Wireshark and listen on the `isla0` interface. You will see exactly what your Rust code is doing in real-time.
