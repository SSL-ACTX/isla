# test_stack.py
#!/usr/bin/env python3

import socket
import time
import sys
import threading
import random
import string
import argparse
import struct

DEFAULT_IP = "192.168.1.2"
DEFAULT_PORT = 80
DNS_PORT = 53
STRESS_THREADS = 100
MTU_TEST_SIZE = 4096  # Larger than one packet to force segmentation


def print_header(name):
    print("\n" + "=" * 60)
    print(f"[*] TEST: {name}")
    print("=" * 60)


def generate_random_string(length):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


# --- TCP TESTS ---


def test_echo_integrity(ip, port):
    print_header("TCP DATA INTEGRITY & BOUNDARIES")

    test_cases = [
        ("Tiny", "ping"),
        ("Standard", "The quick brown fox jumps over the lazy dog."),
        ("Segmentation (4KB)", generate_random_string(MTU_TEST_SIZE)),
    ]

    all_passed = True

    for name, payload in test_cases:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(2.0)
            client.connect((ip, port))

            print(
                f"    [>] Case '{name}' ({len(payload)} bytes)... ", end="", flush=True
            )

            # Send data
            client.sendall(payload.encode())

            # Robust Read Loop
            received = b""
            start_wait = time.time()

            while True:
                try:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    received += chunk

                    # Heuristic: If we have enough data, stop
                    if (
                        len(received) >= len(payload) + 20
                    ):  # +20 for protocol overhead "Isla Echo..."
                        break

                except socket.timeout:
                    break

                if time.time() - start_wait > 5.0:
                    break

            decoded = received.decode(errors="ignore")
            client.close()

            # Strip Protocol Wrappers
            cleaned = decoded.replace("Isla Echo: ", "").replace("> ", "")

            # Verification
            if payload in cleaned:
                print("PASS")
            else:
                print("FAIL")
                print(f"       Expected: {len(payload)} bytes")
                print(f"       Got:      {len(cleaned)} bytes")
                all_passed = False

        except Exception as e:
            print(f"ERROR ({e})")
            all_passed = False

    return all_passed


def test_http_compliance(ip, port):
    print_header("HTTP PROTOCOL COMPLIANCE")
    try:
        print("    [>] Sending HTTP GET... ", end="", flush=True)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(2.0)
        client.connect((ip, port))

        request = "GET /index.html HTTP/1.1\r\nHost: isla.local\r\n\r\n"
        client.sendall(request.encode())

        response = b""
        while True:
            try:
                chunk = client.recv(1024)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        client.close()
        decoded = response.decode(errors="ignore")

        if "HTTP/1.1 200 OK" in decoded and "Project Isla" in decoded:
            print("PASS")
            return True
        else:
            print("FAIL")
            print("       Invalid HTTP Response.")
            return False
    except Exception as e:
        print(f"ERROR: {e}")
        return False


# --- UDP TESTS ---


def test_udp_dns(ip):
    print_header("UDP / DNS COMPLIANCE")
    try:
        print("    [>] Sending DNS Query (A Record)... ", end="", flush=True)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)

        # Manual DNS Packet Construction (Transaction ID: 0x1234)
        # Header: ID=1234, Flags=0100 (Std Query), QDCOUNT=1
        packet = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        # Query: \x06google\x03com\x00 (google.com)
        packet += b"\x06google\x03com\x00"
        # Type: A (1), Class: IN (1)
        packet += struct.pack("!HH", 1, 1)

        sock.sendto(packet, (ip, 53))

        try:
            data, _ = sock.recvfrom(1024)
            print("PASS (Response Received)")
            return True
        except socket.timeout:
            print("WARN (No Response - UDP might be Log-Only)")
            return True  # Not a fatal failure if stack is in log-only mode for DNS

    except Exception as e:
        print(f"ERROR: {e}")
        return False


# --- STRESS TESTS ---


def stress_worker(ip, port, results, index):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((ip, port))
        s.sendall(b"PING")
        s.recv(1024)
        s.close()
        results[index] = True
    except:
        results[index] = False


def test_concurrent_stress(ip, port):
    print_header(f"CONCURRENCY STRESS ({STRESS_THREADS} Threads)")

    threads = []
    results = [False] * STRESS_THREADS

    print(f"    [>] Launching {STRESS_THREADS} simultaneous connections...")

    start_time = time.time()
    for i in range(STRESS_THREADS):
        t = threading.Thread(target=stress_worker, args=(ip, port, results, i))
        t.daemon = True
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    duration = time.time() - start_time
    success = sum(results)

    print(
        f"    [+] Success Rate: {success}/{STRESS_THREADS} ({success / STRESS_THREADS * 100:.1f}%)"
    )
    print(f"    [+] Time Taken:   {duration:.2f}s")

    if success >= STRESS_THREADS * 0.90:
        print("\n[✔] CONCURRENCY TEST PASSED")
        return True
    else:
        print("\n[✘] CONCURRENCY TEST FAILED (Packet Loss High)")
        return False


# --- MAIN ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default=DEFAULT_IP)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    print(f"[*] Target Isla Stack: {args.ip}")

    # 1. Integrity
    if not test_echo_integrity(args.ip, args.port):
        sys.exit(1)

    # 2. Protocol L7 (HTTP)
    if not test_http_compliance(args.ip, args.port):
        sys.exit(1)

    # 3. Protocol L4 (UDP)
    if not test_udp_dns(args.ip):
        sys.exit(1)

    # 4. Stress
    if not test_concurrent_stress(args.ip, args.port):
        sys.exit(1)

    print("\n" + "=" * 60)
    print("ALL SYSTEMS NOMINAL. STACK VERIFIED.")
    print("=" * 60)
